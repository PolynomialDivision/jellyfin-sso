using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using IdentityModel.Client;
using Jellyfin.Plugin.Sso.Configuration;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.Sso.Oidc;

public sealed record OidcIdentity(string Sub, string PreferredUsername, IReadOnlyList<string> Groups);

public sealed class ClaimsExtractor
{
    private readonly OidcClientFactory _factory;

    public ClaimsExtractor(OidcClientFactory factory)
    {
        _factory = factory;
    }

    /// <summary>
    /// Validates the ID token and extracts sub, preferred_username, and group claims.
    /// When GroupsFromUserInfo is true, groups are fetched from the userinfo endpoint instead.
    /// A token signed by a key the cached discovery does not know triggers one fresh
    /// discovery (the IdP rotated its key), then fails.
    /// </summary>
    public async Task<OidcIdentity> ExtractAsync(
        ProviderConfig provider,
        DiscoveryDocumentResponse disco,
        string idToken,
        string? accessToken,
        string expectedNonce,
        CancellationToken ct = default)
    {
        OidcIdentity identity;
        try
        {
            identity = Validate(idToken, disco.Issuer!, provider.ClientId, SigningKeys(disco), expectedNonce, provider.GroupsClaim);
        }
        catch (SecurityTokenSignatureKeyNotFoundException)
        {
            _factory.Invalidate(provider);
            disco = await _factory.GetDiscoveryDocumentAsync(provider, ct).ConfigureAwait(false);
            identity = Validate(idToken, disco.Issuer!, provider.ClientId, SigningKeys(disco), expectedNonce, provider.GroupsClaim);
        }

        if (provider.GroupsFromUserInfo)
        {
            if (string.IsNullOrEmpty(accessToken))
                throw new SecurityTokenException("No access token for the userinfo request.");
            var userInfo = await _factory.GetUserInfoAsync(disco, accessToken, ct).ConfigureAwait(false);
            // userinfo must describe the same person as the ID token (OIDC Core 5.3.2).
            var infoSub = userInfo.Json is { } json && json.TryGetProperty("sub", out var s) ? s.GetString() : null;
            if (!string.Equals(infoSub, identity.Sub, StringComparison.Ordinal))
                throw new SecurityTokenException("userinfo 'sub' does not match the ID token.");
            identity = identity with { Groups = ExtractGroupsFromElement(userInfo.Json, provider.GroupsClaim) };
        }

        return identity;
    }

    private static List<SecurityKey> SigningKeys(DiscoveryDocumentResponse disco)
        => disco.KeySet?.Keys?
            .Select(k => new JsonWebKey(JsonSerializer.Serialize(k)))
            .Cast<SecurityKey>()
            .ToList()
            ?? throw new SecurityTokenException("No signing keys in discovery document.");

    /// <summary>
    /// Validates signature, issuer, audience, lifetime (60 s skew) and nonce of an ID token
    /// and reads sub, preferred_username and the groups claim.
    /// </summary>
    internal static OidcIdentity Validate(
        string idToken, string issuer, string audience, IEnumerable<SecurityKey> keys, string expectedNonce, string groupsClaim)
    {
        var handler = new JwtSecurityTokenHandler();
        // Disable automatic claim type remapping so "sub", "nonce" etc. keep their
        // original names instead of being renamed to long WS-Security URN strings.
        handler.InboundClaimTypeMap.Clear();

        var parameters = new TokenValidationParameters
        {
            ValidIssuer = issuer,
            ValidAudience = audience,
            IssuerSigningKeys = keys,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            RequireExpirationTime = true,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromSeconds(60),
        };

        var principal = handler.ValidateToken(idToken, parameters, out _);

        var nonce = principal.FindFirst(OpenIdConnectParameterNames.Nonce)?.Value;
        if (string.IsNullOrEmpty(nonce) || !string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
            throw new SecurityTokenException("ID token nonce mismatch.");

        var sub = principal.FindFirst("sub")?.Value;
        if (string.IsNullOrEmpty(sub))
            throw new SecurityTokenException("ID token missing 'sub' claim.");
        var username = principal.FindFirst("preferred_username")?.Value;
        if (string.IsNullOrWhiteSpace(username))
            throw new SecurityTokenException("ID token missing 'preferred_username' (scope profile).");

        var groups = principal.Claims
            .Where(c => c.Type == groupsClaim)
            .Select(c => c.Value)
            .ToList();

        return new OidcIdentity(sub, username, groups);
    }

    // UserInfoResponse.Json is JsonElement? in IdentityModel
    private static List<string> ExtractGroupsFromElement(JsonElement? nullableRoot, string claimName)
    {
        if (nullableRoot is not { } root)
            return [];
        return ExtractGroupsFromElement(root, claimName);
    }

    private static List<string> ExtractGroupsFromElement(JsonElement root, string claimName)
    {
        if (root.ValueKind == JsonValueKind.Undefined || root.ValueKind == JsonValueKind.Null)
            return [];

        if (!root.TryGetProperty(claimName, out var el))
            return [];

        if (el.ValueKind == JsonValueKind.Array)
            return el.EnumerateArray()
                .Where(e => e.ValueKind == JsonValueKind.String)
                .Select(e => e.GetString()!)
                .ToList();

        if (el.ValueKind == JsonValueKind.String)
            return [el.GetString()!];

        return [];
    }
}
