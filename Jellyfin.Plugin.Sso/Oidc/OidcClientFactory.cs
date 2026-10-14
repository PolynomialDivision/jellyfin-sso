using System.Collections.Concurrent;
using System.Net.Http.Headers;
using IdentityModel.Client;
using Jellyfin.Plugin.Sso.Configuration;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Sso.Oidc;

/// <summary>
/// Creates and caches per-provider OIDC discovery documents (with the signing keys) for an
/// hour, so a rotated IdP key is picked up without a Jellyfin restart.
/// </summary>
public sealed class OidcClientFactory : IDisposable
{
    private static readonly TimeSpan CacheTtl = TimeSpan.FromHours(1);

    private readonly HttpClient _http;
    private readonly ILogger<OidcClientFactory> _logger;
    private readonly ConcurrentDictionary<string, (DiscoveryDocumentResponse Doc, DateTimeOffset Expiry)> _cache = new();

    public OidcClientFactory(ILogger<OidcClientFactory> logger)
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
        _http.DefaultRequestHeaders.UserAgent.Add(
            new ProductInfoHeaderValue("Jellyfin.Plugin.Sso", "1.0"));
        _logger = logger;
    }

    public async Task<DiscoveryDocumentResponse> GetDiscoveryDocumentAsync(
        ProviderConfig provider, CancellationToken ct = default)
    {
        if (_cache.TryGetValue(CacheKey(provider), out var cached) && cached.Expiry > DateTimeOffset.UtcNow)
            return cached.Doc;

        _logger.LogInformation("Fetching OIDC discovery for provider {Name} ({Authority})",
            provider.Name, provider.Authority);

        // Authentik (and some other IdPs) use a shared authorize endpoint
        // (e.g. /application/o/authorize/) that differs from the per-app issuer path.
        // IdentityModel's strict endpoint validation rejects this — disable it, and check
        // the issuer ourselves below (the ID token is validated against it).
        var doc = await _http.GetDiscoveryDocumentAsync(
            new DiscoveryDocumentRequest
            {
                Address = provider.Authority,
                Policy = new DiscoveryPolicy
                {
                    ValidateEndpoints = false,
                    ValidateIssuerName = false,
                },
            }, ct)
            .ConfigureAwait(false);

        if (doc.IsError)
            throw new InvalidOperationException(
                $"OIDC discovery failed for {provider.Authority}: {doc.Error}");

        if (!SameIssuer(doc.Issuer, provider.Authority))
            throw new InvalidOperationException(
                $"OIDC discovery of {provider.Authority} names another issuer: {doc.Issuer}");

        _cache[CacheKey(provider)] = (doc, DateTimeOffset.UtcNow.Add(CacheTtl));
        return doc;
    }

    /// <summary>Drop the cached document, e.g. when a token is signed by an unknown key.</summary>
    public void Invalidate(ProviderConfig provider) => _cache.TryRemove(CacheKey(provider), out _);

    /// <summary>Issuer and configured authority are the same URL (a trailing slash does not count).</summary>
    internal static bool SameIssuer(string? issuer, string authority)
        => issuer is not null
           && string.Equals(issuer.TrimEnd('/'), authority.TrimEnd('/'), StringComparison.Ordinal);

    // The authority is part of the key: a changed provider setting must not use the old document.
    private static string CacheKey(ProviderConfig provider) => provider.Id + "\n" + provider.Authority;

    /// <summary>
    /// Exchanges an authorization code + PKCE verifier for tokens.
    /// </summary>
    public async Task<TokenResponse> ExchangeCodeAsync(
        ProviderConfig provider,
        DiscoveryDocumentResponse disco,
        string code,
        string redirectUri,
        string codeVerifier,
        CancellationToken ct = default)
    {
        var req = new AuthorizationCodeTokenRequest
        {
            Address = disco.TokenEndpoint,
            ClientId = provider.ClientId,
            Code = code,
            RedirectUri = redirectUri,
            CodeVerifier = codeVerifier,
        };

        if (provider.ClientType == OidcClientType.Confidential)
        {
            var secret = ResolveSecret(provider.ConfidentialSecretRef);
            req.ClientSecret = secret;
        }

        var response = await _http.RequestAuthorizationCodeTokenAsync(req, ct).ConfigureAwait(false);
        if (response.IsError)
            throw new InvalidOperationException($"Token exchange failed: {response.Error}");
        if (string.IsNullOrEmpty(response.IdentityToken))
            throw new InvalidOperationException("Token exchange returned no ID token (scope openid missing?).");

        return response;
    }

    /// <summary>
    /// Fetches the userinfo endpoint — used only when GroupsFromUserInfo is true.
    /// </summary>
    public async Task<UserInfoResponse> GetUserInfoAsync(
        DiscoveryDocumentResponse disco, string accessToken, CancellationToken ct = default)
    {
        var response = await _http.GetUserInfoAsync(new UserInfoRequest
        {
            Address = disco.UserInfoEndpoint,
            Token = accessToken,
        }, ct).ConfigureAwait(false);

        if (response.IsError)
            throw new InvalidOperationException($"Userinfo request failed: {response.Error}");

        return response;
    }

    /// <summary>
    /// Reads a confidential client secret from an env var ("env:VAR_NAME") or file ("file:/path").
    /// The literal secret is never stored in plugin config.
    /// </summary>
    private static string ResolveSecret(string? secretRef)
    {
        if (string.IsNullOrWhiteSpace(secretRef))
            throw new InvalidOperationException(
                "Confidential client requires ConfidentialSecretRef (env:VAR or file:/path).");

        if (secretRef.StartsWith("env:", StringComparison.Ordinal))
        {
            var varName = secretRef["env:".Length..];
            var value = Environment.GetEnvironmentVariable(varName);
            return string.IsNullOrEmpty(value)
                ? throw new InvalidOperationException($"Env var '{varName}' not set.")
                : value;
        }

        if (secretRef.StartsWith("file:", StringComparison.Ordinal))
        {
            var path = secretRef["file:".Length..];
            return File.ReadAllText(path).Trim();
        }

        // Never echo the value: a literal secret pasted here must not end up in a log.
        throw new InvalidOperationException("ConfidentialSecretRef must start with 'env:' or 'file:'.");
    }

    public void Dispose() => _http.Dispose();
}
