using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Jellyfin.Plugin.Sso.Oidc;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Jellyfin.Plugin.Sso.Tests;

/// <summary>ID token validation: everything a forged or replayed token could get wrong.</summary>
public class IdTokenTests
{
    private const string Issuer = "https://login.example.org/application/o/jellyfin/";
    private const string Audience = "jellyfin";
    private const string Nonce = "nonce-123";

    private static readonly RsaSecurityKey Key = new(RSA.Create(2048)) { KeyId = "k1" };
    private static readonly RsaSecurityKey OtherKey = new(RSA.Create(2048)) { KeyId = "k1" };

    private static string Token(
        SecurityKey? key = null, string issuer = Issuer, string audience = Audience, string? nonce = Nonce,
        DateTime? expires = null, string? username = "alice", string[]? groups = null, string? sub = "sub-1")
    {
        var claims = new List<Claim>();
        if (sub is not null) claims.Add(new Claim("sub", sub));
        if (nonce is not null) claims.Add(new Claim("nonce", nonce));
        if (username is not null) claims.Add(new Claim("preferred_username", username));
        foreach (var g in groups ?? ["residents", "it-admins"]) claims.Add(new Claim("groups", g));
        var now = DateTime.UtcNow;
        var exp = expires ?? now.AddMinutes(5);
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = issuer,
            Audience = audience,
            Subject = new ClaimsIdentity(claims),
            NotBefore = exp < now ? exp.AddMinutes(-10) : now.AddMinutes(-1),
            IssuedAt = exp < now ? exp.AddMinutes(-10) : now.AddMinutes(-1),
            Expires = exp,
            SigningCredentials = new SigningCredentials(key ?? Key, SecurityAlgorithms.RsaSha256),
        };
        return new JwtSecurityTokenHandler().CreateEncodedJwt(descriptor);
    }

    private static OidcIdentity Validate(string token, string nonce = Nonce)
        => ClaimsExtractor.Validate(token, Issuer, Audience, [Key], nonce, "groups");

    [Fact]
    public void ValidTokenGivesSubUsernameAndGroups()
    {
        var id = Validate(Token());
        Assert.Equal("sub-1", id.Sub);
        Assert.Equal("alice", id.PreferredUsername);
        Assert.Equal(["residents", "it-admins"], id.Groups);
    }

    [Fact]
    public void SignedByAnotherKeyIsRefused()
        => Assert.ThrowsAny<SecurityTokenException>(() => Validate(Token(key: OtherKey)));

    [Fact]
    public void UnsignedTokenIsRefused()
    {
        var parts = Token().Split('.');
        var none = Base64UrlEncoder.Encode("{\"alg\":\"none\",\"typ\":\"JWT\"}");
        Assert.ThrowsAny<Exception>(() => Validate(none + "." + parts[1] + "."));
    }

    [Fact]
    public void OtherIssuerIsRefused()
        => Assert.ThrowsAny<SecurityTokenException>(() => Validate(Token(issuer: "https://evil.example/application/o/jellyfin/")));

    [Fact]
    public void OtherAudienceIsRefused()
        => Assert.ThrowsAny<SecurityTokenException>(() => Validate(Token(audience: "grafana")));

    [Fact]
    public void ExpiredTokenIsRefused()
        => Assert.ThrowsAny<SecurityTokenException>(() => Validate(Token(expires: DateTime.UtcNow.AddMinutes(-5))));

    [Fact]
    public void WrongNonceIsRefused()
        => Assert.Throws<SecurityTokenException>(() => Validate(Token(), nonce: "another"));

    [Fact]
    public void MissingNonceIsRefused()
        => Assert.Throws<SecurityTokenException>(() => Validate(Token(nonce: null)));

    [Fact]
    public void MissingUsernameIsRefused()
        => Assert.Throws<SecurityTokenException>(() => Validate(Token(username: null)));

    [Fact]
    public void MissingSubIsRefused()
        => Assert.Throws<SecurityTokenException>(() => Validate(Token(sub: null)));

    [Fact]
    public void IssuerOfDiscoveryMustBeTheAuthority()
    {
        Assert.True(OidcClientFactory.SameIssuer(Issuer, Issuer.TrimEnd('/')));
        Assert.False(OidcClientFactory.SameIssuer("https://login.example.org/application/o/grafana/", Issuer));
        Assert.False(OidcClientFactory.SameIssuer(null, Issuer));
    }
}
