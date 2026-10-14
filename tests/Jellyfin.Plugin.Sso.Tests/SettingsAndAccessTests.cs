using Jellyfin.Plugin.Sso.Configuration;
using Jellyfin.Plugin.Sso.Controllers;
using Jellyfin.Plugin.Sso.Provisioning;
using Jellyfin.Plugin.Sso.Web;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Jellyfin.Plugin.Sso.Tests;

public class AccessDecisionTests
{
    private static readonly Guid Films = Guid.NewGuid();
    private static readonly Guid Kids = Guid.NewGuid();

    private static readonly GroupMappingConfig[] Mappings =
    [
        new() { Group = "residents", AllLibraries = true },
        new() { Group = "guests", LibraryIds = [Kids.ToString("N")] },
        new() { Group = "friends", LibraryIds = [Films.ToString(), Kids.ToString("N")] },
        new() { Group = "it-admins", IsAdministrator = true },
    ];

    [Fact]
    public void NoMatchingGroupIsRefused()
    {
        var a = AccessDecision.From(Mappings, ["vpn-users"], requireMapping: true);
        Assert.False(a.Allowed);
        Assert.False(a.IsAdministrator);
    }

    [Fact]
    public void NoMatchingGroupWithoutRequirementGivesNothing()
    {
        var a = AccessDecision.From(Mappings, [], requireMapping: false);
        Assert.True(a.Allowed);
        Assert.False(a.AllLibraries);
        Assert.Empty(a.LibraryIds);
    }

    [Fact]
    public void AdminSeesEverything()
    {
        var a = AccessDecision.From(Mappings, ["it-admins"], requireMapping: true);
        Assert.True(a.Allowed && a.IsAdministrator && a.AllLibraries);
    }

    [Fact]
    public void LibrariesAreTheUnion()
    {
        var a = AccessDecision.From(Mappings, ["guests", "friends"], requireMapping: true);
        Assert.False(a.AllLibraries);
        Assert.Equal(new HashSet<Guid> { Films, Kids }, a.LibraryIds.ToHashSet());
    }

    [Fact]
    public void GroupNamesAreCaseSensitive()
        => Assert.False(AccessDecision.From(Mappings, ["IT-Admins"], requireMapping: true).Allowed);

    [Fact]
    public void BadLibraryIdFails()
        => Assert.Throws<FormatException>(() => AccessDecision.From(
            [new GroupMappingConfig { Group = "x", LibraryIds = ["not-a-guid"] }], ["x"], requireMapping: true));
}

public class ManagedSettingsTests
{
    private const string Valid = """
        {
          // written by house-infra
          "PublicUrl": "https://media.example.org/",
          "LoginButtonText": "Log in with the house account",
          "Providers": [{ "Id": "authentik", "Name": "Authentik", "Enabled": true,
                          "Authority": "https://login.example.org/application/o/jellyfin/",
                          "ClientId": "jellyfin", "ClientType": "Confidential",
                          "ConfidentialSecretRef": "env:SSO_CLIENT_SECRET" }],
          "GroupMappings": [{ "Group": "residents", "AllLibraries": true },
                            { "Group": "it-admins", "IsAdministrator": true }]
        }
        """;

    [Fact]
    public void ParsesTheManagedFile()
    {
        var s = EffectiveConfig.Parse(Valid);
        Assert.True(s.Managed);
        Assert.Equal("https://media.example.org", s.PublicUrl);
        Assert.True(s.RequireGroupMapping);
        var p = Assert.Single(s.Providers);
        Assert.Equal(OidcClientType.Confidential, p.ClientType);
        Assert.Equal(2, s.GroupMappings.Count);
    }

    [Theory]
    [InlineData("""{"Providers": []}""")]
    [InlineData("""{"PublicUrl": "media.example.org", "Providers": []}""")]
    [InlineData("""{"PublicUrl": "javascript:alert(1)", "Providers": []}""")]
    [InlineData("""{"PublicUrl": "https://m.example", "Providers": [{"Id": "a/b", "Authority": "https://x", "ClientId": "c"}]}""")]
    [InlineData("""{"PublicUrl": "https://m.example", "Providers": [{"Id": "a", "ClientId": "c"}]}""")]
    public void RefusesBrokenFiles(string json)
        => Assert.Throws<InvalidDataException>(() => EffectiveConfig.Parse(json));

    [Fact]
    public void AnUnreadableFileTurnsSsoOff()
    {
        var settings = new EffectiveConfig(NullLogger<EffectiveConfig>.Instance, "/nonexistent/sso.json").Get();
        Assert.True(settings.Managed);
        Assert.Empty(settings.Providers);
    }

    [Fact]
    public void ReadsTheFileAgainWhenItChanges()
    {
        var path = Path.GetTempFileName();
        try
        {
            File.WriteAllText(path, Valid);
            var config = new EffectiveConfig(NullLogger<EffectiveConfig>.Instance, path);
            Assert.Single(config.Get().Providers);
            File.WriteAllText(path, Valid.Replace("\"Enabled\": true", "\"Enabled\": false", StringComparison.Ordinal));
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddMinutes(1));
            Assert.False(config.Get().Providers[0].Enabled);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

public class UrlAndPageTests
{
    [Fact]
    public void CallbackComesFromThePublicUrlOnly()
    {
        Assert.Equal("https://media.example.org/sso/oidc/callback/authentik",
            SsoController.CallbackUri("https://media.example.org/", "authentik"));
        Assert.Null(SsoController.CallbackUri("", "authentik"));
    }

    [Fact]
    public void LoginButtonIsEncoded()
    {
        var html = LoginBranding.Button(new ProviderConfig { Id = "authentik", Name = "x" }, "<script>\"");
        Assert.DoesNotContain("<script>", html, StringComparison.Ordinal);
        Assert.Contains("href=\"/sso/oidc/start/authentik\"", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
    }
}
