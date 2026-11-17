using System.Xml.Serialization;
using Jellyfin.Plugin.Sso.Configuration;
using Jellyfin.Plugin.Sso.Enforcement;
using Xunit;

namespace Jellyfin.Plugin.Sso.Tests;

public class DirectoryFeedTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan MaxAge = TimeSpan.FromSeconds(1800);

    private static string Feed(string generatedAt = "2026-11-02T11:50:00Z", string allowed = "[\"alice\", \"carol\"]",
        string admins = "[\"carol\"]", string version = "1")
        => $$"""{"version": {{version}}, "generated_at": "{{generatedAt}}", "allowed": {{allowed}}, "admins": {{admins}}}""";

    [Fact]
    public void AFreshFeedIsUsable()
    {
        var feed = DirectoryFeed.Usable(Feed(), Now, MaxAge, out _);
        Assert.NotNull(feed);
        Assert.True(feed.Allowed.SetEquals(["alice", "carol"]));
        Assert.True(feed.IsAdmin("carol"));
        Assert.False(feed.IsAdmin("alice"));
    }

    [Fact]
    public void AnOffsetOtherThanZIsUnderstood()
        => Assert.NotNull(DirectoryFeed.Usable(Feed("2026-11-02T13:50:00+02:00"), Now, MaxAge, out _));

    [Fact]
    public void AnAdminOutsideAllowedIsNoAdmin()
        => Assert.False(DirectoryFeed.Usable(Feed(admins: "[\"mallory\"]"), Now, MaxAge, out _)!.IsAdmin("mallory"));

    [Theory]
    [InlineData("2026-11-02T11:29:59Z")] // 1801 s old
    [InlineData("2026-11-02T12:05:01Z")] // 301 s ahead
    [InlineData("2026-11-02T11:50:00")] // no offset: which zone?
    [InlineData("yesterday")]
    public void BadTimesAreNotUsable(string generatedAt)
        => Assert.Null(DirectoryFeed.Usable(Feed(generatedAt), Now, MaxAge, out _));

    [Fact]
    public void TheEdgesAreUsable()
    {
        Assert.NotNull(DirectoryFeed.Usable(Feed("2026-11-02T11:30:00Z"), Now, MaxAge, out _));
        Assert.NotNull(DirectoryFeed.Usable(Feed("2026-11-02T12:05:00Z"), Now, MaxAge, out _));
    }

    [Theory]
    [InlineData("2")]
    [InlineData("\"1\"")]
    [InlineData("1.5")]
    public void OtherVersionsAreNotUsable(string version)
        => Assert.Null(DirectoryFeed.Usable(Feed(version: version), Now, MaxAge, out _));

    [Fact]
    public void AnEmptyAllowedListIsNotUsable()
    {
        Assert.Null(DirectoryFeed.Usable(Feed(allowed: "[]", admins: "[]"), Now, MaxAge, out var reason));
        Assert.Contains("empty", reason, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("[]")]
    [InlineData("{\"version\": 1}")]
    [InlineData("{\"version\": 1, \"generated_at\": \"2026-11-02T11:50:00Z\", \"allowed\": [\"a\"]}")]
    [InlineData("{\"version\": 1, \"generated_at\": \"2026-11-02T11:50:00Z\", \"allowed\": [\"a\", 3], \"admins\": []}")]
    [InlineData("{\"version\": 1, \"generated_at\": \"2026-11-02T11:50:00Z\", \"allowed\": [\"a\", \"\"], \"admins\": []}")]
    [InlineData("{\"version\": 1, \"generated_at\": \"2026-11-02T11:50:00Z\", \"allowed\": \"a\", \"admins\": []}")]
    public void GarbageIsNotUsable(string? json)
        => Assert.Null(DirectoryFeed.Usable(json, Now, MaxAge, out _));
}

public class EnforcementSettingsTests
{
    /// <summary>The section as the settings file brings it; a refused file throws.</summary>
    private static EnforcementSettings? Parse(string enforcement)
    {
        var file = SettingsFile.Parse("/etc/sso.json", "{\"Enforcement\": " + enforcement + "}");
        if (file.Error is { } error)
            throw new InvalidDataException(error);
        var config = new PluginConfiguration();
        file.ApplyTo(config);
        return config.Enforcement is { } section ? EnforcementSettings.From(section) : null;
    }

    [Fact]
    public void ParsesTheSection()
    {
        var e = Parse("""
            {"enabled": true, "intervalSeconds": 60,
             "network": {"knownProxies": ["10.251.8.2"], "localNetworkSubnets": ["10.0.10.0/24", "10.0.0.0/24"]},
             "breakGlass": {"users": ["jellyfin-admin"], "enabled": false},
             "allowedApiKeyNames": [],
             "directory": {"path": "/run/house-directory/media.json", "maxAgeSeconds": 1800}}
            """)!;
        Assert.True(e.Enabled);
        Assert.Equal(60, e.IntervalSeconds);
        Assert.Equal(new[] { "10.251.8.2" }, e.Network!.KnownProxies);
        Assert.Equal(2, e.Network.LocalNetworkSubnets.Count);
        Assert.Equal(new[] { "jellyfin-admin" }, e.BreakGlassUsers);
        Assert.False(e.BreakGlassEnabled);
        Assert.Empty(e.AllowedApiKeyNames);
        Assert.Equal(new DirectorySettings("/run/house-directory/media.json", 1800), e.Directory);
    }

    [Fact]
    public void WithoutTheSectionNothingIsEnforced()
        => Assert.Null(Parse("null"));

    [Theory]
    [InlineData("""{"Enabled": true, "IntervalSeconds": 0}""")]
    [InlineData("""{"Enabled": true, "Network": {"KnownProxies": ["proxy.example.org"]}}""")]
    [InlineData("""{"Enabled": true, "Network": {"LocalNetworkSubnets": ["10.0.0.0/33"]}}""")]
    [InlineData("""{"Enabled": true, "BreakGlass": {"Users": [""]}}""")]
    [InlineData("""{"Enabled": true, "Directory": {"Path": "media.json", "MaxAgeSeconds": 60}}""")]
    [InlineData("""{"Enabled": true, "Directory": {"Path": "/run/media.json"}}""")]
    public void RefusesABrokenSection(string enforcement)
        => Assert.Throws<InvalidDataException>(() => Parse(enforcement));
}

public class EnforcementPlannerTests
{
    private const string Provider = "authentik";
    private static readonly DateTimeOffset FeedTime = new(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);
    private static readonly string Sso = EnforcementPlanner.SsoProviderId;
    private const string Password = EnforcementPlanner.PasswordProviderId;

    private static readonly EnforcementSettings Settings = new(
        Enabled: true,
        IntervalSeconds: 60,
        Network: new NetworkSettings(["10.251.8.2"], ["10.0.10.0/24", "10.0.0.0/24"]),
        BreakGlassUsers: ["jellyfin-admin"],
        BreakGlassEnabled: true,
        AllowedApiKeyNames: ["house-monitoring"],
        Directory: new DirectorySettings("/run/house-directory/media.json", 1800));

    private static readonly NetworkFacts NetworkAsWanted = new(["10.251.8.2"], ["10.0.0.0/24", "10.0.10.0/24"], true, ["10.251.8.2"]);

    private static readonly UserFacts BreakGlassUser = new(Guid.NewGuid(), "jellyfin-admin", true, false, false, Password);

    private static UserFacts User(string name, bool admin = false, bool disabled = false, string? provider = null)
        => new(Guid.NewGuid(), name, admin, disabled, true, provider ?? Sso);

    private static LinkConfig Link(UserFacts user, string sub, DateTimeOffset? lastLogin = null)
        => new() { ProviderId = Provider, Sub = sub, JellyfinUserId = user.Id, LastLoginUtc = lastLogin };

    private static DirectoryFeed Feed(string[] allowed, string[]? admins = null)
        => new(FeedTime, allowed.ToHashSet(StringComparer.Ordinal), (admins ?? []).ToHashSet(StringComparer.Ordinal));

    private static EnforcementPlan Plan(
        IEnumerable<UserFacts> users,
        IEnumerable<LinkConfig>? links = null,
        DirectoryFeed? feed = null,
        IEnumerable<Guid>? disabledByPolicy = null,
        EnforcementSettings? settings = null,
        NetworkFacts? network = null,
        bool quickConnect = true,
        IEnumerable<ApiKeyFacts>? apiKeys = null,
        bool wizardDone = true,
        string? provider = Provider)
        => EnforcementPlanner.Plan(new EnforcementInput(
            settings ?? Settings, provider, (links ?? []).ToList(), (disabledByPolicy ?? []).ToList(), wizardDone,
            users.ToList(), network ?? NetworkAsWanted, quickConnect, (apiKeys ?? []).ToList(), feed));

    private static UserChange For(EnforcementPlan plan, UserFacts user) => Assert.Single(plan.Users, c => c.UserId == user.Id);

    private static void NoChangeFor(EnforcementPlan plan, UserFacts user) => Assert.DoesNotContain(plan.Users, c => c.UserId == user.Id);

    // ── a house in order: nothing to do ──────────────────────────────────────────

    [Fact]
    public void NothingChangesWhenEverythingIsAsWanted()
    {
        var alice = User("alice");
        var carol = User("carol", admin: true);
        var plan = Plan([BreakGlassUser, alice, carol], [Link(alice, "alice"), Link(carol, "carol")],
            Feed(["alice", "carol"], ["carol"]));
        Assert.Null(plan.Network);
        Assert.False(plan.EnableQuickConnect);
        Assert.Empty(plan.DeleteApiKeys);
        Assert.Empty(plan.Users);
        Assert.Empty(plan.Errors);
    }

    // ── network and Quick Connect ────────────────────────────────────────────────

    [Fact]
    public void NetworkOrderDoesNotMatter()
        => Assert.Null(Plan([BreakGlassUser], network: NetworkAsWanted with { LocalNetworkSubnets = ["10.0.10.0/24", "10.0.0.0/24"] }).Network);

    [Fact]
    public void ChangedSubnetsAreSavedWithoutRestart()
    {
        var change = Plan([BreakGlassUser], network: NetworkAsWanted with { LocalNetworkSubnets = ["192.168.0.0/16"] }).Network!;
        Assert.True(change.Save);
        Assert.False(change.RestartForKnownProxies);
    }

    [Fact]
    public void RemoteAccessOffIsSwitchedOn()
        => Assert.True(Plan([BreakGlassUser], network: NetworkAsWanted with { EnableRemoteAccess = false }).Network!.Save);

    [Fact]
    public void ChangedKnownProxiesAreSavedAndNeedARestart()
    {
        var facts = new NetworkFacts([], ["10.0.10.0/24", "10.0.0.0/24"], true, []);
        var change = Plan([BreakGlassUser], network: facts).Network!;
        Assert.True(change.Save && change.RestartForKnownProxies);
        Assert.Equal(new[] { "10.251.8.2" }, change.KnownProxies);
    }

    [Fact]
    public void SavedButNotYetInEffectKnownProxiesNeedOnlyTheRestart()
    {
        var change = Plan([BreakGlassUser], network: NetworkAsWanted with { KnownProxiesInEffect = ["10.9.9.9"] }).Network!;
        Assert.False(change.Save);
        Assert.True(change.RestartForKnownProxies);
    }

    [Fact]
    public void KnownProxiesChangedInTheDashboardAreRevertedWithoutRestart()
    {
        // The running server still uses the wanted ones (it read them at startup).
        var change = Plan([BreakGlassUser], network: NetworkAsWanted with { KnownProxies = ["10.9.9.9"] }).Network!;
        Assert.True(change.Save);
        Assert.False(change.RestartForKnownProxies);
    }

    [Fact]
    public void WithoutNetworkSettingsTheNetworkIsLeftAlone()
        => Assert.Null(Plan([BreakGlassUser], settings: Settings with { Network = null },
            network: new NetworkFacts(["1.2.3.4"], [], false, ["1.2.3.4"])).Network);

    [Fact]
    public void QuickConnectIsSwitchedOn()
        => Assert.True(Plan([BreakGlassUser], quickConnect: false).EnableQuickConnect);

    // ── API keys ─────────────────────────────────────────────────────────────────

    [Fact]
    public void ApiKeysNotAllowedByNameAreDeleted()
    {
        var plan = Plan([BreakGlassUser], apiKeys: [new ApiKeyFacts("House-Monitoring", "k1"), new ApiKeyFacts("rogue", "k2"), new ApiKeyFacts("", "k3")]);
        Assert.Equal(new[] { "rogue", "" }, plan.DeleteApiKeys.Select(k => k.Name));
    }

    [Fact]
    public void AnApiKeyNeverShowsItsToken()
        => Assert.DoesNotContain("secret-token", new ApiKeyFacts("rogue", "secret-token").ToString(), StringComparison.Ordinal);

    // ── before the startup wizard ────────────────────────────────────────────────

    [Fact]
    public void BeforeTheWizardOnlyNetworkAndQuickConnect()
    {
        var plan = Plan([User("MyJellyfinUser", admin: true, provider: Password)], quickConnect: false,
            apiKeys: [new ApiKeyFacts("rogue", "k")], network: NetworkAsWanted with { KnownProxies = [] }, wizardDone: false);
        Assert.Empty(plan.Users);
        Assert.Empty(plan.DeleteApiKeys);
        Assert.True(plan.EnableQuickConnect);
        Assert.NotNull(plan.Network);
    }

    // ── break-glass ──────────────────────────────────────────────────────────────

    [Fact]
    public void BreakGlassOffIsDisabledListedAndLoggedOut()
    {
        var plan = Plan([BreakGlassUser], settings: Settings with { BreakGlassEnabled = false });
        var c = For(plan, BreakGlassUser);
        Assert.True(c.IsDisabled);
        Assert.Null(c.IsAdministrator); // stays administrator
        Assert.True(c.RevokeTokens && c.AddToDisabledByPolicy);
    }

    [Fact]
    public void BreakGlassOffStaysAnAdministrator()
    {
        var notAdmin = BreakGlassUser with { IsAdministrator = false, IsDisabled = true };
        var c = For(Plan([notAdmin], settings: Settings with { BreakGlassEnabled = false }, disabledByPolicy: [notAdmin.Id]), notAdmin);
        Assert.True(c.IsAdministrator);
        Assert.False(c.AddToDisabledByPolicy);
    }

    [Fact]
    public void BreakGlassOnIsEnabledAndUnlisted()
    {
        var disabled = BreakGlassUser with { IsDisabled = true };
        var c = For(Plan([disabled], disabledByPolicy: [disabled.Id]), disabled);
        Assert.False(c.IsDisabled);
        Assert.True(c.RemoveFromDisabledByPolicy);
        Assert.False(c.RevokeTokens);
    }

    [Fact]
    public void BreakGlassOnIsALocalPasswordAdministrator()
    {
        var odd = BreakGlassUser with { Name = "JELLYFIN-ADMIN", IsAdministrator = false, EnableRemoteAccess = true, AuthenticationProviderId = Sso };
        var c = For(Plan([odd]), odd);
        Assert.True(c.IsAdministrator);
        Assert.False(c.EnableRemoteAccess);
        Assert.Equal(Password, c.AuthenticationProviderId);
        Assert.Null(c.IsDisabled);
    }

    [Fact]
    public void ALinkedBreakGlassUserIsALinkedUserAndAnError()
    {
        var plan = Plan([BreakGlassUser], [Link(BreakGlassUser, "admin")], Feed(["alice"]));
        Assert.Contains(plan.Errors, e => e.Contains("jellyfin-admin", StringComparison.Ordinal));
        var c = For(plan, BreakGlassUser);
        Assert.True(c.IsDisabled);
        Assert.Equal(Sso, c.AuthenticationProviderId);
    }

    // ── linked users and the feed ────────────────────────────────────────────────

    [Fact]
    public void ALinkedUserNotInTheFeedIsDisabledDemotedAndLoggedOut()
    {
        var carol = User("carol", admin: true);
        var plan = Plan([BreakGlassUser, carol], [Link(carol, "carol")], Feed(["alice"]));
        var c = For(plan, carol);
        Assert.True(c.IsDisabled);
        Assert.False(c.IsAdministrator);
        Assert.True(c.RevokeTokens && c.AddToDisabledByPolicy);
        Assert.Equal("not in the directory feed", c.Reason);
    }

    [Fact]
    public void ALoginNewerThanTheFeedOutweighsIt()
    {
        var alice = User("alice");
        NoChangeFor(Plan([BreakGlassUser, alice], [Link(alice, "alice", FeedTime.AddSeconds(1))], Feed(["carol"])), alice);
    }

    [Fact]
    public void ALoginAtOrBeforeTheFeedDoesNot()
    {
        var alice = User("alice");
        var bob = User("bob");
        var plan = Plan([BreakGlassUser, alice, bob], [Link(alice, "alice", FeedTime), Link(bob, "bob", FeedTime.AddDays(-1))], Feed(["carol"]));
        Assert.True(For(plan, alice).IsDisabled);
        Assert.True(For(plan, bob).IsDisabled);
    }

    [Fact]
    public void AUserTheEnforcementDisabledIsEnabledWhenBackInTheFeed()
    {
        var alice = User("alice", disabled: true);
        var c = For(Plan([BreakGlassUser, alice], [Link(alice, "alice")], Feed(["alice"]), [alice.Id]), alice);
        Assert.False(c.IsDisabled);
        Assert.True(c.RemoveFromDisabledByPolicy);
        Assert.False(c.RevokeTokens);
    }

    [Fact]
    public void AUserDisabledByHandStaysDisabledInTheFeed()
    {
        var alice = User("alice", disabled: true);
        NoChangeFor(Plan([BreakGlassUser, alice], [Link(alice, "alice")], Feed(["alice"])), alice);
    }

    [Fact]
    public void AUserDisabledByHandAndRemovedFromTheFeedIsNotListed()
    {
        var alice = User("alice", disabled: true);
        var c = For(Plan([BreakGlassUser, alice], [Link(alice, "alice")], Feed(["carol"])), alice);
        Assert.False(c.AddToDisabledByPolicy);
        Assert.Null(c.IsDisabled);
        Assert.True(c.RevokeTokens);
    }

    [Fact]
    public void AdminFlagFollowsTheFeed()
    {
        var alice = User("alice");
        var carol = User("carol", admin: true);
        var plan = Plan([BreakGlassUser, alice, carol], [Link(alice, "alice"), Link(carol, "carol")], Feed(["alice", "carol"], ["alice"]));
        Assert.True(For(plan, alice).IsAdministrator);
        Assert.Null(For(plan, alice).IsDisabled);
        Assert.False(For(plan, carol).IsAdministrator);
        Assert.False(For(plan, carol).RevokeTokens);
    }

    [Fact]
    public void ALinkedUserWithAPasswordLoginIsSwitchedToSso()
    {
        var dave = User("dave", provider: Password);
        var c = For(Plan([BreakGlassUser, dave], [Link(dave, "dave")]), dave);
        Assert.Equal(Sso, c.AuthenticationProviderId);
        Assert.Null(c.IsDisabled);
    }

    [Fact]
    public void LinksOfAnotherProviderDoNotCount()
    {
        var alice = User("alice");
        var link = Link(alice, "alice");
        link.ProviderId = "other";
        Assert.Equal("unmanaged account (not linked to an SSO identity, not break-glass)",
            For(Plan([BreakGlassUser, alice], [link], Feed(["alice"])), alice).Reason);
    }

    // ── an unusable feed: the local rules still apply ────────────────────────────

    [Fact]
    public void WithoutAUsableFeedOnlyLocalRulesApply()
    {
        var alice = User("alice", admin: true);
        var listed = User("listed", disabled: true);
        var local = User("local-extra");
        var plan = Plan([BreakGlassUser with { IsDisabled = true }, alice, listed, local],
            [Link(alice, "alice"), Link(listed, "listed")], feed: null, disabledByPolicy: [BreakGlassUser.Id, listed.Id],
            apiKeys: [new ApiKeyFacts("rogue", "k")], quickConnect: false);
        NoChangeFor(plan, alice); // admin flag untouched without a feed
        NoChangeFor(plan, listed); // not enabled without a feed
        Assert.True(For(plan, local).IsDisabled);
        Assert.False(For(plan, BreakGlassUser).IsDisabled);
        Assert.Single(plan.DeleteApiKeys);
        Assert.True(plan.EnableQuickConnect);
    }

    // ── unmanaged accounts ───────────────────────────────────────────────────────

    [Fact]
    public void AnUnmanagedAccountIsDisabled()
    {
        var extra = User("extra", admin: true, provider: Password);
        var c = For(Plan([BreakGlassUser, extra]), extra);
        Assert.True(c.IsDisabled);
        Assert.False(c.IsAdministrator);
        Assert.True(c.RevokeTokens && c.AddToDisabledByPolicy);
        Assert.StartsWith("unmanaged account", c.Reason, StringComparison.Ordinal);
    }

    [Fact]
    public void WithoutAnEnabledProviderNoAccountCountsAsUnmanaged()
    {
        var alice = User("alice");
        var plan = Plan([BreakGlassUser, alice], [Link(alice, "alice")], Feed(["carol"]), provider: null);
        Assert.Empty(plan.Users);
        Assert.Single(plan.Errors);
    }

    // ── never without an administrator ───────────────────────────────────────────

    [Fact]
    public void TheLastAdministratorKeepsTheFlag()
    {
        // No break-glass user exists: removing carol's flag would leave Jellyfin without any.
        var carol = User("carol", admin: true);
        var dave = User("dave", admin: true);
        var plan = Plan([carol, dave], [Link(carol, "carol"), Link(dave, "dave")], Feed(["dave"]));
        var c = For(plan, carol);
        Assert.True(c.IsDisabled); // still disabled and logged out
        Assert.Null(c.IsAdministrator); // but keeps the flag
        Assert.Contains(plan.Errors, e => e.Contains("carol", StringComparison.Ordinal));
        Assert.False(For(plan, dave).IsAdministrator); // in the feed, not an admin there: demoted
    }

    [Fact]
    public void ADisabledAccountIsPreferredToKeepTheFlag()
    {
        var carol = User("carol", admin: true);
        var erin = User("erin", admin: true);
        var plan = Plan([carol, erin], [Link(carol, "carol"), Link(erin, "erin")], Feed(["carol"]));
        Assert.False(For(plan, carol).IsAdministrator); // stays enabled: loses the flag
        Assert.Null(For(plan, erin).IsAdministrator); // disabled: keeps it
    }

    [Fact]
    public void WithABreakGlassAdministratorEveryoneElseCanBeDemoted()
    {
        var carol = User("carol", admin: true);
        var plan = Plan([BreakGlassUser with { IsDisabled = true }, carol], [Link(carol, "carol")], Feed(["dave"]),
            disabledByPolicy: [BreakGlassUser.Id], settings: Settings with { BreakGlassEnabled = false });
        Assert.False(For(plan, carol).IsAdministrator);
        Assert.Empty(plan.Errors);
    }
}

public class EnforcementStateTests
{
    [Fact]
    public void LoginTimeAndPolicyListSurviveTheXmlConfiguration()
    {
        // Jellyfin stores the plugin configuration with XmlSerializer.
        var when = new DateTimeOffset(2026, 11, 2, 12, 0, 0, TimeSpan.Zero);
        var id = Guid.NewGuid();
        var config = new PluginConfiguration
        {
            Links = [new LinkConfig { ProviderId = "authentik", Sub = "alice", JellyfinUserId = id, LastLoginUtc = when },
                     new LinkConfig { ProviderId = "authentik", Sub = "bob", JellyfinUserId = Guid.NewGuid() }],
            DisabledByPolicy = [id],
        };
        var serializer = new XmlSerializer(typeof(PluginConfiguration));
        using var buffer = new MemoryStream();
        serializer.Serialize(buffer, config);
        buffer.Position = 0;
        var back = (PluginConfiguration)serializer.Deserialize(buffer)!;
        Assert.Equal(when, back.Links[0].LastLoginUtc);
        Assert.Null(back.Links[1].LastLoginUtc);
        Assert.Equal(new[] { id }, back.DisabledByPolicy);
    }
}

public class EnforcementStateOwnershipTests
{
    /// <summary>
    /// The configuration the fork of 1.12.0 wrote, as XmlSerializer wrote it: the links (every
    /// resident's account), the enforcement's list and the login times must come through the
    /// move to upstream's base; the old fork's own settings are ignored (the settings file
    /// brings them again).
    /// </summary>
    [Fact]
    public void The_configuration_of_the_old_fork_loads_with_its_links()
    {
        var user = Guid.NewGuid();
        var xml = $"""
            <?xml version="1.0" encoding="utf-8"?>
            <PluginConfiguration xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
              <PublicUrl>https://media.example.org</PublicUrl>
              <LoginButtonText>Mit dem Hauskonto anmelden</LoginButtonText>
              <RequireGroupMapping>true</RequireGroupMapping>
              <Providers>
                <ProviderConfig>
                  <Id>authentik</Id><Name>Haus</Name><Enabled>true</Enabled>
                  <Authority>https://login.example.org/application/o/jellyfin/</Authority>
                  <ClientId>jellyfin</ClientId><ClientType>Confidential</ClientType>
                  <ConfidentialSecretRef>env:SSO_CLIENT_SECRET</ConfidentialSecretRef>
                  <Scopes><string>openid</string></Scopes><GroupsClaim>groups</GroupsClaim>
                  <GroupsFromUserInfo>false</GroupsFromUserInfo>
                </ProviderConfig>
              </Providers>
              <GroupMappings>
                <GroupMappingConfig><Group>residents</Group><LibraryIds /><AllLibraries>true</AllLibraries><IsAdministrator>false</IsAdministrator></GroupMappingConfig>
              </GroupMappings>
              <Links>
                <LinkConfig><ProviderId>authentik</ProviderId><Sub>alice</Sub><JellyfinUserId>{user}</JellyfinUserId><LastLoginUtc>2026-11-02T12:00:00+00:00</LastLoginUtc></LinkConfig>
              </Links>
              <SeenGroups><string>residents</string></SeenGroups>
              <DisabledByPolicy><guid>{user}</guid></DisabledByPolicy>
            </PluginConfiguration>
            """;

        var config = (PluginConfiguration)new XmlSerializer(typeof(PluginConfiguration))
            .Deserialize(new StringReader(xml.Trim()))!;

        var link = Assert.Single(config.Links);
        Assert.Equal(("authentik", "alice", user), (link.ProviderId, link.Sub, link.JellyfinUserId));
        Assert.Equal(new DateTimeOffset(2026, 11, 2, 12, 0, 0, TimeSpan.Zero), link.LastLoginUtc);
        Assert.Equal([user], config.DisabledByPolicy);
        Assert.True(Assert.Single(config.GroupMappings).AllLibraries);
        Assert.Equal("authentik", Assert.Single(config.Providers).Id);
    }

    [Fact]
    public void A_saved_configuration_keeps_the_list_of_users_the_enforcement_disabled()
    {
        using var harness = new PluginHarness();
        var id = Guid.NewGuid();
        harness.Configuration.DisabledByPolicy.Add(id);

        harness.Plugin.UpdateConfiguration(new PluginConfiguration());

        Assert.Equal([id], harness.Plugin.Configuration.DisabledByPolicy);
    }

    [Fact]
    public void The_settings_file_cannot_set_that_list()
        => Assert.Contains("which the plugin keeps itself",
            SettingsFile.Parse("/etc/sso.json", """{ "DisabledByPolicy": [] }""").Error);
}
