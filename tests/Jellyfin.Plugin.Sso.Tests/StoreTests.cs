using Jellyfin.Plugin.Sso.Auth;
using Jellyfin.Plugin.Sso.Oidc;
using Xunit;

namespace Jellyfin.Plugin.Sso.Tests;

/// <summary>The one-time values of a login: each works once, for the right thing only.</summary>
public class StoreTests
{
    [Fact]
    public void LoginStateIsSingleUse()
    {
        var store = new PendingStateStore();
        var (state, pending) = store.Issue("authentik", "https://m.example/sso/oidc/callback/authentik", quickConnect: true);
        Assert.True(pending.QuickConnect);
        Assert.NotNull(store.Consume(state));
        Assert.Null(store.Consume(state));
        Assert.Null(store.Consume(null));
        Assert.Null(store.Consume("guessed"));
    }

    [Fact]
    public void LoginStateValuesAreUniqueAndLong()
    {
        var store = new PendingStateStore();
        var (s1, p1) = store.Issue("a", "https://x");
        var (s2, p2) = store.Issue("a", "https://x");
        Assert.NotEqual(s1, s2);
        Assert.NotEqual(p1.Nonce, p2.Nonce);
        Assert.True(s1.Length >= 40 && p1.Nonce.Length >= 40 && p1.CodeVerifier.Length >= 43);
    }

    [Fact]
    public void PkceChallengeIsS256OfTheVerifier()
        // RFC 7636, appendix B
        => Assert.Equal("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            PendingStateStore.CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));

    [Fact]
    public void EphemeralSecretIsSingleUseAndBound()
    {
        var store = new EphemeralSecretStore();
        var secret = store.Issue("alice");
        Assert.Equal("alice", store.Consume(secret));
        Assert.Null(store.Consume(secret));
    }

    [Fact]
    public async Task SsoProviderRefusesAnotherUsersSecret()
    {
        var store = new EphemeralSecretStore();
        var provider = new SsoAuthenticationProvider(store);
        var secret = store.Issue("alice");
        await Assert.ThrowsAsync<MediaBrowser.Controller.Authentication.AuthenticationException>(() => provider.Authenticate("admin", secret));
        // Consumed by the failed try: it cannot be used for alice either.
        await Assert.ThrowsAsync<MediaBrowser.Controller.Authentication.AuthenticationException>(() => provider.Authenticate("alice", secret));
    }

    [Fact]
    public void QuickConnectApprovalIsSingleUse()
    {
        var store = new QuickConnectApprovalStore();
        var user = Guid.NewGuid();
        var token = store.Issue(user);
        Assert.Equal(user, store.Consume(token));
        Assert.Null(store.Consume(token));
        Assert.Null(store.Consume(""));
        Assert.Null(store.Consume(null));
    }
}
