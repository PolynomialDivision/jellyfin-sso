using Jellyfin.Plugin.Sso.Configuration;
using Jellyfin.Plugin.Sso.Oidc;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Sso.Provisioning;

public sealed class UserProvisioner
{
    private static readonly SemaphoreSlim CreateLock = new(1, 1);

    private readonly IUserManager _userManager;
    private readonly ILogger<UserProvisioner> _logger;

    public UserProvisioner(IUserManager userManager, ILogger<UserProvisioner> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Resolves or JIT-creates the Jellyfin user for the given OIDC identity.
    /// Returns (userId, username) on success.
    /// Throws when a username collision with an existing non-linked account is detected.
    /// </summary>
    public async Task<(Guid UserId, string Username)> ResolveAsync(
        ProviderConfig provider,
        OidcIdentity identity,
        CancellationToken ct = default)
    {
        // One login at a time from here on: two first logins of the same person must not
        // create two users (or two links).
        await CreateLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await ResolveLockedAsync(provider, identity).ConfigureAwait(false);
        }
        finally
        {
            CreateLock.Release();
        }
    }

    private async Task<(Guid UserId, string Username)> ResolveLockedAsync(ProviderConfig provider, OidcIdentity identity)
    {
        var config = Plugin.Instance!.Configuration;

        // 1. Check for an existing link — the only way to match, never by username.
        var existing = config.Links.FirstOrDefault(l =>
            l.ProviderId == provider.Id &&
            string.Equals(l.Sub, identity.Sub, StringComparison.Ordinal));

        if (existing != null)
        {
            var user = _userManager.GetUserById(existing.JellyfinUserId);
            if (user is null)
            {
                _logger.LogWarning(
                    "Link exists for sub={Sub} but Jellyfin user {Id} not found — removing stale link.",
                    identity.Sub, existing.JellyfinUserId);
                config.Links.Remove(existing);
                Plugin.Instance.SaveConfiguration();
            }
            else
            {
                _logger.LogDebug("SSO login: matched existing user {Name} via link.", user.Username);
                return (user.Id, user.Username);
            }
        }

        // 2. No link — JIT create a new user.
        // Reject if a local user with the same name already exists (could be an admin account).
        var collision = _userManager.GetUserByName(identity.PreferredUsername);
        if (collision is not null)
        {
            _logger.LogWarning(
                "SSO JIT blocked: username '{Name}' already exists. " +
                "To link manually: ProviderId={ProviderId} Sub={Sub} JellyfinUserId={UserId}",
                identity.PreferredUsername, provider.Id, identity.Sub, collision.Id);
            throw new InvalidOperationException(
                $"Username '{identity.PreferredUsername}' already exists. " +
                "An administrator must manually link this account.");
        }

        _logger.LogInformation("SSO JIT: creating new Jellyfin user '{Name}'.", identity.PreferredUsername);
        var newUser = await _userManager.CreateUserAsync(identity.PreferredUsername).ConfigureAwait(false);

        // Start from Jellyfin's defaults for a new user and change only what SSO owns: the
        // login goes through SSO, no admin and no library until the group sync decides.
        var policy = _userManager.GetUserDto(newUser).Policy
            ?? throw new InvalidOperationException("The new Jellyfin user has no policy.");
        policy.AuthenticationProviderId = typeof(Auth.SsoAuthenticationProvider).FullName!;
        policy.IsAdministrator = false;
        policy.EnableAllFolders = false;
        policy.EnabledFolders = [];
        await _userManager.UpdatePolicyAsync(newUser.Id, policy).ConfigureAwait(false);

        // Store the link.
        config.Links.Add(new LinkConfig
        {
            ProviderId = provider.Id,
            Sub = identity.Sub,
            JellyfinUserId = newUser.Id,
        });
        Plugin.Instance.SaveConfiguration();

        return (newUser.Id, newUser.Username);
    }
}
