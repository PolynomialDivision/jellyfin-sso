using Jellyfin.Plugin.Sso.Oidc;
using MediaBrowser.Controller.Library;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Sso.Provisioning;

/// <summary>
/// Declarative sync of what the IdP groups decide: the admin flag and library access, on every
/// login. Everything else of the user's policy (disabled, remote access, parental rating,
/// sessions …) is read and kept, so an admin's change in Jellyfin is not undone by a login;
/// a user disabled in Jellyfin stays disabled.
/// </summary>
public sealed class PermissionSync
{
    private readonly IUserManager _userManager;
    private readonly ILogger<PermissionSync> _logger;

    public PermissionSync(IUserManager userManager, ILogger<PermissionSync> logger)
    {
        _userManager = userManager;
        _logger = logger;
    }

    public async Task SyncAsync(Guid userId, OidcIdentity identity, AccessDecision access, CancellationToken ct = default)
    {
        var user = _userManager.GetUserById(userId)
            ?? throw new InvalidOperationException("The Jellyfin user of this login no longer exists.");
        var policy = _userManager.GetUserDto(user).Policy
            ?? throw new InvalidOperationException("The Jellyfin user has no policy.");

        policy.IsAdministrator = access.IsAdministrator;
        policy.EnableAllFolders = access.AllLibraries;
        policy.EnabledFolders = access.AllLibraries ? [] : access.LibraryIds.ToArray();
        // The authentication provider is set once, when JIT creates the user. A local account
        // that an admin linked by hand keeps its own (password) login next to SSO.

        _logger.LogInformation(
            "SSO sync for user {Id}: admin={Admin}, all libraries={All}, libraries={Count}, groups={Groups}",
            userId, access.IsAdministrator, access.AllLibraries, access.LibraryIds.Count, string.Join(", ", identity.Groups));

        await _userManager.UpdatePolicyAsync(userId, policy).ConfigureAwait(false);

        var config = Plugin.Instance!.Configuration;
        var newGroups = identity.Groups.Except(config.SeenGroups, StringComparer.Ordinal).ToList();
        if (newGroups.Count > 0)
        {
            config.SeenGroups.AddRange(newGroups);
            Plugin.Instance.SaveConfiguration();
        }
    }
}
