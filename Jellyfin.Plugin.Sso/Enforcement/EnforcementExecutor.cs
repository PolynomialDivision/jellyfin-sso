using Jellyfin.Data;
using Jellyfin.Database.Implementations.Enums;
using MediaBrowser.Common.Net;
using MediaBrowser.Controller;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Controller.Library;
using MediaBrowser.Controller.Security;
using MediaBrowser.Model.Serialization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

using Jellyfin.Plugin.Sso.Provisioning;

namespace Jellyfin.Plugin.Sso.Enforcement;

/// <summary>
/// The enforcement's only contact with Jellyfin: reads the facts for the planner and carries
/// out its plan. Failures of one user are logged and the next user is done.
/// </summary>
public sealed class EnforcementExecutor
{
    // Process-wide (AppDomain data survives Jellyfin's in-process restart, which loads the
    // plugin again with fresh statics): the KnownProxies a restart was already requested for.
    internal const string RestartMarker = "Jellyfin.Plugin.Sso.Enforcement.RestartedForKnownProxies";

    private readonly IUserManager _userManager;
    private readonly SessionRevoker _revoker;
    private readonly IServerConfigurationManager _config;
    private readonly IServerApplicationHost _host;
    private readonly IXmlSerializer _xml;
    private readonly IServiceScopeFactory _scopes;
    private readonly ILogger<EnforcementExecutor> _logger;

    public EnforcementExecutor(
        IUserManager userManager,
        SessionRevoker revoker,
        IServerConfigurationManager config,
        IServerApplicationHost host,
        IXmlSerializer xml,
        IServiceScopeFactory scopes,
        ILogger<EnforcementExecutor> logger)
    {
        _userManager = userManager;
        _revoker = revoker;
        _config = config;
        _host = host;
        _xml = xml;
        _scopes = scopes;
        _logger = logger;
    }

    /// <summary>True once Jellyfin finished starting (restarting before that is not safe).</summary>
    public bool ServerStarted => _host.CoreStartupHasCompleted;

    public bool StartupWizardCompleted => _config.Configuration.IsStartupWizardCompleted;

    public bool QuickConnectAvailable => _config.Configuration.QuickConnectAvailable;

    /// <summary>The KnownProxies Jellyfin has now (at startup: the ones in effect until a restart).</summary>
    public IReadOnlyList<string> CurrentKnownProxies() => _config.GetNetworkConfiguration().KnownProxies.ToArray();

    public NetworkFacts NetworkFacts(IReadOnlyList<string> knownProxiesInEffect)
    {
        var n = _config.GetNetworkConfiguration();
        return new NetworkFacts(n.KnownProxies.ToArray(), n.LocalNetworkSubnets.ToArray(), n.EnableRemoteAccess, knownProxiesInEffect);
    }

    public IReadOnlyList<UserFacts> Users()
        => _userManager.GetUsers()
            .Select(u => new UserFacts(
                u.Id,
                u.Username,
                u.HasPermission(PermissionKind.IsAdministrator),
                u.HasPermission(PermissionKind.IsDisabled),
                u.HasPermission(PermissionKind.EnableRemoteAccess),
                u.AuthenticationProviderId))
            .ToList();

    public async Task<IReadOnlyList<ApiKeyFacts>> ApiKeysAsync()
    {
        using var scope = _scopes.CreateScope();
        var keys = await scope.ServiceProvider.GetRequiredService<IAuthenticationManager>().GetApiKeys().ConfigureAwait(false);
        return keys.Select(k => new ApiKeyFacts(k.AppName ?? string.Empty, k.AccessToken)).ToList();
    }

    public async Task ApplyAsync(EnforcementPlan plan)
    {
        foreach (var error in plan.Errors)
            _logger.LogError("SSO enforcement: {Problem}", error);

        if (plan.EnableQuickConnect)
        {
            _config.Configuration.QuickConnectAvailable = true;
            _config.SaveConfiguration();
            _logger.LogWarning("SSO enforcement: Quick Connect was off; switched on (native apps log in through it).");
        }

        if (plan.DeleteApiKeys.Count > 0)
        {
            using var scope = _scopes.CreateScope();
            var auth = scope.ServiceProvider.GetRequiredService<IAuthenticationManager>();
            foreach (var key in plan.DeleteApiKeys)
            {
                try
                {
                    await auth.DeleteApiKey(key.AccessToken).ConfigureAwait(false);
                    _logger.LogWarning("SSO enforcement: deleted the API key named '{Name}' (not in AllowedApiKeyNames).", key.Name);
                }
                catch (Exception ex) when (ex is not OutOfMemoryException)
                {
                    _logger.LogError(ex, "SSO enforcement: could not delete the API key named '{Name}'.", key.Name);
                }
            }
        }

        foreach (var change in plan.Users)
        {
            try
            {
                await ApplyUserAsync(change).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                _logger.LogError(ex, "SSO enforcement: could not apply the policy to user '{Name}' ({Reason}).", change.Name, change.Reason);
            }
        }

        // Last: a restart ends this round.
        if (plan.Network is { } network)
            ApplyNetwork(network);
    }

    /// <summary>
    /// After a successful SSO login (the caller holds the PolicyState lock): a user the
    /// enforcement disabled is enabled again, since the IdP just let the person in. A user
    /// disabled by hand is not touched.
    /// </summary>
    public async Task EnableAfterLoginAsync(Guid userId)
    {
        if (!PolicyState.IsDisabledByPolicy(userId))
            return;
        var user = _userManager.GetUserById(userId)
            ?? throw new InvalidOperationException("The Jellyfin user of this login no longer exists.");
        if (user.HasPermission(PermissionKind.IsDisabled))
        {
            var policy = _userManager.GetUserDto(user).Policy
                ?? throw new InvalidOperationException("The Jellyfin user has no policy.");
            policy.IsDisabled = false;
            await _userManager.UpdatePolicyAsync(userId, policy).ConfigureAwait(false);
            _logger.LogWarning("SSO enforcement: user '{Name}' enabled again by a fresh SSO login.", user.Username);
        }
        PolicyState.RemoveDisabledByPolicy(userId);
    }

    private async Task ApplyUserAsync(UserChange change)
    {
        // Listed before it is disabled (see PolicyState).
        if (change.AddToDisabledByPolicy)
            PolicyState.AddDisabledByPolicy(change.UserId);

        if (change.ChangesPolicy)
        {
            var user = _userManager.GetUserById(change.UserId)
                ?? throw new InvalidOperationException("the user no longer exists");
            var policy = _userManager.GetUserDto(user).Policy
                ?? throw new InvalidOperationException("the user has no policy");
            // Admin flag in the same write as the disable: Jellyfin's own API never leaves an
            // enabled-looking admin half-changed either.
            if (change.IsAdministrator is { } admin)
                policy.IsAdministrator = admin;
            if (change.IsDisabled is { } disabled)
                policy.IsDisabled = disabled;
            if (change.EnableRemoteAccess is { } remote)
                policy.EnableRemoteAccess = remote;
            if (change.AuthenticationProviderId is { } provider)
                policy.AuthenticationProviderId = provider;
            await _userManager.UpdatePolicyAsync(change.UserId, policy).ConfigureAwait(false);
            _logger.LogWarning(
                "SSO enforcement: user '{Name}' ({Reason}): {Changes}.",
                change.Name, change.Reason, Describe(change));
        }

        if (change.RevokeTokens)
            await RevokeAsync(change).ConfigureAwait(false);

        // Unlisted after it is enabled.
        if (change.RemoveFromDisabledByPolicy)
            PolicyState.RemoveDisabledByPolicy(change.UserId);
    }

    /// <summary>
    /// Every token and session of the user, and every login of theirs still under way: the
    /// plugin's own revocation, as for an unlink or a back-channel logout.
    /// </summary>
    private async Task RevokeAsync(UserChange change)
    {
        await _revoker.RevokeUserAsync(change.UserId).ConfigureAwait(false);
        _logger.LogWarning("SSO enforcement: user '{Name}' ({Reason}): every session ended.", change.Name, change.Reason);
    }

    private void ApplyNetwork(NetworkChange change)
    {
        if (change.Save)
        {
            var n = _config.GetNetworkConfiguration();
            n.KnownProxies = change.KnownProxies.ToArray();
            n.LocalNetworkSubnets = change.LocalNetworkSubnets.ToArray();
            n.EnableRemoteAccess = true;
            _config.SaveConfiguration(NetworkConfigurationStore.StoreKey, n);
            _logger.LogWarning(
                "SSO enforcement: network settings set: KnownProxies [{Proxies}], LocalNetworkSubnets [{Subnets}], remote access on.",
                string.Join(", ", change.KnownProxies), string.Join(", ", change.LocalNetworkSubnets));
        }

        if (!change.RestartForKnownProxies)
            return;

        // What a restart would read: the file, not the object in memory.
        var path = Path.Combine(_config.CommonApplicationPaths.ConfigurationDirectoryPath, NetworkConfigurationStore.StoreKey + ".xml");
        NetworkConfiguration? saved = null;
        try
        {
            saved = _xml.DeserializeFromFile(typeof(NetworkConfiguration), path) as NetworkConfiguration;
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException or UnauthorizedAccessException)
        {
            _logger.LogError(ex, "SSO enforcement: cannot read {Path} back.", path);
        }
        if (saved is null || !EnforcementPlanner.SameSet(saved.KnownProxies, change.KnownProxies))
        {
            _logger.LogError(
                "SSO enforcement: KnownProxies in {Path} still differ from [{Proxies}] after saving; not restarting. Check the file.",
                path, string.Join(", ", change.KnownProxies));
            return;
        }

        var wanted = string.Join(",", change.KnownProxies.Select(p => p.Trim().ToLowerInvariant()).Order(StringComparer.Ordinal));
        if (AppDomain.CurrentDomain.GetData(RestartMarker) is string done && done == wanted)
        {
            _logger.LogError(
                "SSO enforcement: Jellyfin already restarted once for KnownProxies [{Proxies}] and still does not use them; not restarting again.",
                string.Join(", ", change.KnownProxies));
            return;
        }

        AppDomain.CurrentDomain.SetData(RestartMarker, wanted);
        _logger.LogWarning(
            "SSO enforcement: restarting Jellyfin once: it reads KnownProxies only at startup and runs with [{Old}], configured are [{Proxies}].",
            string.Join(", ", change.KnownProxiesInEffect), string.Join(", ", change.KnownProxies));
        using var scope = _scopes.CreateScope();
        scope.ServiceProvider.GetRequiredService<ISystemManager>().Restart();
    }

    private static string Describe(UserChange c)
    {
        var parts = new List<string>();
        if (c.IsDisabled is { } d)
            parts.Add(d ? "disabled" : "enabled");
        if (c.IsAdministrator is { } a)
            parts.Add(a ? "administrator" : "no administrator");
        if (c.EnableRemoteAccess is { } r)
            parts.Add(r ? "remote access on" : "remote access off");
        if (c.AuthenticationProviderId is { } p)
            parts.Add("login via " + (p == EnforcementPlanner.SsoProviderId ? "SSO only" : "password"));
        return string.Join(", ", parts);
    }
}
