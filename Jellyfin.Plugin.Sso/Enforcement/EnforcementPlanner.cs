using Jellyfin.Plugin.Sso.Configuration;

namespace Jellyfin.Plugin.Sso.Enforcement;

/// <summary>What the planner needs to know about one Jellyfin user.</summary>
public sealed record UserFacts(
    Guid Id,
    string Name,
    bool IsAdministrator,
    bool IsDisabled,
    bool EnableRemoteAccess,
    string? AuthenticationProviderId);

/// <summary>
/// Jellyfin's network settings now, and the KnownProxies the running server was started with
/// (Jellyfin reads them only at startup, so a saved change needs a restart).
/// </summary>
public sealed record NetworkFacts(
    IReadOnlyList<string> KnownProxies,
    IReadOnlyList<string> LocalNetworkSubnets,
    bool EnableRemoteAccess,
    IReadOnlyList<string> KnownProxiesInEffect);

/// <summary>An API key. The key itself never appears in logs or messages.</summary>
public sealed record ApiKeyFacts(string Name, string AccessToken)
{
    public override string ToString() => "API key '" + Name + "'";
}

public sealed record EnforcementInput(
    EnforcementSettings Settings,
    // The enabled provider whose links make a user "linked"; null: none is enabled.
    string? ProviderId,
    IReadOnlyList<LinkConfig> Links,
    IReadOnlyCollection<Guid> DisabledByPolicy,
    // False while Jellyfin's startup wizard is not done: users and API keys are left alone.
    bool StartupWizardCompleted,
    IReadOnlyList<UserFacts> Users,
    NetworkFacts Network,
    bool QuickConnectAvailable,
    IReadOnlyList<ApiKeyFacts> ApiKeys,
    // Null: no directory configured, or the feed is not usable this round.
    DirectoryFeed? Feed);

/// <summary>The network settings to save, and whether the server must restart for them.</summary>
public sealed record NetworkChange(
    IReadOnlyList<string> KnownProxies,
    IReadOnlyList<string> LocalNetworkSubnets,
    bool Save,
    bool RestartForKnownProxies,
    IReadOnlyList<string> KnownProxiesInEffect);

/// <summary>
/// The changes to one user. Policy values are set only where they differ from the user's
/// facts (null: leave as it is), so an unchanged user is not written.
/// </summary>
public sealed record UserChange(Guid UserId, string Name, string Reason)
{
    public bool? IsAdministrator { get; init; }
    public bool? IsDisabled { get; init; }
    public bool? EnableRemoteAccess { get; init; }
    public string? AuthenticationProviderId { get; init; }

    /// <summary>End every token and session of the user (the executor skips it when there is none).</summary>
    public bool RevokeTokens { get; init; }

    public bool AddToDisabledByPolicy { get; init; }
    public bool RemoveFromDisabledByPolicy { get; init; }

    public bool ChangesPolicy
        => IsAdministrator.HasValue || IsDisabled.HasValue || EnableRemoteAccess.HasValue || AuthenticationProviderId is not null;
}

public sealed record EnforcementPlan(
    NetworkChange? Network,
    bool EnableQuickConnect,
    IReadOnlyList<ApiKeyFacts> DeleteApiKeys,
    IReadOnlyList<UserChange> Users,
    IReadOnlyList<string> Errors);

/// <summary>
/// Pure decisions of the enforcement: from the facts of one round to the changes. No Jellyfin
/// call happens here (EnforcementExecutor does them), so every rule is unit-tested.
/// </summary>
public static class EnforcementPlanner
{
    /// <summary>Jellyfin's own password provider (Jellyfin.Server.Implementations, not referenced by plugins).</summary>
    public const string PasswordProviderId = "Jellyfin.Server.Implementations.Users.DefaultAuthenticationProvider";

    public static readonly string SsoProviderId = typeof(Auth.SsoAuthenticationProvider).FullName!;

    public static EnforcementPlan Plan(EnforcementInput input)
    {
        var errors = new List<string>();
        var network = PlanNetwork(input.Settings.Network, input.Network);
        if (!input.StartupWizardCompleted)
            return new EnforcementPlan(network, !input.QuickConnectAvailable, [], [], errors);

        var allowedKeys = input.Settings.AllowedApiKeyNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var deleteKeys = input.ApiKeys.Where(k => !allowedKeys.Contains(k.Name ?? string.Empty)).ToList();

        return new EnforcementPlan(network, !input.QuickConnectAvailable, deleteKeys, PlanUsers(input, errors), errors);
    }

    private static NetworkChange? PlanNetwork(NetworkSettings? wanted, NetworkFacts facts)
    {
        if (wanted is null)
            return null;
        var save = !SameSet(facts.KnownProxies, wanted.KnownProxies)
                   || !SameSet(facts.LocalNetworkSubnets, wanted.LocalNetworkSubnets)
                   || !facts.EnableRemoteAccess;
        // The running server uses the KnownProxies it started with, whatever the file says now.
        var restart = !SameSet(facts.KnownProxiesInEffect, wanted.KnownProxies);
        return save || restart
            ? new NetworkChange(wanted.KnownProxies, wanted.LocalNetworkSubnets, save, restart, facts.KnownProxiesInEffect)
            : null;
    }

    /// <summary>Order and duplicates do not matter; addresses compare case-insensitively (IPv6).</summary>
    internal static bool SameSet(IEnumerable<string> a, IEnumerable<string> b)
        => a.Select(x => x.Trim()).ToHashSet(StringComparer.OrdinalIgnoreCase)
            .SetEquals(b.Select(x => x.Trim()));

    private static List<UserChange> PlanUsers(EnforcementInput input, List<string> errors)
    {
        var breakGlass = input.Settings.BreakGlassUsers.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var disabledByPolicy = input.DisabledByPolicy.ToHashSet();
        var links = input.ProviderId is null
            ? new Dictionary<Guid, List<LinkConfig>>()
            : input.Links.Where(l => string.Equals(l.ProviderId, input.ProviderId, StringComparison.Ordinal))
                .GroupBy(l => l.JellyfinUserId)
                .ToDictionary(g => g.Key, g => g.ToList());
        if (input.ProviderId is null)
            errors.Add("No SSO provider is enabled: linked and unmanaged accounts are left alone this round.");

        var changes = new List<UserChange>();
        foreach (var user in input.Users.OrderBy(u => u.Name, StringComparer.OrdinalIgnoreCase))
        {
            var inList = disabledByPolicy.Contains(user.Id);
            Target? target;
            if (links.TryGetValue(user.Id, out var userLinks))
            {
                if (breakGlass.Contains(user.Name))
                    errors.Add($"Break-glass user '{user.Name}' is linked to an SSO identity; it is treated as a linked user. Remove the link or the break-glass entry.");
                target = Linked(userLinks, input.Feed, user, inList);
            }
            else if (breakGlass.Contains(user.Name))
            {
                target = BreakGlass(input.Settings.BreakGlassEnabled, user, inList);
            }
            else if (input.ProviderId is null)
            {
                target = null;
            }
            else
            {
                target = Disable("unmanaged account (not linked to an SSO identity, not break-glass)", user, inList);
            }

            if (target is not null && Diff(user, target, inList) is { } change)
                changes.Add(change);
        }

        KeepOneAdministrator(input.Users, changes, errors);
        return changes;
    }

    // What a rule wants for a user; null fields: the rule does not care.
    private sealed record Target(string Reason)
    {
        public bool? IsAdministrator { get; init; }
        public bool? IsDisabled { get; init; }
        public bool? EnableRemoteAccess { get; init; }
        public string? AuthenticationProviderId { get; init; }
        public bool RevokeTokens { get; init; }
        public bool AddToList { get; init; }
        public bool RemoveFromList { get; init; }
    }

    /// <summary>
    /// The local emergency administrator: password login, admin, only from the local networks.
    /// It stays an administrator while disabled, so Jellyfin always has one.
    /// </summary>
    private static Target BreakGlass(bool enabled, UserFacts user, bool inList)
        => enabled
            ? new Target("break-glass account (enabled)")
            {
                IsAdministrator = true,
                IsDisabled = false,
                EnableRemoteAccess = false,
                AuthenticationProviderId = PasswordProviderId,
                RemoveFromList = inList,
            }
            : new Target("break-glass account (disabled)")
            {
                IsAdministrator = true,
                IsDisabled = true,
                EnableRemoteAccess = false,
                AuthenticationProviderId = PasswordProviderId,
                RevokeTokens = true,
                AddToList = !inList,
            };

    private static Target Linked(List<LinkConfig> links, DirectoryFeed? feed, UserFacts user, bool inList)
    {
        // A linked account logs in through SSO only: a password next to it would outlive the
        // person's removal from the directory.
        var ssoOnly = new Target("linked account") { AuthenticationProviderId = SsoProviderId };
        if (feed is null)
            return ssoOnly;

        // A login newer than the feed is fresher evidence (the IdP let the person in after the
        // feed was written): wait for the next feed.
        var lastLogin = links.Max(l => l.LastLoginUtc);
        if (lastLogin is { } login && login > feed.GeneratedAt)
            return ssoOnly;

        if (!links.Any(l => feed.Allowed.Contains(l.Sub)))
            return Disable("not in the directory feed", user, inList) with { AuthenticationProviderId = SsoProviderId };

        return ssoOnly with
        {
            Reason = "in the directory feed",
            IsAdministrator = links.Any(l => feed.IsAdmin(l.Sub)),
            // Only what the enforcement disabled is enabled again; a disable by hand stays.
            IsDisabled = inList ? false : null,
            RemoveFromList = inList,
        };
    }

    /// <summary>
    /// Disabled, no admin, no token. Listed as disabled by policy only when the enforcement is
    /// the one disabling it: an account an admin already disabled by hand stays theirs.
    /// </summary>
    private static Target Disable(string reason, UserFacts user, bool inList)
        => new(reason)
        {
            IsAdministrator = false,
            IsDisabled = true,
            RevokeTokens = true,
            AddToList = !user.IsDisabled && !inList,
        };

    private static UserChange? Diff(UserFacts user, Target t, bool inList)
    {
        var change = new UserChange(user.Id, user.Name, t.Reason)
        {
            IsAdministrator = t.IsAdministrator is { } a && a != user.IsAdministrator ? a : null,
            IsDisabled = t.IsDisabled is { } d && d != user.IsDisabled ? d : null,
            EnableRemoteAccess = t.EnableRemoteAccess is { } r && r != user.EnableRemoteAccess ? r : null,
            AuthenticationProviderId = t.AuthenticationProviderId is { } p
                && !string.Equals(p, user.AuthenticationProviderId, StringComparison.OrdinalIgnoreCase) ? p : null,
            RevokeTokens = t.RevokeTokens,
            AddToDisabledByPolicy = t.AddToList && !inList,
            RemoveFromDisabledByPolicy = t.RemoveFromList && inList,
        };
        return change.ChangesPolicy || change.RevokeTokens || change.AddToDisabledByPolicy || change.RemoveFromDisabledByPolicy
            ? change
            : null;
    }

    /// <summary>
    /// Jellyfin must keep at least one administrator account (its UserController refuses to
    /// remove the last one; UserManager does not check). When the plan would leave none, one
    /// demoted account keeps the flag: preferably one that ends up disabled, so nobody gains
    /// anything by it.
    /// </summary>
    private static void KeepOneAdministrator(IReadOnlyList<UserFacts> users, List<UserChange> changes, List<string> errors)
    {
        var byId = changes.ToDictionary(c => c.UserId);
        var anyAdminLeft = users.Any(u => byId.TryGetValue(u.Id, out var c) ? c.IsAdministrator ?? u.IsAdministrator : u.IsAdministrator);
        if (anyAdminLeft)
            return;

        var keep = changes
            .Where(c => c.IsAdministrator == false)
            .OrderByDescending(c => c.IsDisabled ?? users.First(u => u.Id == c.UserId).IsDisabled)
            .ThenBy(c => c.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (keep is null)
            return;

        changes[changes.IndexOf(keep)] = keep with { IsAdministrator = null };
        errors.Add($"'{keep.Name}' keeps the administrator flag: Jellyfin would have no administrator left. "
            + "Configure a break-glass user.");
    }
}
