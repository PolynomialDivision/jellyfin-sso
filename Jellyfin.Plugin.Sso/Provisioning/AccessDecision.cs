using Jellyfin.Plugin.Sso.Configuration;

namespace Jellyfin.Plugin.Sso.Provisioning;

/// <summary>What the IdP groups of one login grant in Jellyfin.</summary>
public sealed record AccessDecision(bool Allowed, bool IsAdministrator, bool AllLibraries, IReadOnlyList<Guid> LibraryIds)
{
    /// <summary>
    /// Pure: the union of every mapping whose group the user has. Admins and "all libraries"
    /// mappings see everything. With requireMapping, no matching mapping means no access
    /// (checked before a user is created or changed).
    /// </summary>
    public static AccessDecision From(IEnumerable<GroupMappingConfig> mappings, IEnumerable<string> groups, bool requireMapping)
    {
        var have = groups.ToHashSet(StringComparer.Ordinal);
        var matched = mappings.Where(m => have.Contains(m.Group)).ToList();
        var isAdmin = matched.Any(m => m.IsAdministrator);
        var all = isAdmin || matched.Any(m => m.AllLibraries);
        var ids = all ? [] : matched
            .SelectMany(m => m.LibraryIds)
            .Select(id => Guid.TryParse(id, out var g) ? g : throw new FormatException($"library id '{id}' is not a GUID"))
            .Distinct()
            .ToList();
        return new AccessDecision(!requireMapping || matched.Count > 0, isAdmin, all, ids);
    }
}
