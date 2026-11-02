using Jellyfin.Plugin.Sso.Configuration;

namespace Jellyfin.Plugin.Sso.Enforcement;

/// <summary>
/// The enforcement's state in the plugin configuration (DisabledByPolicy, LastLoginUtc of the
/// links; every access through PluginStateStore) and the round lock. An enforcement round
/// holds the round lock from reading the facts to the last change; an SSO login takes it to
/// record itself and to enable a user the enforcement disabled. So a round never acts on a
/// login it has not seen.
/// </summary>
public sealed class PolicyState
{
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task<IDisposable> LockAsync(CancellationToken ct)
    {
        await _lock.WaitAsync(ct).ConfigureAwait(false);
        return new Releaser(_lock);
    }

    private static PluginStateStore Store => PluginStateStore.Shared;

    public static IReadOnlyList<Guid> DisabledByPolicy() => Store.Read(c => c.DisabledByPolicy.ToList());

    public static bool IsDisabledByPolicy(Guid userId) => Store.Read(c => c.DisabledByPolicy.Contains(userId));

    /// <summary>Copies of the links, so a round reads one consistent state.</summary>
    public static IReadOnlyList<LinkConfig> Links() => Store.Read(c => c.Links.Select(Copy).ToList());

    internal static LinkConfig Copy(LinkConfig l)
        => new() { ProviderId = l.ProviderId, Sub = l.Sub, JellyfinUserId = l.JellyfinUserId, LastLoginUtc = l.LastLoginUtc };

    // The list is saved before a user is disabled and after it is enabled: a crash in between
    // leaves a user that is enabled and listed (disabled again next round when it should be),
    // never one the enforcement disabled but forgot (it would count as disabled by hand).
    public static void AddDisabledByPolicy(Guid userId)
        => Store.Update(c =>
        {
            if (c.DisabledByPolicy.Contains(userId))
                return false;
            c.DisabledByPolicy.Add(userId);
            return true;
        });

    public static void RemoveDisabledByPolicy(Guid userId)
        => Store.Update(c => c.DisabledByPolicy.RemoveAll(id => id == userId) > 0);

    /// <summary>Records a successful SSO login on the user's link of this provider and subject.</summary>
    public static void RecordLogin(string providerId, string sub, DateTimeOffset when)
        => Store.Update(c =>
        {
            var link = c.Links.FirstOrDefault(l => l.ProviderId == providerId && string.Equals(l.Sub, sub, StringComparison.Ordinal));
            if (link is null)
                return false;
            link.LastLoginUtc = when;
            return true;
        });

    private sealed class Releaser(SemaphoreSlim semaphore) : IDisposable
    {
        private int _released;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _released, 1) == 0)
                semaphore.Release();
        }
    }
}
