using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Jellyfin.Plugin.Sso.Auth;

/// <summary>
/// Quick Connect through SSO, without a code in any link: after the IdP login the person types
/// the code their device shows. Typing it is the confirmation, as in Jellyfin's own Quick
/// Connect page; a link that carries a code (someone else's device) would sign a person in on
/// a stranger's device with one click. The approval token proves that this browser just
/// completed the IdP login: random, single use, five minutes, bound to the Jellyfin user.
/// </summary>
public sealed class QuickConnectApprovalStore
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    private sealed record Entry(Guid UserId, DateTimeOffset Expiry);

    private readonly ConcurrentDictionary<string, Entry> _store = new();

    public string Issue(Guid userId)
    {
        Purge();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        _store[token] = new Entry(userId, DateTimeOffset.UtcNow.Add(Ttl));
        return token;
    }

    /// <summary>The user bound to the token, or null; the token is gone afterwards either way.</summary>
    public Guid? Consume(string? token)
    {
        if (string.IsNullOrEmpty(token) || !_store.TryRemove(token, out var entry))
            return null;
        return entry.Expiry > DateTimeOffset.UtcNow ? entry.UserId : null;
    }

    private void Purge()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var (key, entry) in _store)
        {
            if (entry.Expiry <= now)
                _store.TryRemove(key, out _);
        }
    }
}
