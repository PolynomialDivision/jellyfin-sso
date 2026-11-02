namespace Jellyfin.Plugin.Sso.Configuration;

/// <summary>
/// The one lock around the plugin's own state in its XML configuration (links, seen groups,
/// DisabledByPolicy). Logins, the dashboard endpoints and the enforcement change these lists
/// from different threads; saving serializes the whole configuration, so a save must never
/// enumerate a list another thread is changing. Every change and its save, and every read of a
/// list, happens in here. Short and synchronous: no Jellyfin call inside.
/// </summary>
public sealed class PluginStateStore
{
    private readonly object _lock = new();
    private readonly Func<PluginConfiguration> _config;
    private readonly Action _save;

    internal PluginStateStore(Func<PluginConfiguration> config, Action save)
    {
        _config = config;
        _save = save;
    }

    /// <summary>The store of the loaded plugin.</summary>
    public static PluginStateStore Shared { get; } = new(
        () => Plugin.Instance?.Configuration ?? throw new InvalidOperationException("The SSO plugin is not loaded."),
        () => Plugin.Instance!.SaveConfiguration());

    /// <summary>Reads under the lock; return copies, never the lists themselves.</summary>
    public T Read<T>(Func<PluginConfiguration, T> read)
    {
        lock (_lock)
            return read(_config());
    }

    /// <summary>Changes under the lock and saves when the change says it changed something.</summary>
    public void Update(Func<PluginConfiguration, bool> change)
    {
        lock (_lock)
        {
            if (change(_config()))
                _save();
        }
    }

    /// <summary>Like Update, with a result for the caller.</summary>
    public T Update<T>(Func<PluginConfiguration, (T Result, bool Changed)> change)
    {
        lock (_lock)
        {
            var (result, changed) = change(_config());
            if (changed)
                _save();
            return result;
        }
    }
}
