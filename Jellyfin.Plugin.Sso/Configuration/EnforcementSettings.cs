using System.Net;

namespace Jellyfin.Plugin.Sso.Configuration;

/// <summary>
/// The "Enforcement" setting, validated: what the enforcement service
/// (Enforcement/EnforcementService) keeps true in Jellyfin, at startup and every interval.
/// Set by the settings file; without it nothing is enforced.
/// </summary>
public sealed record EnforcementSettings(
    bool Enabled,
    int IntervalSeconds,
    NetworkSettings? Network,
    IReadOnlyList<string> BreakGlassUsers,
    bool BreakGlassEnabled,
    IReadOnlyList<string> AllowedApiKeyNames,
    DirectorySettings? Directory)
{
    public const int DefaultIntervalSeconds = 60;
    public const int MaxIntervalSeconds = 86400;

    /// <summary>Validated settings from the file's section; throws InvalidDataException when invalid.</summary>
    public static EnforcementSettings From(EnforcementFile file)
    {
        var interval = file.IntervalSeconds ?? DefaultIntervalSeconds;
        if (interval < 1 || interval > MaxIntervalSeconds)
            throw new InvalidDataException($"Enforcement.IntervalSeconds must be between 1 and {MaxIntervalSeconds}");

        NetworkSettings? network = null;
        if (file.Network is { } n)
        {
            // Only addresses and networks: a host name would be resolved by Jellyfin at startup,
            // i.e. trusted to whoever answers DNS then.
            var proxies = Clean(n.KnownProxies, "Enforcement.Network.KnownProxies");
            foreach (var p in proxies)
            {
                if (!IPAddress.TryParse(p, out _) && !IPNetwork.TryParse(p, out _))
                    throw new InvalidDataException($"Enforcement.Network.KnownProxies: '{p}' is no IP address or network");
            }
            var subnets = Clean(n.LocalNetworkSubnets, "Enforcement.Network.LocalNetworkSubnets");
            foreach (var s in subnets)
            {
                if (!IPNetwork.TryParse(s, out _) && !IPAddress.TryParse(s, out _))
                    throw new InvalidDataException($"Enforcement.Network.LocalNetworkSubnets: '{s}' is no network");
            }
            network = new NetworkSettings(proxies, subnets);
        }

        var breakGlass = Clean(file.BreakGlass?.Users, "Enforcement.BreakGlass.Users");
        var apiKeys = Clean(file.AllowedApiKeyNames, "Enforcement.AllowedApiKeyNames");

        DirectorySettings? directory = null;
        if (file.Directory is { } d)
        {
            if (string.IsNullOrWhiteSpace(d.Path) || !System.IO.Path.IsPathFullyQualified(d.Path))
                throw new InvalidDataException("Enforcement.Directory.Path must be an absolute path");
            if (d.MaxAgeSeconds is not { } maxAge || maxAge < 1)
                throw new InvalidDataException("Enforcement.Directory.MaxAgeSeconds must be a positive number");
            directory = new DirectorySettings(d.Path, maxAge);
        }

        return new EnforcementSettings(file.Enabled, interval, network, breakGlass, file.BreakGlass?.Enabled ?? false,
            apiKeys, directory);
    }

    private static List<string> Clean(List<string?>? values, string name)
    {
        var result = new List<string>();
        foreach (var v in values ?? [])
        {
            if (string.IsNullOrWhiteSpace(v))
                throw new InvalidDataException($"{name} must not contain empty values");
            result.Add(v.Trim());
        }
        return result;
    }
}

/// <summary>Jellyfin's network settings that the house manages.</summary>
public sealed record NetworkSettings(IReadOnlyList<string> KnownProxies, IReadOnlyList<string> LocalNetworkSubnets);

/// <summary>Where the house directory feed is and how old it may be.</summary>
public sealed record DirectorySettings(string Path, int MaxAgeSeconds);

// The JSON shape of the section (property names case-insensitive like the rest of the file).
public sealed class EnforcementFile
{
    public bool Enabled { get; set; }
    public int? IntervalSeconds { get; set; }
    public NetworkFile? Network { get; set; }
    public BreakGlassFile? BreakGlass { get; set; }
    public List<string?>? AllowedApiKeyNames { get; set; }
    public DirectoryFile? Directory { get; set; }
}

public sealed class NetworkFile
{
    public List<string?>? KnownProxies { get; set; }
    public List<string?>? LocalNetworkSubnets { get; set; }
}

public sealed class BreakGlassFile
{
    public List<string?>? Users { get; set; }
    public bool Enabled { get; set; }
}

public sealed class DirectoryFile
{
    public string? Path { get; set; }
    public int? MaxAgeSeconds { get; set; }
}
