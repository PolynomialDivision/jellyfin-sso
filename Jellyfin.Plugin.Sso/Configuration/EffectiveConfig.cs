using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Sso.Configuration;

/// <summary>The settings a login uses: public URL, providers and group mappings.</summary>
public sealed record SsoSettings(
    string PublicUrl,
    string LoginButtonText,
    bool RequireGroupMapping,
    IReadOnlyList<ProviderConfig> Providers,
    IReadOnlyList<GroupMappingConfig> GroupMappings,
    bool Managed);

/// <summary>
/// Where the settings come from. With the environment variable SSO_MANAGED_CONFIG set to a
/// JSON file (written by configuration management, mounted read-only), the public URL,
/// providers and group mappings come only from that file and the dashboard cannot change
/// them. Without it, they come from the plugin configuration (dashboard). Links and seen
/// groups always stay in the plugin configuration: they are state, not settings.
/// A managed file that cannot be read fails closed: no provider, so no SSO login.
/// </summary>
public sealed class EffectiveConfig
{
    public const string EnvironmentVariable = "SSO_MANAGED_CONFIG";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
    };

    private readonly ILogger<EffectiveConfig> _logger;
    private readonly string? _path;
    private readonly object _lock = new();
    private DateTime _loadedWriteTime;
    private SsoSettings? _managed;

    public EffectiveConfig(ILogger<EffectiveConfig> logger)
        : this(logger, Environment.GetEnvironmentVariable(EnvironmentVariable))
    {
    }

    internal EffectiveConfig(ILogger<EffectiveConfig> logger, string? path)
    {
        _logger = logger;
        _path = string.IsNullOrWhiteSpace(path) ? null : path;
    }

    public bool IsManaged => _path is not null;

    public SsoSettings Get()
    {
        if (_path is null)
        {
            var c = Plugin.Instance?.Configuration ?? new PluginConfiguration();
            return new SsoSettings(c.PublicUrl, c.LoginButtonText, c.RequireGroupMapping,
                c.Providers, c.GroupMappings, Managed: false);
        }

        lock (_lock)
        {
            try
            {
                var writeTime = File.GetLastWriteTimeUtc(_path);
                if (_managed is null || writeTime != _loadedWriteTime)
                {
                    _managed = Parse(File.ReadAllText(_path));
                    _loadedWriteTime = writeTime;
                    _logger.LogInformation("SSO: settings loaded from {Path} ({Count} provider(s), {Mappings} mapping(s)).",
                        _path, _managed.Providers.Count, _managed.GroupMappings.Count);
                }
                return _managed;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
            {
                _logger.LogError(ex, "SSO: cannot read the managed settings {Path}; SSO login is off.", _path);
                _managed = null;
                return new SsoSettings(string.Empty, string.Empty, true, [], [], Managed: true);
            }
        }
    }

    internal static SsoSettings Parse(string json)
    {
        var file = JsonSerializer.Deserialize<ManagedFile>(json, JsonOptions)
            ?? throw new InvalidDataException("empty managed settings");
        if (string.IsNullOrWhiteSpace(file.PublicUrl) || !Uri.TryCreate(file.PublicUrl, UriKind.Absolute, out var url)
            || url.Scheme != Uri.UriSchemeHttps && url.Scheme != Uri.UriSchemeHttp)
            throw new InvalidDataException("PublicUrl must be an absolute http(s) URL");
        foreach (var p in file.Providers)
        {
            if (string.IsNullOrWhiteSpace(p.Id) || p.Id.Any(ch => !char.IsAsciiLetterOrDigit(ch) && ch != '-' && ch != '_'))
                throw new InvalidDataException("every provider needs an Id of letters, digits, '-' or '_'");
            if (string.IsNullOrWhiteSpace(p.Authority) || string.IsNullOrWhiteSpace(p.ClientId))
                throw new InvalidDataException($"provider {p.Id} needs Authority and ClientId");
        }
        return new SsoSettings(file.PublicUrl.TrimEnd('/'), file.LoginButtonText ?? string.Empty,
            file.RequireGroupMapping ?? true, file.Providers, file.GroupMappings, Managed: true);
    }

    private sealed class ManagedFile
    {
        public string PublicUrl { get; set; } = string.Empty;
        public string? LoginButtonText { get; set; }
        public bool? RequireGroupMapping { get; set; }
        public List<ProviderConfig> Providers { get; set; } = [];
        public List<GroupMappingConfig> GroupMappings { get; set; } = [];
    }
}
