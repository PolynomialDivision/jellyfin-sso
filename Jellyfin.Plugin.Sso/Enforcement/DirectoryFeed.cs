using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Jellyfin.Plugin.Sso.Enforcement;

/// <summary>
/// The house directory's list of who may use Jellyfin, written by another container:
/// <c>{"version": 1, "generated_at": "…Z", "allowed": ["sub", …], "admins": ["sub", …]}</c>.
/// Subjects are the OIDC <c>sub</c> of the configured provider (LinkConfig.Sub).
/// </summary>
public sealed partial record DirectoryFeed(DateTimeOffset GeneratedAt, IReadOnlySet<string> Allowed, IReadOnlySet<string> Admins)
{
    public const int SupportedVersion = 1;

    /// <summary>A feed from further ahead than this is a broken clock, not a fresh list.</summary>
    public static readonly TimeSpan MaxFutureSkew = TimeSpan.FromSeconds(300);

    // Larger than any real list of a house; a bigger file is not read into memory.
    internal const long MaxBytes = 1024 * 1024;

    /// <summary>
    /// Admins is the subset of allowed: a subject only in "admins" is not let in by it.
    /// </summary>
    public bool IsAdmin(string sub) => Allowed.Contains(sub) && Admins.Contains(sub);

    /// <summary>
    /// The feed if it may be used for decisions now, else null and why. Usable only when it
    /// parses, has version 1, a generated_at with an explicit offset that is neither older than
    /// maxAge nor more than five minutes ahead, and a non-empty "allowed" (an empty list is far
    /// more likely a broken export than a house without residents; it would disable everyone).
    /// </summary>
    public static DirectoryFeed? Usable(string? json, DateTimeOffset now, TimeSpan maxAge, out string reason)
    {
        if (json is null)
        {
            reason = "no feed";
            return null;
        }

        DirectoryFeed feed;
        try
        {
            feed = Parse(json);
        }
        catch (Exception ex) when (ex is JsonException or InvalidDataException)
        {
            reason = "invalid: " + ex.Message;
            return null;
        }

        if (feed.GeneratedAt > now + MaxFutureSkew)
        {
            reason = $"generated_at {feed.GeneratedAt:O} is in the future";
            return null;
        }
        if (now - feed.GeneratedAt > maxAge)
        {
            reason = $"generated_at {feed.GeneratedAt:O} is older than {maxAge.TotalSeconds:0} s";
            return null;
        }
        if (feed.Allowed.Count == 0)
        {
            reason = "\"allowed\" is empty";
            return null;
        }

        reason = string.Empty;
        return feed;
    }

    internal static DirectoryFeed Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new InvalidDataException("not a JSON object");

        if (!root.TryGetProperty("version", out var version) || version.ValueKind != JsonValueKind.Number
            || !version.TryGetInt32(out var v) || v != SupportedVersion)
            throw new InvalidDataException($"\"version\" must be {SupportedVersion}");

        if (!root.TryGetProperty("generated_at", out var generated) || generated.ValueKind != JsonValueKind.String)
            throw new InvalidDataException("\"generated_at\" is missing");
        var text = generated.GetString()!;
        // A time without an offset could be any zone: not guessed.
        if (!ExplicitOffset().IsMatch(text)
            || !DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var generatedAt))
            throw new InvalidDataException("\"generated_at\" must be an ISO 8601 time with Z or an offset");

        return new DirectoryFeed(generatedAt, Subjects(root, "allowed"), Subjects(root, "admins"));
    }

    private static HashSet<string> Subjects(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out var list) || list.ValueKind != JsonValueKind.Array)
            throw new InvalidDataException($"\"{name}\" must be a list");
        var result = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in list.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || string.IsNullOrEmpty(item.GetString()))
                throw new InvalidDataException($"\"{name}\" must contain only non-empty strings");
            result.Add(item.GetString()!);
        }
        return result;
    }

    [GeneratedRegex(@"T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$", RegexOptions.CultureInvariant)]
    private static partial Regex ExplicitOffset();
}
