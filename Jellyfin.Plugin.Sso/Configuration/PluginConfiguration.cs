using MediaBrowser.Model.Plugins;

namespace Jellyfin.Plugin.Sso.Configuration;

public class PluginConfiguration : BasePluginConfiguration
{
    /// <summary>
    /// The public base URL of Jellyfin (e.g. https://media.example.org). The OIDC callback
    /// URL is built from it, never from request headers (Host / X-Forwarded-* are client
    /// controlled). Required: without it the login refuses to start.
    /// </summary>
    public string PublicUrl { get; set; } = string.Empty;

    /// <summary>Text of the login button; empty: "Login with SSO (provider name)".</summary>
    public string LoginButtonText { get; set; } = string.Empty;

    /// <summary>
    /// When true (default), an IdP login whose groups match no mapping is refused before a
    /// Jellyfin user is created or changed.
    /// </summary>
    public bool RequireGroupMapping { get; set; } = true;

    public List<ProviderConfig> Providers { get; set; } = [];
    public List<GroupMappingConfig> GroupMappings { get; set; } = [];

    // State written by the plugin itself (never part of the managed file).
    public List<LinkConfig> Links { get; set; } = [];
    public List<string> SeenGroups { get; set; } = [];
}

public class ProviderConfig
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = string.Empty;
    public bool Enabled { get; set; }

    /// <summary>OIDC issuer URL — used for discovery (/.well-known/openid-configuration).</summary>
    public string Authority { get; set; } = string.Empty;

    public string ClientId { get; set; } = string.Empty;
    public OidcClientType ClientType { get; set; } = OidcClientType.Public;

    /// <summary>
    /// Env var name (prefix "env:") or absolute file path (prefix "file:") containing
    /// the client_secret. Never the literal secret. Only used when ClientType=Confidential.
    /// </summary>
    public string? ConfidentialSecretRef { get; set; }

    public List<string> Scopes { get; set; } = ["openid", "profile", "email"];

    /// <summary>Claim name for groups. Default "groups" works for Authentik + Authelia.</summary>
    public string GroupsClaim { get; set; } = "groups";

    /// <summary>When true, fetch groups from userinfo endpoint instead of the ID token.</summary>
    public bool GroupsFromUserInfo { get; set; }
}

public enum OidcClientType
{
    Public,
    Confidential,
}

public class GroupMappingConfig
{
    public string Group { get; set; } = string.Empty;

    /// <summary>
    /// Library GUIDs (stable ItemId values from ILibraryManager.GetVirtualFolders()).
    /// Stored as strings to survive XML serialization round-trips cleanly.
    /// </summary>
    public List<string> LibraryIds { get; set; } = [];

    /// <summary>Access to every library, including ones added later (no IDs needed).</summary>
    public bool AllLibraries { get; set; }

    public bool IsAdministrator { get; set; }
}

/// <summary>
/// Maps one OIDC identity (provider + sub) to one Jellyfin user.
/// Created by JIT provisioning or a manual admin action. Never auto-matched by username.
/// </summary>
public class LinkConfig
{
    public string ProviderId { get; set; } = string.Empty;
    public string Sub { get; set; } = string.Empty;
    public Guid JellyfinUserId { get; set; }
}
