using Jellyfin.Plugin.Sso.Configuration;
using MediaBrowser.Controller.Library;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Jellyfin.Plugin.Sso.Controllers;

/// <summary>
/// Admin API + UI endpoints.
/// /ui is AllowAnonymous (static HTML/JS only). All data endpoints require admin.
/// </summary>
[ApiController]
[Route("sso/admin")]
public sealed class AdminController : ControllerBase
{
    private readonly ILibraryManager _libraryManager;
    private readonly IUserManager _userManager;
    private readonly EffectiveConfig _settings;

    public AdminController(ILibraryManager libraryManager, IUserManager userManager, EffectiveConfig settings)
    {
        _libraryManager = libraryManager;
        _userManager = userManager;
        _settings = settings;
    }

    // ─── Config ──────────────────────────────────────────────────────────────

    /// <summary>The settings in use (from the managed file, if any) plus the plugin's state.</summary>
    [HttpGet("config")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetConfig()
    {
        var c = Plugin.Instance!.Configuration;
        var s = _settings.Get();
        return Ok(new
        {
            s.PublicUrl,
            s.LoginButtonText,
            s.RequireGroupMapping,
            s.Providers,
            s.GroupMappings,
            c.Links,
            c.SeenGroups,
            s.Managed,
        });
    }

    [HttpPost("config")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult SaveConfig([FromBody] PluginConfiguration config)
    {
        if (_settings.IsManaged)
            return Conflict("The SSO settings are managed by a file (" + EffectiveConfig.EnvironmentVariable
                + "); only account links can be changed here.");
        // Links and seen groups are the plugin's own state: never replaced by a page save
        // (a page opened earlier would drop the links made since).
        var current = Plugin.Instance!.Configuration;
        config.Links = current.Links;
        config.SeenGroups = current.SeenGroups;
        Plugin.Instance.UpdateConfiguration(config);
        return Ok();
    }

    // ─── Libraries ───────────────────────────────────────────────────────────

    [HttpGet("libraries")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetLibraries()
    {
        var folders = _libraryManager.GetVirtualFolders();
        return Ok(folders.Select(f => new { f.Name, ItemId = f.ItemId }));
    }

    // ─── Jellyfin users (for the manual-link dropdown) ────────────────────────

    [HttpGet("users")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetUsers()
    {
        var linkedIds = Plugin.Instance!.Configuration.Links
            .Select(l => l.JellyfinUserId).ToHashSet();
        return Ok(_userManager.GetUsers()
            .OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase)
            .Select(u => new { Id = u.Id, Name = u.Username, Linked = linkedIds.Contains(u.Id) })
            .ToList());
    }

    // ─── Seen groups ──────────────────────────────────────────────────────────

    [HttpGet("seen-groups")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetSeenGroups()
        => Ok(Plugin.Instance!.Configuration.SeenGroups.OrderBy(g => g));

    // ─── Links ───────────────────────────────────────────────────────────────

    [HttpGet("links")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetLinks()
    {
        var config = Plugin.Instance!.Configuration;
        return Ok(config.Links.Select(l => new
        {
            l.ProviderId,
            l.Sub,
            l.JellyfinUserId,
            Username = _userManager.GetUserById(l.JellyfinUserId)?.Username ?? "(deleted)",
        }));
    }

    [HttpPost("links")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult CreateLink([FromBody] LinkConfig link)
    {
        var config = Plugin.Instance!.Configuration;
        if (config.Links.Any(l =>
                l.ProviderId == link.ProviderId &&
                string.Equals(l.Sub, link.Sub, StringComparison.Ordinal)))
            return Conflict("Link already exists.");
        config.Links.Add(link);
        Plugin.Instance.SaveConfiguration();
        return Ok();
    }

    [HttpDelete("links/{jellyfinUserId:guid}")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult DeleteLink(Guid jellyfinUserId)
    {
        var config = Plugin.Instance!.Configuration;
        var removed = config.Links.RemoveAll(l => l.JellyfinUserId == jellyfinUserId);
        if (removed == 0) return NotFound();
        Plugin.Instance.SaveConfiguration();
        return Ok();
    }

}
