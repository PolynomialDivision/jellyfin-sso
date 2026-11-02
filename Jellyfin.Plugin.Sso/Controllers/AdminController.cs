using Jellyfin.Plugin.Sso.Configuration;
using Jellyfin.Plugin.Sso.Enforcement;
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
        var s = _settings.Get();
        var (links, seenGroups) = PluginStateStore.Shared.Read(c => (c.Links.Select(PolicyState.Copy).ToList(), c.SeenGroups.ToList()));
        return Ok(new
        {
            s.PublicUrl,
            s.LoginButtonText,
            s.RequireGroupMapping,
            s.Providers,
            s.GroupMappings,
            Links = links,
            SeenGroups = seenGroups,
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
        // Links, seen groups and the enforcement's list are the plugin's own state: never
        // replaced by a page save (a page opened earlier would drop the links made since).
        PluginStateStore.Shared.Update(current =>
        {
            config.Links = current.Links;
            config.SeenGroups = current.SeenGroups;
            config.DisabledByPolicy = current.DisabledByPolicy;
            Plugin.Instance!.UpdateConfiguration(config); // saves itself
            return false;
        });
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
        var linkedIds = PluginStateStore.Shared.Read(c => c.Links.Select(l => l.JellyfinUserId).ToHashSet());
        return Ok(_userManager.GetUsers()
            .OrderBy(u => u.Username, StringComparer.OrdinalIgnoreCase)
            .Select(u => new { Id = u.Id, Name = u.Username, Linked = linkedIds.Contains(u.Id) })
            .ToList());
    }

    // ─── Seen groups ──────────────────────────────────────────────────────────

    [HttpGet("seen-groups")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetSeenGroups()
        => Ok(PluginStateStore.Shared.Read(c => c.SeenGroups.OrderBy(g => g).ToList()));

    // ─── Links ───────────────────────────────────────────────────────────────

    [HttpGet("links")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult GetLinks()
    {
        var links = PluginStateStore.Shared.Read(c => c.Links.Select(PolicyState.Copy).ToList());
        return Ok(links.Select(l => new
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
        // Only a real login sets the login time (a future one would shield the user from the
        // directory feed).
        link.LastLoginUtc = null;
        var added = PluginStateStore.Shared.Update(c =>
        {
            if (c.Links.Any(l => l.ProviderId == link.ProviderId && string.Equals(l.Sub, link.Sub, StringComparison.Ordinal)))
                return (false, false);
            c.Links.Add(link);
            return (true, true);
        });
        return added ? Ok() : Conflict("Link already exists.");
    }

    [HttpDelete("links/{jellyfinUserId:guid}")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult DeleteLink(Guid jellyfinUserId)
    {
        var removed = PluginStateStore.Shared.Update(c =>
        {
            var n = c.Links.RemoveAll(l => l.JellyfinUserId == jellyfinUserId);
            return (n, n > 0);
        });
        return removed == 0 ? NotFound() : Ok();
    }

}
