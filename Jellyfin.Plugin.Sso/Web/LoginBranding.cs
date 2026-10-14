using System.Net;
using Jellyfin.Plugin.Sso.Configuration;
using MediaBrowser.Controller.Configuration;
using MediaBrowser.Model.Branding;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Sso.Web;

/// <summary>
/// Sets Jellyfin's LoginDisclaimer to an "Login with SSO" anchor link.
/// Runs once at plugin start and whenever the configuration changes.
/// DOMPurify allows anchor tags with href, so this is the supported approach.
/// </summary>
public sealed class LoginBranding
{
    private readonly IServerConfigurationManager _configManager;
    private readonly EffectiveConfig _settings;
    private readonly ILogger<LoginBranding> _logger;

    public LoginBranding(IServerConfigurationManager configManager, EffectiveConfig settings, ILogger<LoginBranding> logger)
    {
        _configManager = configManager;
        _settings = settings;
        _logger = logger;
    }

    public void Apply()
    {
        var settings = _settings.Get();
        var provider = settings.Providers.FirstOrDefault(p => p.Enabled);

        var branding = (_configManager.GetConfiguration("branding") as BrandingOptions)
            ?? new BrandingOptions();

        if (provider is null)
        {
            // No enabled provider — remove the button if it was previously set by us.
            if (branding.LoginDisclaimer?.Contains("/sso/oidc/start") == true)
            {
                branding.LoginDisclaimer = string.Empty;
                _configManager.SaveConfiguration("branding", branding);
            }
            return;
        }

        var link = Button(provider, settings.LoginButtonText);

        if (string.Equals(branding.LoginDisclaimer, link, StringComparison.Ordinal))
            return; // no change needed

        branding.LoginDisclaimer = link;
        _configManager.SaveConfiguration("branding", branding);
        _logger.LogInformation("SSO: login button set in Jellyfin branding for provider {Name}.", provider.Name);
    }

    /// <summary>A link styled with Jellyfin's own button classes; every value HTML-encoded.</summary>
    internal static string Button(ProviderConfig provider, string? text)
    {
        var label = string.IsNullOrWhiteSpace(text) ? $"Login with SSO ({provider.Name})" : text;
        return "<a class=\"raised emby-button block\" "
            + $"href=\"/sso/oidc/start/{WebUtility.HtmlEncode(Uri.EscapeDataString(provider.Id))}\" "
            + "style=\"display:block;text-align:center;margin-top:.5em\">"
            + WebUtility.HtmlEncode(label) + "</a>";
    }
}
