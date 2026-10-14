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
            // No enabled provider — remove the button and our style if they were set by us.
            var css = MergeCss(branding.CustomCss, null);
            var hadButton = branding.LoginDisclaimer?.Contains("/sso/oidc/start") == true;
            if (hadButton || !string.Equals(css, branding.CustomCss ?? string.Empty, StringComparison.Ordinal))
            {
                if (hadButton)
                    branding.LoginDisclaimer = string.Empty;
                branding.CustomCss = css;
                _configManager.SaveConfiguration("branding", branding);
            }
            return;
        }

        var link = Button(provider, settings.LoginButtonText);
        var style = MergeCss(branding.CustomCss, LoginCss.Value);

        if (string.Equals(branding.LoginDisclaimer, link, StringComparison.Ordinal)
            && string.Equals(branding.CustomCss, style, StringComparison.Ordinal))
            return; // no change needed

        branding.LoginDisclaimer = link;
        branding.CustomCss = style;
        _configManager.SaveConfiguration("branding", branding);
        _logger.LogInformation("SSO: login button set in Jellyfin branding for provider {Name}.", provider.Name);
    }

    private const string CssStart = "/* jellyfin-sso:start";
    private const string CssEnd = "/* jellyfin-sso:end */";

    // Web/login.css: the button large and above the password form (Jellyfin renders the login
    // disclaimer below it and allows no script there; CSS is all a plugin can change).
    private static readonly Lazy<string> LoginCss = new(() =>
    {
        using var stream = typeof(LoginBranding).Assembly.GetManifestResourceStream("Jellyfin.Plugin.Sso.Web.login.css")
            ?? throw new InvalidOperationException("login.css is not embedded");
        using var reader = new StreamReader(stream);
        return reader.ReadToEnd().Trim();
    });

    /// <summary>
    /// The custom CSS with our block (between the markers) replaced by <paramref name="block"/>,
    /// or removed when it is null. CSS an admin wrote outside the markers stays as it is.
    /// </summary>
    internal static string MergeCss(string? existing, string? block)
    {
        var css = existing ?? string.Empty;
        var start = css.IndexOf(CssStart, StringComparison.Ordinal);
        if (start >= 0)
        {
            var end = css.IndexOf(CssEnd, start, StringComparison.Ordinal);
            css = end < 0 ? css[..start] : css[..start] + css[(end + CssEnd.Length)..];
        }
        css = css.Trim();
        if (block is null)
            return css;
        return css.Length == 0 ? block : css + "\n" + block;
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
