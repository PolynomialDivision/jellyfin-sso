using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Sso.Web;

/// <summary>
/// Sets the login button when Jellyfin starts and again whenever the plugin configuration is
/// saved. (Upstream relied on Plugin.ServiceProvider, which nothing ever set, so the button
/// never appeared on its own.)
/// </summary>
public sealed class BrandingStartup : IHostedService
{
    private readonly LoginBranding _branding;
    private readonly ILogger<BrandingStartup> _logger;

    public BrandingStartup(LoginBranding branding, ILogger<BrandingStartup> logger)
    {
        _branding = branding;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        Apply();
        if (Plugin.Instance is { } plugin)
            plugin.ConfigurationChanged += OnConfigurationChanged;
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        if (Plugin.Instance is { } plugin)
            plugin.ConfigurationChanged -= OnConfigurationChanged;
        return Task.CompletedTask;
    }

    private void OnConfigurationChanged(object? sender, MediaBrowser.Model.Plugins.BasePluginConfiguration e) => Apply();

    private void Apply()
    {
        try
        {
            _branding.Apply();
        }
        catch (Exception ex) when (ex is IOException or InvalidOperationException)
        {
            _logger.LogError(ex, "SSO: could not set the login button.");
        }
    }
}
