using Jellyfin.Plugin.Sso.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Jellyfin.Plugin.Sso.Enforcement;

/// <summary>
/// Keeps the managed "Enforcement" section true in Jellyfin: one round as soon as Jellyfin has
/// started, then one every IntervalSeconds. The section is read again each round; without it
/// (or with Enabled false) nothing is done. A managed file that cannot be read means no round
/// at all: nothing is decided from a guess.
/// </summary>
public sealed class EnforcementService : BackgroundService
{
    private static readonly TimeSpan IdleInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan WarnEvery = TimeSpan.FromMinutes(10);

    private readonly EffectiveConfig _settings;
    private readonly EnforcementExecutor _executor;
    private readonly PolicyState _state;
    private readonly ILogger<EnforcementService> _logger;

    private IReadOnlyList<string> _knownProxiesInEffect = [];
    private DateTimeOffset _lastFeedWarning = DateTimeOffset.MinValue;
    private bool _feedWasUnusable;
    private DateTimeOffset _lastSettingsError = DateTimeOffset.MinValue;
    private bool _wasActive;
    private bool _wizardNoticeLogged;

    public EnforcementService(EffectiveConfig settings, EnforcementExecutor executor, PolicyState state, ILogger<EnforcementService> logger)
    {
        _settings = settings;
        _executor = executor;
        _state = state;
        _logger = logger;
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        // Jellyfin configured its forwarded-headers handling from these when this host was
        // built; a later change of the setting needs a restart to take effect.
        _knownProxiesInEffect = _executor.CurrentKnownProxies();
        return base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                // A restart while Jellyfin is still starting is not safe; it is quick anyway.
                if (!_executor.ServerStarted)
                {
                    await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken).ConfigureAwait(false);
                    continue;
                }

                var wait = await RoundAsync(stoppingToken).ConfigureAwait(false);
                await Task.Delay(wait, stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Jellyfin is stopping.
        }
    }

    /// <summary>One enforcement round; returns the time until the next.</summary>
    internal async Task<TimeSpan> RoundAsync(CancellationToken ct)
    {
        var settings = _settings.Get();
        var now = DateTimeOffset.UtcNow;
        if (settings.LoadFailed)
        {
            if (now - _lastSettingsError >= WarnEvery)
            {
                _lastSettingsError = now;
                _logger.LogError("SSO enforcement: the managed settings cannot be read; no enforcement round until they can.");
            }
            return IdleInterval;
        }

        if (settings.Enforcement is not { Enabled: true } enforcement)
        {
            if (_wasActive)
                _logger.LogWarning("SSO enforcement: switched off in the managed settings.");
            _wasActive = false;
            return IdleInterval;
        }
        if (!_wasActive)
            _logger.LogInformation("SSO enforcement: on, every {Seconds} s.", enforcement.IntervalSeconds);
        _wasActive = true;

        try
        {
            using (await _state.LockAsync(ct).ConfigureAwait(false))
            {
                var wizardDone = _executor.StartupWizardCompleted;
                if (!wizardDone && !_wizardNoticeLogged)
                {
                    _wizardNoticeLogged = true;
                    _logger.LogInformation("SSO enforcement: the startup wizard is not done; users and API keys are left alone until it is.");
                }

                var input = new EnforcementInput(
                    enforcement,
                    settings.Providers.FirstOrDefault(p => p.Enabled)?.Id,
                    PolicyState.Links(),
                    PolicyState.DisabledByPolicy(),
                    wizardDone,
                    wizardDone ? _executor.Users() : [],
                    _executor.NetworkFacts(_knownProxiesInEffect),
                    _executor.QuickConnectAvailable,
                    wizardDone ? await _executor.ApiKeysAsync().ConfigureAwait(false) : [],
                    ReadFeed(enforcement.Directory, now));
                await _executor.ApplyAsync(EnforcementPlanner.Plan(input)).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            _logger.LogError(ex, "SSO enforcement: the round failed; next try in {Seconds} s.", enforcement.IntervalSeconds);
        }

        return TimeSpan.FromSeconds(enforcement.IntervalSeconds);
    }

    /// <summary>The feed if usable; else null, with a warning at most every ten minutes.</summary>
    private DirectoryFeed? ReadFeed(DirectorySettings? directory, DateTimeOffset now)
    {
        if (directory is null)
            return null;

        string? json = null;
        string? readError = null;
        try
        {
            var info = new FileInfo(directory.Path);
            if (!info.Exists)
                readError = "the file does not exist";
            else if (info.Length > DirectoryFeed.MaxBytes)
                readError = $"the file is larger than {DirectoryFeed.MaxBytes} bytes";
            else
                json = File.ReadAllText(directory.Path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            readError = ex.Message;
        }

        var feed = DirectoryFeed.Usable(json, now, TimeSpan.FromSeconds(directory.MaxAgeSeconds), out var reason);
        if (feed is not null)
        {
            if (_feedWasUnusable)
                _logger.LogInformation("SSO enforcement: the directory feed {Path} is usable again.", directory.Path);
            _feedWasUnusable = false;
            return feed;
        }

        _feedWasUnusable = true;
        if (now - _lastFeedWarning >= WarnEvery)
        {
            _lastFeedWarning = now;
            _logger.LogWarning(
                "SSO enforcement: the directory feed {Path} is not usable ({Reason}); no directory decisions until it is.",
                directory.Path, readError ?? reason);
        }
        return null;
    }
}
