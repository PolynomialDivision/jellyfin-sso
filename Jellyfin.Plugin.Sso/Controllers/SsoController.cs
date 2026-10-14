using System.Net;
using IdentityModel.Client;
using Jellyfin.Plugin.Sso.Auth;
using Jellyfin.Plugin.Sso.Configuration;
using Jellyfin.Plugin.Sso.Oidc;
using Jellyfin.Plugin.Sso.Provisioning;
using MediaBrowser.Common.Extensions;
using MediaBrowser.Controller.Authentication;
using MediaBrowser.Controller.QuickConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace Jellyfin.Plugin.Sso.Controllers;

[ApiController]
[Route("sso")]
public sealed class SsoController : ControllerBase
{
    private readonly PendingStateStore _states;
    private readonly OidcClientFactory _oidc;
    private readonly ClaimsExtractor _claims;
    private readonly UserProvisioner _provisioner;
    private readonly PermissionSync _permissions;
    private readonly EphemeralSecretStore _secrets;
    private readonly QuickConnectApprovalStore _approvals;
    private readonly EffectiveConfig _settings;
    private readonly IQuickConnect _quickConnect;
    private readonly ILogger<SsoController> _logger;

    public SsoController(
        PendingStateStore states,
        OidcClientFactory oidc,
        ClaimsExtractor claims,
        UserProvisioner provisioner,
        PermissionSync permissions,
        EphemeralSecretStore secrets,
        QuickConnectApprovalStore approvals,
        EffectiveConfig settings,
        IQuickConnect quickConnect,
        ILogger<SsoController> logger)
    {
        _states = states;
        _oidc = oidc;
        _claims = claims;
        _provisioner = provisioner;
        _permissions = permissions;
        _secrets = secrets;
        _approvals = approvals;
        _settings = settings;
        _quickConnect = quickConnect;
        _logger = logger;
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Web login path: browser navigates here, gets redirected to IdP
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Stable entry point — auto-picks the single enabled provider.
    /// Used by the login button so the URL never changes.
    /// </summary>
    [HttpGet("oidc/start")]
    [AllowAnonymous]
    public Task<IActionResult> StartDefault(CancellationToken ct)
    {
        var provider = _settings.Get().Providers.FirstOrDefault(p => p.Enabled);
        return provider is null
            ? Task.FromResult<IActionResult>(NotFound("No enabled SSO provider configured."))
            : StartFlow(provider.Id, quickConnect: false, ct);
    }

    [HttpGet("oidc/start/{providerId}")]
    [AllowAnonymous]
    public Task<IActionResult> Start(string providerId, CancellationToken ct)
        => StartFlow(providerId, quickConnect: false, ct);

    // ──────────────────────────────────────────────────────────────────────────
    // Quick Connect path: log in here, then type the code the app shows
    // ──────────────────────────────────────────────────────────────────────────

    /// <summary>Quick Connect for native apps: the IdP login, then a form for the device's code.</summary>
    [HttpGet("oidc/start/qc")]
    [AllowAnonymous]
    public Task<IActionResult> StartDefaultQuickConnect([FromQuery] string? code, CancellationToken ct)
    {
        if (code is not null)
            return Task.FromResult(CodeInLink());
        var provider = _settings.Get().Providers.FirstOrDefault(p => p.Enabled);
        return provider is null
            ? Task.FromResult<IActionResult>(NotFound("No enabled SSO provider configured."))
            : StartFlow(provider.Id, quickConnect: true, ct);
    }

    [HttpGet("oidc/start/{providerId}/qc")]
    [AllowAnonymous]
    public Task<IActionResult> StartWithQuickConnect(string providerId, [FromQuery] string? code, CancellationToken ct)
        => code is not null ? Task.FromResult(CodeInLink()) : StartFlow(providerId, quickConnect: true, ct);

    /// <summary>The form of the Quick Connect page: the approval token and the typed code.</summary>
    [HttpPost("oidc/quickconnect")]
    [AllowAnonymous]
    [Consumes("application/x-www-form-urlencoded")]
    public async Task<IActionResult> ApproveQuickConnect([FromForm] string? token, [FromForm] string? code)
    {
        var userId = _approvals.Consume(token);
        if (userId is null)
            return Page("Quick Connect", "<p>This page has expired. Start again from the app.</p>", HttpStatusCode.BadRequest);
        var typed = (code ?? string.Empty).Trim();
        if (typed.Length == 0 || typed.Length > 32)
            return Page("Quick Connect", "<p>Please type the code your app shows. Start again from the app.</p>", HttpStatusCode.BadRequest);

        bool authorized;
        try
        {
            authorized = await _quickConnect.AuthorizeRequest(userId.Value, typed).ConfigureAwait(false);
        }
        // Jellyfin: ResourceNotFoundException for an unknown code, AuthenticationException for an
        // expired one or Quick Connect switched off.
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or AuthenticationException
                                       or ResourceNotFoundException)
        {
            _logger.LogInformation("SSO Quick Connect: code not accepted for user {Id}: {Message}", userId, ex.Message);
            authorized = false;
        }

        return authorized
            ? Page("Quick Connect", "<p>Login approved. You can close this tab and return to your app.</p>")
            : Page("Quick Connect", "<p>That code is unknown or has expired. Start Quick Connect in the app again.</p>",
                HttpStatusCode.BadRequest);
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Callback: IdP returns here with code+state
    // ──────────────────────────────────────────────────────────────────────────

    [HttpGet("oidc/callback/{providerId}")]
    [AllowAnonymous]
    public async Task<IActionResult> Callback(
        string providerId,
        [FromQuery] string? code,
        [FromQuery] string? state,
        [FromQuery] string? error,
        CancellationToken ct)
    {
        // The state is consumed first, also when the IdP reports an error: one state, one try.
        var pending = _states.Consume(state);

        if (!string.IsNullOrEmpty(error))
        {
            _logger.LogWarning("OIDC callback error for provider {Id}: {Error}", providerId, error);
            return Failed("The login was cancelled or refused by the identity provider.");
        }

        if (pending is null)
            return Failed("Invalid or expired login. Please try logging in again.");
        if (string.IsNullOrEmpty(code))
            return Failed("The identity provider sent no code.");

        var settings = _settings.Get();
        var provider = GetEnabledProvider(settings, providerId);
        if (provider is null || provider.Id != pending.ProviderId)
            return Failed("Provider mismatch.");

        try
        {
            var disco = await _oidc.GetDiscoveryDocumentAsync(provider, ct).ConfigureAwait(false);

            var tokens = await _oidc.ExchangeCodeAsync(
                provider, disco, code, pending.RedirectUri, pending.CodeVerifier, ct)
                .ConfigureAwait(false);

            var identity = await _claims.ExtractAsync(
                provider, disco,
                tokens.IdentityToken!, tokens.AccessToken,
                pending.Nonce, ct)
                .ConfigureAwait(false);

            // Decide before anything is created or changed: no matching group, no account.
            var access = AccessDecision.From(settings.GroupMappings, identity.Groups, settings.RequireGroupMapping);
            if (!access.Allowed)
            {
                _logger.LogWarning("SSO login refused for sub={Sub} ({Name}): no group mapping matches {Groups}",
                    identity.Sub, identity.PreferredUsername, string.Join(", ", identity.Groups));
                return Failed("Your account has no access to this Jellyfin server.");
            }

            var (userId, username) = await _provisioner.ResolveAsync(provider, identity, ct)
                .ConfigureAwait(false);

            await _permissions.SyncAsync(userId, identity, access, ct).ConfigureAwait(false);

            if (pending.QuickConnect)
                return QuickConnectForm(_approvals.Issue(userId), username);

            return CompleteWebLogin(username);
        }
        catch (Exception ex) when (ex is InvalidOperationException or SecurityTokenException or HttpRequestException
                                       or FormatException)
        {
            _logger.LogWarning(ex, "SSO login failed for provider {Id}", providerId);
            return Failed("The login could not be completed. Please try again; if it keeps failing, tell an administrator.");
        }
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Manual account linking (admin-only)
    // ──────────────────────────────────────────────────────────────────────────

    [HttpPost("admin/link")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult LinkAccount(
        [FromBody] LinkRequest req)
    {
        var config = Plugin.Instance!.Configuration;

        if (config.Links.Any(l =>
                l.ProviderId == req.ProviderId &&
                string.Equals(l.Sub, req.Sub, StringComparison.Ordinal)))
        {
            return Conflict("A link for this provider+sub already exists.");
        }

        config.Links.Add(new LinkConfig
        {
            ProviderId = req.ProviderId,
            Sub = req.Sub,
            JellyfinUserId = req.JellyfinUserId,
        });
        Plugin.Instance.SaveConfiguration();

        return Ok();
    }

    [HttpDelete("admin/link/{jellyfinUserId}")]
    [Authorize(Policy = "RequiresElevation")]
    public IActionResult UnlinkAccount(Guid jellyfinUserId)
    {
        var config = Plugin.Instance!.Configuration;
        var removed = config.Links.RemoveAll(l => l.JellyfinUserId == jellyfinUserId);
        if (removed == 0)
            return NotFound("No link found for this user.");
        Plugin.Instance.SaveConfiguration();
        return Ok();
    }

    // ──────────────────────────────────────────────────────────────────────────
    // Helpers
    // ──────────────────────────────────────────────────────────────────────────

    private async Task<IActionResult> StartFlow(string providerId, bool quickConnect, CancellationToken ct)
    {
        var settings = _settings.Get();
        var provider = GetEnabledProvider(settings, providerId);
        if (provider is null)
            return NotFound("SSO provider not found or not enabled.");
        if (quickConnect && !_quickConnect.IsEnabled)
            return BadRequest("Quick Connect is disabled on this server.");

        var redirectUri = CallbackUri(settings.PublicUrl, provider.Id);
        if (redirectUri is null)
        {
            _logger.LogError("SSO: PublicUrl is not set; the login cannot start.");
            return Failed("SSO is not configured completely (public URL missing).");
        }

        DiscoveryDocumentResponse disco;
        try
        {
            disco = await _oidc.GetDiscoveryDocumentAsync(provider, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is InvalidOperationException or HttpRequestException)
        {
            _logger.LogWarning(ex, "SSO: discovery of provider {Id} failed", provider.Id);
            return Failed("The identity provider is not reachable right now. Please try again later.");
        }

        var (state, pending) = _states.Issue(provider.Id, redirectUri, quickConnect);
        var authorizeUrl = new RequestUrl(disco.AuthorizeEndpoint
            ?? throw new InvalidOperationException("Discovery document has no authorize endpoint."))
            .CreateAuthorizeUrl(
                clientId: provider.ClientId,
                responseType: "code",
                scope: string.Join(' ', provider.Scopes),
                redirectUri: redirectUri,
                state: state,
                nonce: pending.Nonce,
                codeChallenge: PendingStateStore.CodeChallenge(pending.CodeVerifier),
                codeChallengeMethod: "S256");

        return Redirect(authorizeUrl);
    }

    /// <summary>
    /// The callback URL from the configured public URL only. Host and X-Forwarded-* headers
    /// are not used: they come from the client.
    /// </summary>
    internal static string? CallbackUri(string publicUrl, string providerId)
        => string.IsNullOrWhiteSpace(publicUrl)
            ? null
            : $"{publicUrl.TrimEnd('/')}/sso/oidc/callback/{Uri.EscapeDataString(providerId)}";

    private IActionResult CodeInLink()
        => Page("Quick Connect",
            "<p>For your safety, a Quick Connect code is never accepted from a link. "
            + "Open <code>/sso/oidc/start/qc</code> yourself, log in, and type the code your app shows.</p>",
            HttpStatusCode.BadRequest);

    private IActionResult Failed(string message)
        => Page("SSO Login", "<p>" + WebUtility.HtmlEncode(message) + "</p>", HttpStatusCode.BadRequest);

    private IActionResult QuickConnectForm(string token, string username)
        => Page("Quick Connect",
            "<p>Signed in as <strong>" + WebUtility.HtmlEncode(username) + "</strong>.</p>"
            + "<p>Type the code your app shows. Only enter a code from a device you are holding: "
            + "it will be signed in as you.</p>"
            + "<form method=\"post\" action=\"/sso/oidc/quickconnect\">"
            + "<input type=\"hidden\" name=\"token\" value=\"" + WebUtility.HtmlEncode(token) + "\"/>"
            + "<input name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" autofocus required "
            + "maxlength=\"32\" style=\"font-size:1.5em;width:8em;text-align:center\"/> "
            + "<button type=\"submit\" style=\"font-size:1.2em\">Approve</button></form>");

    private ContentResult Page(string title, string bodyHtml, HttpStatusCode status = HttpStatusCode.OK)
    {
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers["X-Frame-Options"] = "DENY";
        return new ContentResult
        {
            StatusCode = (int)status,
            ContentType = "text/html; charset=utf-8",
            Content = "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>"
                + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>"
                + "<title>" + WebUtility.HtmlEncode(title) + "</title>"
                + "<style>body{font-family:system-ui,sans-serif;max-width:32em;margin:3em auto;padding:0 1em;"
                + "background:#1c1c1c;color:#ddd}a{color:#00a4dc}</style></head><body>"
                + "<h1>" + WebUtility.HtmlEncode(title) + "</h1>" + bodyHtml + "</body></html>",
        };
    }

    private ContentResult CompleteWebLogin(string username)
    {
        var secret = _secrets.Issue(username);

        // The callback page runs standalone (outside Jellyfin's SPA) so window.ApiClient
        // is unavailable. We authenticate via raw fetch, write the result into Jellyfin's
        // localStorage credential format, then redirect into the SPA.
        var html = $$"""
            <!DOCTYPE html>
            <html><head><meta charset="utf-8"/><title>SSO Login</title>
            <style>body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#1c1c1c;color:#ddd}</style>
            </head><body>
            <p id="msg">Completing login&hellip;</p>
            <script>
            (async function() {
              const msg = document.getElementById('msg');
              try {
                const deviceId = localStorage.getItem('_deviceId2') || crypto.randomUUID();
                localStorage.setItem('_deviceId2', deviceId);

                // Authenticate as the web client with its device id. Jellyfin keys sessions
                // by client + device id, so the token belongs to the same session the web
                // app later plays on, instead of a second session that shares the device id.
                const info = await fetch('/System/Info/Public').then(function(r){ return r.json(); });
                // Rough match of the names jellyfin-web reports, so the device list stays readable.
                const ua = navigator.userAgent;
                const device = /Edg\//.test(ua) ? 'Edge Chromium'
                  : /Firefox\//.test(ua) ? 'Firefox'
                  : /Chrome\//.test(ua) ? 'Chrome'
                  : /Safari\//.test(ua) ? 'Safari'
                  : 'Web Browser';
                const authHeader = 'MediaBrowser Client="Jellyfin Web", Device="' + device + '", DeviceId="'
                  + deviceId + '", Version="' + info.Version + '"';

                const res = await fetch('/Users/AuthenticateByName', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': authHeader },
                  body: JSON.stringify({ Username: {{JsonEscape(username)}}, Pw: {{JsonEscape(secret)}} })
                });

                if (!res.ok) throw new Error('Auth failed: HTTP ' + res.status);
                const data = await res.json();

                // Write credentials into localStorage in Jellyfin's expected format.
                const credsKey = 'jellyfin_credentials';
                let creds = { Servers: [] };
                try { creds = JSON.parse(localStorage.getItem(credsKey) || '{"Servers":[]}'); } catch(e) {}

                const serverEntry = {
                  Id: data.ServerId,
                  AccessToken: data.AccessToken,
                  UserId: data.User.Id,
                  UserName: data.User.Name,
                  // jellyfin-web resolves the API address from the entry itself; without
                  // an address for the chosen mode it throws "Must supply a serverAddress".
                  ManualAddress: window.location.origin,
                  LastConnectionMode: 2,
                  DateLastAccessed: Date.now(),
                };

                const idx = creds.Servers.findIndex(function(s){ return s.Id === data.ServerId; });
                if (idx >= 0) { creds.Servers[idx] = Object.assign(creds.Servers[idx], serverEntry); }
                else { creds.Servers.push(serverEntry); }

                localStorage.setItem(credsKey, JSON.stringify(creds));

                msg.textContent = 'Login successful — redirecting…';
                window.location.replace('/web/index.html');
              } catch(e) {
                msg.textContent = 'SSO login failed: ' + e.message;
              }
            })();
            </script>
            </body></html>
            """;

        // The page carries a one-time secret: never cached, never framed, no referrer.
        Response.Headers["Cache-Control"] = "no-store";
        Response.Headers["Referrer-Policy"] = "no-referrer";
        Response.Headers["X-Frame-Options"] = "DENY";
        return Content(html, "text/html; charset=utf-8");
    }

    private static ProviderConfig? GetEnabledProvider(SsoSettings settings, string providerId)
        => settings.Providers
            .FirstOrDefault(p => p.Enabled &&
                string.Equals(p.Id, providerId, StringComparison.Ordinal));

    // System.Text.Json escapes <, >, & and quotes by default, so the value is safe inside <script>.
    private static string JsonEscape(string s)
        => System.Text.Json.JsonSerializer.Serialize(s);
}

public sealed class LinkRequest
{
    public required string ProviderId { get; set; }
    public required string Sub { get; set; }
    public required Guid JellyfinUserId { get; set; }
}
