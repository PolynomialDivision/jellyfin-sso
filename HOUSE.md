# The house fork

Fork of [be-nj/jellyfin-sso](https://github.com/be-nj/jellyfin-sso) 1.12.0 (MIT), used by
house-infra (`stacks/jellyfin`). Upstream is a young one-person project (first commit
2026-09-17, no tests); everything in the login path was reviewed line by line on 2026-10-14
before this fork was deployed. Branch `house`; `upstream` is the original.

## What changed, and why

Security (found in the review):

1. **Quick Connect phishing.** Upstream approved the Quick Connect code from the start link
   (`/sso/oidc/start/qc?code=…`) right after the IdP login. Anyone could send a link with
   the code of *their* TV; one click by a logged-in person signed the stranger's TV in as
   them. Now a code in a link is refused; after the login the person types the code of the
   device they hold (like Jellyfin's own Quick Connect page). The form carries a random,
   single-use, five-minute token bound to the user (`QuickConnectApprovalStore`).
2. **Callback URL from client headers.** Upstream built the redirect URI from `Host` and
   `X-Forwarded-*`. Now it comes only from the configured `PublicUrl`.
3. **Policy reset on every login.** Upstream replaced the whole user policy at each login
   with a fresh one: a user an admin had disabled in Jellyfin was enabled again by their next
   SSO login, and every other restriction was lost. Now only admin flag and library access
   are set; the rest of the policy is read and kept.
4. **Login without any mapped group** created an account with no library. Now refused
   before anything is created (`RequireGroupMapping`, default on).
5. **Discovery issuer not checked** (strict validation is off for Authentik's shared
   endpoints) and cached forever (a rotated IdP key broke logins until a restart). Now the
   issuer must equal the configured authority, the document is cached for an hour, and an
   unknown signing key triggers one fresh discovery.
6. Hardening: ID tokens must carry `nonce`, `sub`, `preferred_username`, an expiry and a
   signature; userinfo groups only with a matching `sub`; error pages without IdP or
   exception text; `no-store`/`no-referrer`/`DENY` on the pages with one-time values; the
   login button text HTML-encoded; an invalid `ConfidentialSecretRef` is never echoed.

Function:

- **Managed settings** (`SSO_MANAGED_CONFIG` = a JSON file): public URL, button text,
  providers and group mappings from configuration management; the dashboard shows them
  read-only. Links and seen groups stay in the plugin's XML (state). A broken file turns SSO
  off (fail closed).
- `AllLibraries` per group mapping (no library GUIDs needed).
- The login button is actually set at startup (upstream relied on a service provider
  property nothing ever assigned).
- A local account an admin links by hand keeps its password login (upstream switched it to
  SSO-only at the next login). With the enforcement on, a linked account is SSO-only (below).
- JIT creation under a lock (two simultaneous first logins: one user).
- Built against Jellyfin 12.2.0; Microsoft.IdentityModel 8.23.0.

## Enforcement (managed "Enforcement" section)

Why: group changes in the IdP used to reach Jellyfin only at the person's next login. Someone
who moved out kept their tokens, their admin flag, their account; a local account or an API
key created in the dashboard stayed unnoticed. Now configuration management states what must
be true and a hosted service (`Enforcement/EnforcementService`) keeps it true: one round as
soon as Jellyfin has started, then every `IntervalSeconds`. Without the section nothing new
happens; a managed file that cannot be read means no round at all (logged as an error).

```json
"Enforcement": {
  "Enabled": true,
  "IntervalSeconds": 60,
  "Network": { "KnownProxies": ["10.251.8.2"], "LocalNetworkSubnets": ["10.0.10.0/24", "10.0.0.0/24"] },
  "BreakGlass": { "Users": ["jellyfin-admin"], "Enabled": false },
  "AllowedApiKeyNames": [],
  "Directory": { "Path": "/run/house-directory/media.json", "MaxAgeSeconds": 1800 }
}
```

Invalid values (an interval outside 1–86400 s, a proxy that is not an IP address or network,
a relative feed path …) make the whole managed file invalid: SSO off, no enforcement.
`Network` and `Directory` are optional (absent: not enforced); `AllowedApiKeyNames` absent
means none is allowed.

The directory feed is written by another container and only read here:

```json
{"version": 1, "generated_at": "2026-11-02T12:00:00Z", "allowed": ["<sub>"], "admins": ["<sub>"]}
```

`allowed`: the OIDC subjects (`LinkConfig.Sub`) of everyone entitled to Jellyfin; `admins`
(within `allowed`): who must be a Jellyfin administrator. The feed is used only if it parses,
has version 1, a `generated_at` with `Z` or an offset that is at most `MaxAgeSeconds` old and
at most 300 s ahead, and a non-empty `allowed`. Otherwise every directory decision is skipped
for the round (a warning at most every ten minutes) and the local rules still run.

Rules per round (decisions: `EnforcementPlanner`, pure and unit-tested; Jellyfin calls:
`EnforcementExecutor`):

1. **Network**: `KnownProxies` and `LocalNetworkSubnets` exactly as configured (order does not
   matter), remote access on. Jellyfin reads KnownProxies only at startup, so a change restarts
   Jellyfin once (logged). The restart is in-process; a marker in the AppDomain (it survives
   the plugin being loaded again) stops a second restart for the same value, and the saved
   `network.xml` is read back first: if it still differs, an error instead of a restart.
   Changed in the dashboard while running, the value is set back without a restart (the
   running server still uses the managed one).
2. **Quick Connect** on (native apps log in through it).
3. **API keys** whose name is not in `AllowedApiKeyNames` (case-insensitive) are deleted;
   the log names the key, never the token.
4. **Users** (only after Jellyfin's startup wizard is done):
   - *Break-glass* (by name; must not be linked): always administrator, password login,
     no remote access (so it logs in only from `LocalNetworkSubnets`). `Enabled: false`:
     disabled, every token revoked. It stays administrator while disabled, so Jellyfin always
     has one. `Enabled: true` enables it every round, also after a Jellyfin lockout for failed
     logins (`LoginAttemptsBeforeLockout`, off by default): accepted, because the account is
     reachable only from the admin networks.
   - *Linked* (a link of the enabled provider): SSO login only, intended (a password would
     outlive the person's removal; with the enforcement on, this replaces the earlier "a
     linked local account keeps its password").
     With a usable feed, unless the user logged in via SSO after `generated_at` (fresher
     evidence; wait for the next feed): not in `allowed` → no admin, disabled, all tokens
     revoked and sessions ended; in `allowed` → admin flag = in `admins`, and enabled again if
     the enforcement had disabled it.
   - *Every other account*: "unmanaged account", disabled and logged out. Linking it in the
     dashboard brings it under the linked rule.
   - The enforcement remembers whom it disabled (`DisabledByPolicy` in the plugin XML). Only
     those are enabled again (by the feed or by a fresh SSO login); an account an admin
     disabled by hand stays disabled.
   - Jellyfin's API refuses to disable an administrator or remove the last one, its
     UserManager does not: the admin flag goes in the same write as the disable, and if a
     round would leave no administrator at all, one demoted account (preferably a disabled
     one) keeps the flag, with an error in the log. Failures are logged per user; the next
     user is still done.
5. **SSO login**: the callback records `LastLoginUtc` on the link (web and Quick Connect),
   and enables a user that is in `DisabledByPolicy` (the IdP just let the person in). Both
   happen under the same lock as a round, so a round never acts on a login it has not seen.

Links, seen groups and `DisabledByPolicy` are changed, saved and read only inside one lock
(`Configuration/PluginStateStore`): saving serializes the whole plugin XML, which must never
meet a list another thread (a login, the dashboard, a round) is changing.

Tokens are revoked with `ISessionManager.RevokeUserTokens` (no token spared: Jellyfin deletes
each device/token and ends its sessions), then any remaining session of the user is ended.

## Build and test

No local .NET needed (`scripts/dotnet.sh` runs the pinned SDK container):

```sh
scripts/dotnet.sh test tests/Jellyfin.Plugin.Sso.Tests     # unit tests (98)
tests/e2e/run.sh [jellyfin image]                          # real Jellyfin + mock IdP (60 checks)
```

The e2e test starts a disposable Jellyfin on the host network (port 8096) with the plugin,
runs the first-run wizard through the API and plays the browser against
`tests/e2e/mock_idp.py` (shaped like Authentik): web login, single-use secret, Quick Connect
by typed code only, refusals (no group, name collision, replayed state, disabled user),
forged forwarding headers, managed settings. Then the enforcement with a 3 s interval and a
feed file the test writes: removal from and return to the feed, stale and future feeds, a
fresh login against an older feed, a disable by hand, admin flag from the feed, unmanaged
account, API keys, break-glass off and on, network settings with exactly one restart. The
full Jellyfin log of the run is kept in `tests/runs/e2e/jellyfin.log`.

## Release into the house

house-infra compiles the plugin on the host from this repository at a pinned commit
(`stacks/jellyfin/stack.yml` → `build_sources.jellyfin_sso`). A new Jellyfin version:

1. `Jellyfin.Controller` and `Jellyfin.Model` in the csproj to the new server version.
2. Unit tests, then `tests/e2e/run.sh <new jellyfin image@digest>`.
3. Commit, push; in house-infra the new `jellyfin_base` and the new commit together.

Upstream changes: `git fetch upstream`, read the diff (it is the login path), merge, test.
