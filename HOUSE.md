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
  SSO-only at the next login).
- JIT creation under a lock (two simultaneous first logins: one user).
- Built against Jellyfin 12.2.0; Microsoft.IdentityModel 8.23.0.

## Build and test

No local .NET needed (`scripts/dotnet.sh` runs the pinned SDK container):

```sh
scripts/dotnet.sh test tests/Jellyfin.Plugin.Sso.Tests     # unit tests (33)
tests/e2e/run.sh [jellyfin image]                          # real Jellyfin + mock IdP (30 checks)
```

The e2e test starts a disposable Jellyfin on the host network (port 8096) with the plugin,
runs the first-run wizard through the API and plays the browser against
`tests/e2e/mock_idp.py` (shaped like Authentik): web login, single-use secret, Quick Connect
by typed code only, refusals (no group, name collision, replayed state, disabled user),
forged forwarding headers, managed settings.

## Release into the house

house-infra compiles the plugin on the host from this repository at a pinned commit
(`stacks/jellyfin/stack.yml` → `build_sources.jellyfin_sso`). A new Jellyfin version:

1. `Jellyfin.Controller` and `Jellyfin.Model` in the csproj to the new server version.
2. Unit tests, then `tests/e2e/run.sh <new jellyfin image@digest>`.
3. Commit, push; in house-infra the new `jellyfin_base` and the new commit together.

Upstream changes: `git fetch upstream`, read the diff (it is the login path), merge, test.
