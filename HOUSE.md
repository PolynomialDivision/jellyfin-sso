# The house fork

Fork of [be-nj/jellyfin-sso](https://github.com/be-nj/jellyfin-sso), used by house-infra
(`stacks/jellyfin`). Branch `house`; `upstream` is the original. Since 2026-11-17 the fork is
upstream's code (1.12.22 then) plus a thin layer, instead of the rewrite of 1.12.0 it was from
2026-10-14: upstream had meanwhile fixed most of what the first fork fixed, with tests, reviews
and the OpenID conformance suite, and fixed more besides.

## What is on top of upstream

Upstream took four of the five changes the house proposed (#295; AllLibraries, PublicAddress,
the refused and the typed Quick Connect code; [docs/house-upstream-proposals.md](docs/house-upstream-proposals.md))
and declined the settings file. Since 2026-11-18 `house` is `upstream/main` plus the commits
below, no branches merged in.

**House only:**

- **Settings file** (`Configuration/SettingsFile*.cs`, `JELLYFIN_SSO_SETTINGS_FILE`): settings
  from a JSON file, applied at startup through upstream's `ConfigurationRules`, shown read-only
  on the page. house-infra writes providers, mappings and the enforcement from `identity.yml`.
  Declined upstream.
- **Enforcement** (`Enforcement/`, `Configuration/EnforcementSettings.cs`, the `Enforcement`
  and `DisabledByPolicy` settings, `LinkConfig.LastLoginUtc`, the login hook in
  `SsoCallbackController`): keeps the settings file's `Enforcement` section true, at start and
  every `IntervalSeconds`. The directory feed (written by house-infra's `jellyfin-directory`)
  says who may use Jellyfin and who is admin: everyone else is disabled and every token and
  login of theirs revoked (upstream's `SessionRevoker`), the admin flag follows the feed; a
  login newer than the feed wins until the next feed; a user an admin disabled by hand stays
  disabled. Also: linked accounts log in through SSO only, accounts neither linked nor
  break-glass are disabled, the break-glass account only when switched on and only from the
  local networks, API keys only with an allowed name, Jellyfin's Known Proxies and local
  networks as set (one restart for the proxies), Quick Connect on. Invalid section or a
  settings file that was not applied: no round at all.
- `scripts/dotnet.sh` (the SDK in Docker, `DOTNET_SDK` from house-infra) and
  `scripts/plugin-files.txt` (the DLLs house-infra's image copies; the house e2e test checks it
  against upstream's `scripts/package.sh`).
- `tests/house-e2e/`: the plugin as the house runs it, in a real Jellyfin against a mock
  provider: settings file, web login, Quick Connect by typed code, refusals, forged headers,
  and the whole enforcement (feed, stale feed, disable by hand, API keys, break-glass,
  network settings).

## Checks

```
scripts/dotnet.sh test tests/Jellyfin.Plugin.Sso.Tests   # the unit tests, house's included
tests/house-e2e/run.sh [jellyfin image]     # the house's end-to-end test
make e2e                                    # upstream's end-to-end suite (Playwright; long)
```

`make test` runs as root in its container and leaves root-owned build output behind; then
`scripts/dotnet.sh` and the house e2e test cannot write there.

## Updates

- **Packages and new Jellyfin releases:** house-infra's update run (its docs/UPDATES.md, "The
  Jellyfin SSO plugin follows Jellyfin"): package versions in the csproj, the unit tests and
  `tests/house-e2e/run.sh` against the Jellyfin it deploys, commit on `house`, push, pin.
  Upstream builds against the first release of a major (`Jellyfin.Controller` 12.0.0) and tests
  every 12.x, so a new 12.x needs no change here; a new major (a new .NET) is done by hand.
- **Upstream's changes:** the update report counts the commits of `upstream/main` not merged.
  `git fetch upstream && git merge upstream/main` on `house` (conflicts, if any, are where
  the settings file or the enforcement meet upstream: `ConfigurationRules`, `AdminController`,
  `Plugin.cs`, `SsoCallbackController`), `make test`, `tests/house-e2e/run.sh`,
  push, then the pin in house-infra. Read upstream's changes to the login path first.

## Release into the house

house-infra compiles the plugin on the host from this repository at a pinned commit
(`stacks/jellyfin/stack.yml` → `build_sources.jellyfin_sso`), with the settings file it
renders (`stacks/jellyfin/files/sso.json.j2`).
