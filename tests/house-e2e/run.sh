#!/usr/bin/env bash
# House end-to-end test: the plugin as the house runs it (settings file, Quick Connect by typed
# code, public address, the enforcement) in a real, disposable Jellyfin (local Docker, host
# network, port 8096) against the mock IdP (port 19000). Needs Docker, python3 and
# python-cryptography. house-infra's update run calls it with the Jellyfin it is about to deploy.
#   tests/house-e2e/run.sh [jellyfin image]
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
JELLYFIN_IMAGE=${1:-jellyfin/jellyfin:12.4.20261026-211555@sha256:fea863d0cd9ec445985d9c75fc6ed64e38a1d2766cf0c250a33d553f4fc1b771}
run="$root/tests/runs/house-e2e"
secret=e2e-client-secret
container=jellyfin-sso-house-e2e

# The house image copies the DLLs scripts/plugin-files.txt names; upstream's packaging names
# them in scripts/package.sh. A dependency upstream adds must not go missing in the image.
packaged=$(sed -n '/^EXTRA_DLLS=(/,/^)/p' "$root/scripts/package.sh" | grep -oE '[A-Za-z.]+\.dll')
if ! diff <(printf 'Jellyfin.Plugin.Sso.dll\n%s\n' "$packaged") "$root/scripts/plugin-files.txt"; then
  echo "scripts/plugin-files.txt differs from the DLLs scripts/package.sh packages (above)" >&2
  exit 1
fi

# shellcheck disable=SC2329  # called by the trap below
cleanup() {
  docker logs "$container" >"$run/jellyfin.log" 2>&1 || true
  docker rm -f "$container" >/dev/null 2>&1 || true
  [ -n "${idp_pid:-}" ] && kill "$idp_pid" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$run" && mkdir -p "$run/config/plugins/SSO Authentication_0.0.0.0" "$run/cache" "$run/publish" \
  "$run/settings" "$run/directory"
"$root/scripts/dotnet.sh" publish Jellyfin.Plugin.Sso -c Release -o /src/tests/runs/house-e2e/publish >/dev/null
while read -r dll; do
  cp "$run/publish/$dll" "$run/config/plugins/SSO Authentication_0.0.0.0/"
done < "$root/scripts/plugin-files.txt"

# Directories, not files, are mounted: the test replaces the settings file and the directory
# feed atomically (rename), as configuration management and the directory writer do.
cat > "$run/settings/sso.json" <<'EOF'
{
  "PublicAddress": "http://127.0.0.1:8096",
  "TypeQuickConnectCode": true,
  "RequireMappedGroup": true,
  "Providers": [{"Id": "authentik", "Name": "Authentik", "Enabled": true,
                 "Authority": "http://127.0.0.1:19000/application/o/jellyfin/",
                 "ClientId": "jellyfin", "ClientType": "Confidential",
                 "ConfidentialSecretRef": "env:SSO_CLIENT_SECRET",
                 "Scopes": ["openid", "profile", "email", "groups"], "CreateAccounts": true}],
  "GroupMappings": [{"Group": "residents", "AllLibraries": true},
                    {"Group": "it-admins", "IsAdministrator": true}],
  "Enforcement": {
    "Enabled": true,
    "IntervalSeconds": 3,
    "Network": {"KnownProxies": ["10.251.8.2"], "LocalNetworkSubnets": ["10.0.10.0/24", "10.0.0.0/24"]},
    "BreakGlass": {"Users": ["jellyfin-admin"], "Enabled": true},
    "AllowedApiKeyNames": ["house-monitoring"],
    "Directory": {"Path": "/run/house-directory/media.json", "MaxAgeSeconds": 1800}
  }
}
EOF

python3 "$root/tests/house-e2e/mock_idp.py" --port 19000 --client-id jellyfin --client-secret "$secret" \
  --redirect-uri http://127.0.0.1:8096/sso/oidc/callback/authentik &
idp_pid=$!

docker run -d --name "$container" --network host -u "$(id -u):$(id -g)" \
  -e JELLYFIN_SSO_SETTINGS_FILE=/etc/jellyfin-sso/sso.json -e SSO_CLIENT_SECRET="$secret" \
  -v "$run/settings:/etc/jellyfin-sso:ro" -v "$run/directory:/run/house-directory:ro" \
  -v "$run/config:/config" -v "$run/cache:/cache" \
  "$JELLYFIN_IMAGE" >/dev/null
healthy() {
  for _ in $(seq 90); do
    [ "$(curl -s http://127.0.0.1:8096/health || true)" = Healthy ] && return 0
    sleep 2
  done
}
healthy
# The enforcement sets KnownProxies at the first start and restarts Jellyfin once for them
# (Jellyfin reads them only at startup). Wait for the second start; e2e.py checks it was one.
for _ in $(seq 90); do
  [ "$(docker logs "$container" 2>&1 | grep -c 'Startup complete')" -ge 2 ] && break
  sleep 2
done
healthy

status=0
E2E_SETTINGS="$run/settings/sso.json" E2E_FEED="$run/directory/media.json" E2E_CONTAINER="$container" \
  python3 "$root/tests/house-e2e/e2e.py" || status=$?
if [ "$status" -ne 0 ]; then
  echo "--- Jellyfin log (SSO lines)"
  docker logs "$container" 2>&1 | grep -iE "sso|Jellyfin.Plugin.Sso|error" | tail -40
fi
exit "$status"
