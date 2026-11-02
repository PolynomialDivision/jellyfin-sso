#!/usr/bin/env bash
# End-to-end test: the plugin in a real, disposable Jellyfin (local Docker, host network,
# port 8096) against the mock IdP (port 19000). Needs Docker, python3 and python-cryptography.
#   tests/e2e/run.sh [jellyfin image]
# The image defaults to the one in JELLYFIN_IMAGE below; pass another to test an update.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
JELLYFIN_IMAGE=${1:-jellyfin/jellyfin:12.2.20261005-225228@sha256:357724bf0ae27a672c7cbaa899db2d9abeb13dbd8657ccce750258a4c059d037}
run="$root/tests/runs/e2e"
secret=e2e-client-secret

# shellcheck disable=SC2329  # called by the trap below
cleanup() {
  docker logs jellyfin-sso-e2e >"$run/jellyfin.log" 2>&1 || true
  docker rm -f jellyfin-sso-e2e >/dev/null 2>&1 || true
  [ -n "${idp_pid:-}" ] && kill "$idp_pid" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf "$run" && mkdir -p "$run/config/plugins/SSO Authentication_0.0.0.0" "$run/cache" "$run/publish" \
  "$run/managed" "$run/directory"
"$root/scripts/dotnet.sh" publish Jellyfin.Plugin.Sso -c Release -o /src/tests/runs/e2e/publish >/dev/null
while read -r dll; do
  cp "$run/publish/$dll" "$run/config/plugins/SSO Authentication_0.0.0.0/"
done < "$root/scripts/plugin-files.txt"

# Directories, not files, are mounted: the test replaces the managed file and the directory
# feed atomically (rename), as configuration management and the directory writer do.
cat > "$run/managed/sso.json" <<'EOF'
{
  "PublicUrl": "http://127.0.0.1:8096",
  "LoginButtonText": "Log in with the house account",
  "Providers": [{"Id": "authentik", "Name": "Authentik", "Enabled": true,
                 "Authority": "http://127.0.0.1:19000/application/o/jellyfin/",
                 "ClientId": "jellyfin", "ClientType": "Confidential",
                 "ConfidentialSecretRef": "env:SSO_CLIENT_SECRET"}],
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

python3 "$root/tests/e2e/mock_idp.py" --port 19000 --client-id jellyfin --client-secret "$secret" \
  --redirect-uri http://127.0.0.1:8096/sso/oidc/callback/authentik &
idp_pid=$!

docker run -d --name jellyfin-sso-e2e --network host -u "$(id -u):$(id -g)" \
  -e SSO_MANAGED_CONFIG=/etc/jellyfin-sso/sso.json -e SSO_CLIENT_SECRET="$secret" \
  -v "$run/managed:/etc/jellyfin-sso:ro" -v "$run/directory:/run/house-directory:ro" \
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
  [ "$(docker logs jellyfin-sso-e2e 2>&1 | grep -c 'Startup complete')" -ge 2 ] && break
  sleep 2
done
healthy

status=0
E2E_MANAGED="$run/managed/sso.json" E2E_FEED="$run/directory/media.json" E2E_CONTAINER=jellyfin-sso-e2e \
  python3 "$root/tests/e2e/e2e.py" || status=$?
if [ "$status" -ne 0 ]; then
  echo "--- Jellyfin log (SSO lines)"
  docker logs jellyfin-sso-e2e 2>&1 | grep -iE "sso|Jellyfin.Plugin.Sso|error" | tail -40
fi
exit "$status"
