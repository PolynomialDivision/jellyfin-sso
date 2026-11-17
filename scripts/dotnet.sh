#!/usr/bin/env bash
# Run the dotnet CLI in the pinned .NET SDK container (no local SDK needed).
#   scripts/dotnet.sh build Jellyfin.Plugin.Sso -c Release
#   scripts/dotnet.sh test tests/Jellyfin.Plugin.Sso.Tests
# The NuGet cache lives in .nuget/ of the repository (gitignored).
# DOTNET_SDK overrides the image: house-infra's update run passes the SDK that builds the plugin
# into the Jellyfin image (stacks/jellyfin images.dotnet_sdk), so the checks use that very SDK.
set -euo pipefail
SDK=${DOTNET_SDK:-mcr.microsoft.com/dotnet/sdk:10.0@sha256:fe0fd4e93bd2fbb47c883b7a6369e5c8d3db8bf01cdc5981f6ee35fbdf3ff4fb}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/.nuget"
exec docker run --rm -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 -e NUGET_PACKAGES=/src/.nuget \
  -v "$root:/src" -w /src "$SDK" dotnet "$@"
