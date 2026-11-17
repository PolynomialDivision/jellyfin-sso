#!/usr/bin/env bash
# Run the dotnet CLI in the .NET SDK container global.json names (no local SDK needed).
#   scripts/dotnet.sh build Jellyfin.Plugin.Sso -c Release
#   scripts/dotnet.sh test tests/Jellyfin.Plugin.Sso.Tests
# Runs as your user, unlike `make test`. The NuGet cache lives in .nuget/ (gitignored).
# DOTNET_SDK overrides the image: house-infra's update run passes the image (with its digest)
# that builds the plugin into the Jellyfin image, the SDK of global.json too.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
version=$(sed -n 's/.*"version": *"\([0-9.]*\)".*/\1/p' "$root/global.json")
SDK=${DOTNET_SDK:-mcr.microsoft.com/dotnet/sdk:$version}
mkdir -p "$root/.nuget"
exec docker run --rm -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 -e NUGET_PACKAGES=/src/.nuget \
  -v "$root:/src" -w /src "$SDK" dotnet "$@"
