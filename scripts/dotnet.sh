#!/usr/bin/env bash
# Run the dotnet CLI in the pinned .NET SDK container (no local SDK needed).
#   scripts/dotnet.sh build Jellyfin.Plugin.Sso -c Release
#   scripts/dotnet.sh test tests/Jellyfin.Plugin.Sso.Tests
# The NuGet cache lives in .nuget/ of the repository (gitignored).
set -euo pipefail
SDK=mcr.microsoft.com/dotnet/sdk:10.0@sha256:0d99ebf1ccad15037b5c98c9fe8979d6b8dbac23812feae2277a0b277b5c5ffa
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/.nuget"
exec docker run --rm -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 -e NUGET_PACKAGES=/src/.nuget \
  -v "$root:/src" -w /src "$SDK" dotnet "$@"
