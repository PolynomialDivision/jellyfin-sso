#!/usr/bin/env bash
# Run the dotnet CLI in the pinned .NET SDK container (no local SDK needed).
#   scripts/dotnet.sh build Jellyfin.Plugin.Sso -c Release
#   scripts/dotnet.sh test tests/Jellyfin.Plugin.Sso.Tests
# The NuGet cache lives in .nuget/ of the repository (gitignored).
set -euo pipefail
SDK=mcr.microsoft.com/dotnet/sdk:10.0@sha256:212fe4cb74627d5adf9817a4088906ae3edff1bd853bb27565d4b46731efe61e
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
mkdir -p "$root/.nuget"
exec docker run --rm -u "$(id -u):$(id -g)" \
  -e HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 -e NUGET_PACKAGES=/src/.nuget \
  -v "$root:/src" -w /src "$SDK" dotnet "$@"
