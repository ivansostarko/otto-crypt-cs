# syntax=docker/dockerfile:1.6
# Dev container for building and experimenting with the OTTO Crypt .NET library
FROM mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim

# Useful tools + tini for clean PID1 + libsodium for Sodium.Core native runtime
RUN apt-get update && apt-get install -y --no-install-recommends \    bash ca-certificates tini git \    libsodium23 \    && rm -rf /var/lib/apt/lists/*

ENV DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1

# Use tini as entrypoint
ENTRYPOINT ["/usr/bin/tini","--"]

# Working directory for interactive usage
WORKDIR /work

# Keep the container running by default; exec in and run dotnet commands
CMD ["bash","-lc","tail -f /dev/null"]
