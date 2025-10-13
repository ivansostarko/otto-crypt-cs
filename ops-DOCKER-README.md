# Docker usage for IvanSostarko.OttoCrypt (.NET)

Run the **.NET 8** toolchain and build the OTTO Crypt library inside a container.

## Quick start

1) Build the image and start a background container:
```bash
docker compose up -d --build
```

2) Restore, build, and pack the library:
```bash
docker compose run --rm setup
# Packages will appear under ./artifacts (override with ARTIFACTS_PATH)
```

3) Open a shell to experiment:
```bash
docker compose exec app bash
# e.g., run a one-off quickstart console app
docker compose run --rm quickstart
```

## Volumes
- `/src` → your repo (mounted from the current directory)
- `/artifacts` → where `dotnet pack` outputs `.nupkg` (overridable via `ARTIFACTS_PATH`)

## Notes
- Base image: `mcr.microsoft.com/dotnet/sdk:8.0-bookworm-slim`
- Installs `libsodium23` so **Sodium.Core** can use native crypto.
- The container defaults to idle. Use `docker compose exec app bash` for an interactive shell.
