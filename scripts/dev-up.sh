#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Run: sudo bash scripts/install-docker.sh" >&2
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    echo "Docker Compose plugin is not installed." >&2
    exit 1
fi

if [[ ! -f .env ]]; then
    echo "Creating .env from .env.example. Please review and change the password."
    cp .env.example .env
fi

# Make all app files world-readable so the container's splunk user can load the app.
# Directories need the execute bit. .env is kept as-is because it contains secrets.
# certs/ should contain only public CA certificates; they must be readable by Splunk.
mkdir -p local metadata
touch local/.gitkeep metadata/.gitkeep 2>/dev/null || true
find . -type d -not -path './.git/*' -exec chmod a+rx {} +
find . -type f -not -path './.git/*' -not -name '.env' -exec chmod a+r {} +

docker compose up -d

echo ""
echo "Splunk is starting. This can take 60-90 seconds."
echo "  Web UI:  http://localhost:8000"
echo "  REST:    https://localhost:8089"
echo "  HEC:     https://localhost:8088"
echo ""
echo "Run 'make logs' to follow startup, then 'make fix-perms' and 'make status'."
