#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

make lint
make test
make package

echo ""
echo "=== CI pipeline passed ==="
