#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p .editor-packages
docker compose run --rm --no-deps -T dev sh <<'C'
src=$(python -c "import sysconfig; print(sysconfig.get_paths()['purelib'])")
find /app/.editor-packages -mindepth 1 -delete
cp -a "$src"/. /app/.editor-packages/
C
