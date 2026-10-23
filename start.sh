#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null || { echo "docker nao encontrado" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker nao esta rodando" >&2; exit 1; }

docker compose build api
./scripts/sync-editor-libs.sh || echo "aviso: editor nao preparado" >&2
docker compose run --rm --no-deps -T dev python -m secops_core.generator
docker compose up -d --wait

echo
echo "API:       http://localhost:${API_PORT:-8080}"
echo "Dashboard: http://localhost:${DASHBOARD_PORT:-8501}"
