#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null || { echo "docker nao encontrado" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "docker nao esta rodando" >&2; exit 1; }

docker compose build api
docker compose up -d --wait

echo
echo "API:       http://localhost:8000"
echo "Dashboard: http://localhost:8501"
