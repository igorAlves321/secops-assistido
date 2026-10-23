RUN = docker compose run --rm dev

.PHONY: help build editor generate up down restart logs sh test lint format add

help:
	@echo "build    constroi a imagem"
	@echo "editor   copia as bibliotecas para o editor (VS Code)"
	@echo "generate gera data/logs_simulados.jsonl"
	@echo "up       sobe api e dashboard"
	@echo "down     derruba tudo"
	@echo "restart  reinicia api e dashboard"
	@echo "logs     acompanha os logs"
	@echo "sh       shell dentro do container"
	@echo "test     roda o pytest"
	@echo "lint     roda o ruff check"
	@echo "format   formata com o ruff"
	@echo "add      adiciona dependencia: make add pkg=<nome>"

build:
	docker compose build api
	./scripts/sync-editor-libs.sh

editor:
	./scripts/sync-editor-libs.sh

generate:
	$(RUN) python -m secops_core.generator

up:
	docker compose up -d

down:
	docker compose --profile dev down

restart:
	docker compose restart api dashboard

logs:
	docker compose logs -f

sh:
	$(RUN) bash

test:
	$(RUN) pytest

lint:
	$(RUN) ruff check .

format:
	$(RUN) ruff format .

add:
	@test -n "$(pkg)" || (echo "uso: make add pkg=<nome>"; exit 1)
	$(RUN) uv add --no-sync $(pkg)
	$(MAKE) build
