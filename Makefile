.DEFAULT_GOAL := help
VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
TAILWIND ?= tailwindcss
CADDY ?= caddy

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

venv: ## Create the virtualenv
	python3 -m venv $(VENV)

install: venv ## Install runtime + dev dependencies (editable)
	$(PIP) install -e ".[dev]" --quiet

css: ## Compile static/src/main.css -> static/app.css (needs tailwindcss CLI; override with TAILWIND=path)
	cd craftpass && $(TAILWIND) -i static/src/main.css -o static/app.css --minify

test: ## Run the test suite
	$(PY) -m pytest

lint: ## Ruff lint + format check
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

fmt: ## Auto-fix lint findings and reformat
	$(PY) -m ruff check --fix .
	$(PY) -m ruff format .

dev: ## Run a dev server on http://127.0.0.1:8000 with auto-reload
	$(PY) -m uvicorn craftpass.main:app --host 127.0.0.1 --port 8000 --reload

image: ## Build the container image (run on the ARM64 host for a native build)
	docker build -t labcraft/craftpass:latest .

validate-caddy: ## Validate deploy/Caddyfile (override binary with CADDY=path/to/caddy)
	$(CADDY) validate --config deploy/Caddyfile --adapter caddyfile

.PHONY: help venv install css test lint fmt dev image validate-caddy
