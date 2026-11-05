PYTHON ?= python3

.PHONY: install test lint format generate analyze serve docker-build ci

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff format .
	$(PYTHON) -m ruff check --fix .

ci: lint test

generate:
	socdetect generate --out data/sample --seed 42

analyze: generate
	socdetect analyze data/sample --out reports --seed 42

serve:
	socdetect serve --host 127.0.0.1 --port 8000

docker-build:
	docker build -t socdetect:local .
