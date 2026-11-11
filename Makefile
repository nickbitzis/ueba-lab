PORT ?= 8892
SCALE ?= 1.0
SEED ?= 7
MAX_DAYS ?= 3
MAX_BENIGN ?= 1

.PHONY: install test lint eval gate run docker-build screenshot clean

install:
	uv sync --python 3.12

test:
	uv run pytest -q

lint:
	uvx ruff check .

eval:  ## all four configurations against the planted scenarios; writes docs/evaluation.*
	uv run uebalab eval --seed $(SEED) --scale $(SCALE) --out docs/evaluation.json --markdown docs/evaluation.md

gate:  ## what CI runs: fail unless every scenario is a case within MAX_DAYS and benign cases <= MAX_BENIGN
	uv run uebalab eval --seed $(SEED) --scale $(SCALE) --gate --max-days $(MAX_DAYS) --max-benign $(MAX_BENIGN)

run:
	UEBA_SCALE=$(SCALE) UEBA_SEED=$(SEED) uv run uebalab serve --port $(PORT)

docker-build:
	docker build -t ueba-lab .

screenshot:  ## needs the server running on $(PORT) and Google Chrome
	uv run python scripts/screenshot.py --port $(PORT)

clean:
	rm -rf .pytest_cache .ruff_cache data
