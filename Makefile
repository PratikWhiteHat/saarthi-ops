.PHONY: setup api chat doctor test lint format

setup:
	./scripts/setup_mac.sh

api:
	uv run fastapi dev src/saarthi_ai/main.py

chat:
	uv run saarthi chat

doctor:
	uv run saarthi doctor

test:
	uv run pytest

lint:
	uv run ruff check .

format:
	uv run ruff format .
