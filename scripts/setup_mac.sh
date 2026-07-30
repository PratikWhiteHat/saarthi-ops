#!/usr/bin/env bash
set -euo pipefail

MODEL="${SAARTHI_OLLAMA_MODEL:-qwen3.5:9b}"

echo "==> Checking macOS and Apple Silicon"
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This script is intended for macOS." >&2
  exit 1
fi

ARCH="$(uname -m)"
echo "Architecture: $ARCH"

if ! xcode-select -p >/dev/null 2>&1; then
  echo "Install Apple's command-line tools, then rerun this script:"
  echo "  xcode-select --install"
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "uv is missing. Install it with either:"
  echo "  brew install uv"
  echo "or"
  echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
  exit 1
fi

if ! command -v ollama >/dev/null 2>&1; then
  echo "Ollama is missing. Install the macOS application from the official Ollama website."
  exit 1
fi

[[ -f .env ]] || cp .env.example .env

echo "==> Installing Python and project dependencies"
uv sync --extra dev

echo "==> Pulling local model: $MODEL"
ollama pull "$MODEL"

echo "==> Running checks"
uv run ruff check .
uv run pytest
uv run saarthi doctor

echo
echo "Setup complete. Start the API with:"
echo "  uv run fastapi dev src/saarthi_ai/main.py"
echo "Start terminal chat with:"
echo "  uv run saarthi chat"
