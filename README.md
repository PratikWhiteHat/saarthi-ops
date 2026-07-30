# Saarthi AI Starter

Phase 0 foundation for a local security-specialized AI assistant on Apple Silicon.

## What is included
- FastAPI backend
- Ollama integration
- Terminal chat CLI
- Environment-based configuration
- Health checks
- Initial tests and lint configuration
- Master `SKILL.md`

This starter intentionally does **not** execute security tools. Tool execution will be added later
with authorization checks, allowlists, sandboxing, approval prompts, timeouts, and audit logs.

## Prerequisites
- Apple Silicon Mac with macOS Sonoma 14 or newer
- 24 GB unified memory is suitable for the default 9B quantized model
- At least 20 GB free disk space recommended for the initial environment and model
- Apple Command Line Tools
- Git
- `uv`
- Ollama

## 1. Verify the Mac

```bash
sw_vers
uname -m
sysctl -n hw.memsize
xcode-select -p || xcode-select --install
```

Expected architecture: `arm64`.

## 2. Install uv

Using Homebrew:

```bash
brew install uv
```

Or use Astral's installer:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Restart Terminal if `uv` is not immediately found.

## 3. Install and start Ollama

Install the official Ollama macOS application, move it to Applications, and open it once.
Then verify:

```bash
ollama --version
curl http://localhost:11434/api/tags
```

## 4. Configure and initialize this project

```bash
cd saarthi-ai-starter
cp .env.example .env
./scripts/setup_mac.sh
```

The default model is:

```text
qwen3.5:9b
```

To use another model, edit `.env` before running setup.

## 5. Run the API

```bash
uv run fastapi dev src/saarthi_ai/main.py
```

Open the generated API documentation at `http://127.0.0.1:8000/docs`.

Health checks:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/health/model
```

Chat request:

```bash
curl -s http://127.0.0.1:8000/v1/chat \
  -H 'Content-Type: application/json' \
  -d '{
    "messages": [
      {
        "role": "user",
        "content": "Explain the difference between an observation and an inference in a security report."
      }
    ],
    "think": false
  }'
```

## 6. Run terminal chat

```bash
uv run saarthi chat
```

Run setup diagnostics:

```bash
uv run saarthi doctor
```

## 7. Development checks

```bash
uv run ruff check .
uv run ruff format .
uv run pytest
```

## Next milestone
Phase 1 will define the dataset schema, provenance records, licenses, sanitization rules, and the
first evaluation set. We should create the evaluation set before fine-tuning so improvements can be
measured honestly.
