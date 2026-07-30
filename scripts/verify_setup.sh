#!/usr/bin/env bash
set -euo pipefail

printf '%-18s %s\n' "macOS:" "$(sw_vers -productVersion 2>/dev/null || echo unavailable)"
printf '%-18s %s\n' "Architecture:" "$(uname -m)"
printf '%-18s %s\n' "Memory bytes:" "$(sysctl -n hw.memsize 2>/dev/null || echo unavailable)"
printf '%-18s %s\n' "uv:" "$(uv --version 2>/dev/null || echo missing)"
printf '%-18s %s\n' "Ollama:" "$(ollama --version 2>/dev/null || echo missing)"
printf '%-18s %s\n' "Git:" "$(git --version 2>/dev/null || echo missing)"
printf '%-18s %s\n' "Model:" "${SAARTHI_OLLAMA_MODEL:-qwen3.5:9b}"
