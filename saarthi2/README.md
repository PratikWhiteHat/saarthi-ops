# Saarthi 2.0

A **local-first, AI-native security workflow orchestration engine** — Osmedeus's
shape (declarative YAML workflows + an agentic AI loop), rebuilt in Python around
a local Ollama model.

> Status: **v1 foundation.** Runnable workflow engine with `tool`, `http`, and
> agentic `llm` steps; `foreach`/`when`/`register`; SQLite + evidence + audit;
> CLI. Distributed runners, web UI, and more step types are future work.

## Design

```
YAML workflow ─▶ loader ─▶ runner ─▶ step dispatcher ─┬─ tool  (run any command)
                                                      ├─ http  (request)
                                                      └─ llm   (agentic Ollama loop:
                                                                plan → call tools → observe → repeat)
                    every action ─▶ policy gate ─▶ audit log (+ optional enforcement)
                    results ─▶ SQLite + sha256 evidence store
```

- **Steps** are pluggable — register a handler in `steps/__init__.py`.
- **The `llm` step** is the "AI runs tools repeatedly" loop. It calls tools from
  `tools.py` (`run_command`, `http_get`, …) through the same injected path as
  declarative steps.
- **Policy is a seam.** The default `PermissiveGate` runs everything and only
  *audits* (Osmedeus-style, workflow-author-trusted). Swap in `ScopedGate` to
  enforce a host allowlist + destructive-token denylist with zero step changes.

## Safety note

This engine trusts whoever authors the workflow (like Ansible/Make). The `llm`
step reads target output, so a hostile target could attempt prompt injection —
keep that in mind before granting the agent the `run_command` tool against
untrusted targets. Every command is written to `~/.saarthi2/audit.jsonl`.

## Usage

```bash
# from the saarthi2/ directory
uv run saarthi2 workflow list
uv run saarthi2 workflow lint recon
uv run saarthi2 run recon -t example.com
uv run saarthi2 run ./workflows/recon.yaml -t example.com --var depth=2
```

Config via env: `SAARTHI2_OLLAMA_HOST`, `SAARTHI2_OLLAMA_MODEL`,
`SAARTHI2_WORK_DIR`, `SAARTHI2_WORKFLOWS_DIR`.

## Workflow format

```yaml
name: recon
vars: { target: example.com }
steps:
  - id: subs
    uses: tool
    with: { cmd: "subfinder -d {{ target }} -silent" }
    register: subs
  - id: probe
    uses: tool
    loop: "{{ steps.subs.output }}"     # once per line, bound to {{ item }}
    when: "{{ steps.subs.output }}"     # skip if empty
    with: { cmd: "httpx -u {{ item }} -silent" }
  - id: triage
    uses: llm
    with:
      prompt: "Triage these hosts:\n{{ steps.probe.output }}"
      tools: []            # omit for all tools; [] = summarize only
      max_iterations: 4
```

## Layout

```
src/saarthi2/
  engine/   models · loader · context(interpolation) · runner
  steps/    tool · http · llm
  ai/       ollama(client) · agent(tool-calling loop)
  tools.py  AI tool registry (run_command, http_get)
  policy.py Gate (permissive default + scoped opt-in)
  state.py  SQLite + evidence + audit
  runtime.py real deps (subprocess/httpx/ollama)
  cli.py    typer CLI
workflows/  recon.yaml
tests/
```
