# Saarthi 2.0

A **local-first, AI-native security workflow orchestration engine** — Osmedeus's
shape (declarative YAML workflows + an agentic AI loop), rebuilt in Python around
a local Ollama model.

> Status: **v0.5.** Workflow engine (`tool`/`http`/`llm`/`function`/`parallel`/
> `notify`/`subagent` steps, `foreach`/`when`/`register`); local/docker/ssh
> runners (**SSH connection pooling** via ControlMaster); a **plugin system**
> (drop-in functions/adapters/steps); **45 tool adapters**; **55 functions**
> (file/unix + string/url/util/
> json(jq-lite)/markdown groups, incl. SARIF/nuclei parsing + CDN/WAF
> classification); **Markdown/JSON run reports + snapshot export/import**;
> **workspaces** (runs grouped per target); **cloud object-storage upload**
> (S3/GCS/Azure); Slack/Discord/Telegram notifications; ACP sub-agents (Claude
> Code/Codex/Gemini); distributed queue + worker (Redis-optional); cloud
> provisioners (DO/AWS/GCP/Linode/Azure); **interval + cron + file-watch
> triggers** + webhooks; **SQLite (default) or PostgreSQL** backend + evidence +
> audit + stats; CLI (`run`/`scan`/`health`/`function`/`db`/`report`/`snapshot`/
> `storage`/`watch`/`install`/`config`/`usage`); REST API + Web UI with Mermaid
> visualization, a Tools/Functions browser, and optional API-key auth.

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
# installed globally (uv tool install --editable ./saarthi2)
saarthi2 usage                 # common command examples
saarthi2 workflow list
saarthi2 workflow lint recon
saarthi2 run recon -t example.com
saarthi2 scan example.com      # convenience: run the 'full' flow
saarthi2 health                # which tool binaries are installed
saarthi2 function run apex_domain --arg text=a.b.example.co.uk
saarthi2 report run-...        # Markdown report for a completed run

# Web UI + REST API dashboard (workflow visualization, runs, live logs)
saarthi2 serve                 # http://127.0.0.1:8777
saarthi2 serve --host 0.0.0.0 --port 9000
saarthi2 serve --reload        # dev: auto-restart on source changes
```

Run a scan from the browser with the **▷ New Scan** button (top-right), or from
the CLI. Note: the dashboard HTML is read from disk per request (UI edits show on
reload), but Python code changes need a server restart — use `--reload` in dev.

## Web UI + REST API

`saarthi2 serve` launches a FastAPI app that serves a **single-page dashboard**
(light theme) with a grouped left sidebar and a slide-over detail drawer:

- **Dashboard** — stat cards (runs, findings by severity) + recent runs
- **Runs** — table of every run (workspace-filterable); click a run to open a
  **detail drawer** with the step table, per-step **Output**, **Findings**, and
  **📄 Report** + **🧠 AI Analyze** buttons
- **Workflows** — pick a workflow, see its Mermaid diagram, and run it against a
  target from the browser
- **Findings** — all findings; click one for a details drawer (severity, tool,
  rule, message, location, run)
- **Workspaces**, **Events** (audit log), **Catalog** (tools / functions /
  sub-agents / cloud & storage / plugins), **LLM Playground** (chat), **Settings**
- All target-derived text is rendered as inert text (never HTML)

REST endpoints:

| Method | Path | Purpose |
|---|---|---|
| GET  | `/api/workflows` | list workflows |
| GET  | `/api/workflows/{name}` | detail + `mermaid` diagram |
| POST | `/api/runs` | start a run `{workflow, target, vars, no_ai}` |
| GET  | `/api/runs` | list runs |
| GET  | `/api/runs/{run_id}` | run status, steps (with output), findings, live log |
| GET  | `/api/runs/{run_id}/steps/{step_id}/output` | full step output (evidence or preview) |
| GET  | `/api/tools` | tool-adapter catalog |
| GET  | `/api/functions` | function library |
| GET  | `/api/subagents` | ACP sub-agent catalog |
| GET  | `/api/providers` | cloud-provider catalog |
| GET  | `/api/findings` | recorded findings (`?run_id=`) |
| GET  | `/api/runs/{run_id}/report` | Markdown/JSON report (`?format=`) |
| GET  | `/api/stats` | run/finding aggregate counts |
| GET  | `/api/events` | tail of the audit log (`?limit=`) |
| GET  | `/api/settings` | redacted runtime settings |
| GET  | `/api/workspaces` | workspaces (grouped runs) |
| GET  | `/api/runs?workspace=` | runs filtered by workspace |
| GET  | `/api/storage` | cloud storage providers |
| GET  | `/api/plugins` | discovered extension plugins |
| POST | `/api/llm` | one-shot LLM chat `{prompt, tools}` |
| GET/POST | `/api/jobs` | queue size / enqueue a distributed job |
| POST/GET | `/api/hooks/{workflow}` | webhook trigger a run |
| GET  | `/api/health` | health |

Config via env: `SAARTHI2_OLLAMA_HOST`, `SAARTHI2_OLLAMA_MODEL`,
`SAARTHI2_WORK_DIR`, `SAARTHI2_WORKFLOWS_DIR`, `SAARTHI2_DATABASE_URL` (PostgreSQL),
`SAARTHI2_REDIS_URL`, `SAARTHI2_API_KEY`.

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

## Step types

| `uses` | What it does |
|---|---|
| `tool` | Run a raw `cmd`, or a named adapter (`tool: subfinder`), on a runner |
| `function` | Run a built-in data/file function (see below) |
| `http` | Make a single HTTP request |
| `llm` | Agentic Ollama loop (plan → call tools → observe → repeat) |
| `parallel` | Run a list of sub-steps concurrently (`with: {steps: [...]}`) |
| `notify` | Send a message to Slack/Discord/Telegram |
| `subagent` | Delegate a prompt to Claude Code / Codex / Gemini / OpenCode |

Plus per-step `loop` (foreach), `when` (conditional), `register`, `continue_on_error`.

## Runners

A `tool` step runs `local` (default), in `docker`, or over `ssh`:

```yaml
- id: scan
  uses: tool
  with:
    tool: nuclei
    target: "{{ item }}"
    runner: docker          # or: ssh
    image: projectdiscovery/nuclei:latest
    # ssh_host: user@box    # for runner: ssh
```

**SSH connection pooling** is on by default: repeated `ssh` steps to the same host
reuse a single authenticated session via OpenSSH ControlMaster/ControlPersist
(no re-handshake per command). Tune per step: `ssh_pool: false` to disable,
`ssh_persist: 10m`, `ssh_control_dir: ~/.saarthi2/ssh`.

## AI hunt (autonomous, bounded)

The `ai-hunt` workflow shows the "AI runs tools repeatedly" loop end to end:
deterministic recon (parallel discovery → live-host probing), then an `llm` step
where the agent **picks the most interesting hosts and runs its own follow-up
scans**, then reports findings + next steps.

```bash
saarthi2 run ai-hunt -t example.com     # needs Ollama + recon tools installed
```

The agent is given the **`run_scan`** tool (not raw `run_command`), which is
bounded by design:

- **Allowlist** — only non-destructive detection/recon adapters (nuclei, httpx,
  tlsx, whatweb, katana, …). Brute-forcers (ffuf/gobuster) and `sqlmap` (`--dump`)
  are excluded, so the agent can't DoS a small host or exfiltrate data.
- **Scope lock** — the target must be the run's apex domain or a subdomain of it;
  anything else is refused (this also defends against prompt injection from
  untrusted tool output).
- **Destructive-token denylist** + the usual **policy gate audit** on every call.

To let the agent run *arbitrary* commands instead, give an `llm` step
`tools: [run_command]` — that trades the guardrails for full flexibility (use only
against targets you fully control).

## Skill RAG (ground the AI in bug-hunting playbooks)

Retrieval over the [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
skill corpus (~80 vuln-class playbooks) grounds the local model **without**
fine-tuning — a dependency-free BM25-lite retriever over `SKILL.md` sections.

```bash
saarthi2 skills fetch                 # download the corpus -> <work_dir>/skills
saarthi2 skills search "idor api"     # preview the top matching sections
saarthi2 skills list                  # what's loaded
# or point at an existing copy: export SAARTHI2_SKILLS_DIR=finetune/skills
```

It plugs into the AI three ways:
- **`llm` step** — `with: {skills: true}` prepends the relevant playbook(s) to the
  prompt (`skills: "<query>"` to override, `skills_k: N` for how many).
- **`search_skills` agent tool** — the `ai-hunt` agent calls it to pull the right
  methodology before scanning a host.
- **Web UI** — a **Skills** tab (search + browse), and **🧠 AI Analyze** is
  skill-grounded automatically. `GET /api/skills` + `/api/skills/search`.

For a permanent, offline weight change instead of retrieval, see `finetune/`
(LoRA fine-tune → `saarthi-bughunter` Ollama model).

## Plugins

Extend the engine without touching core. A plugin is a Python module exposing any
of `SAARTHI2_FUNCTIONS` (dict), `SAARTHI2_ADAPTERS` (list), `SAARTHI2_STEPS` (dict):

```python
# ~/.saarthi2/plugins/mytools.py
SAARTHI2_PLUGIN_NAME = "mytools"
def _shout(args, ctx):
    return {"output": str(args.get("text", "")).upper(), "data": {}}
SAARTHI2_FUNCTIONS = {"shout": _shout}
SAARTHI2_ADAPTERS = [{"name": "myscan", "binary": "myscan", "category": "vuln",
                      "template": "myscan -u {target}"}]
```

Plugins load from `<work_dir>/plugins/*.py` **and** from any installed package
declaring a `saarthi2.plugins` entry point. `saarthi2 plugins list` and
`GET /api/plugins` show what's loaded; they merge into the same registries the
built-ins use (so `function run`, `tool: myscan`, `uses: <step>` all just work).

## Tool adapters (45)

Reference a tool by name instead of a raw command; `{param}` placeholders come
from `with`, and `args` appends extra flags:

```yaml
- id: subs
  uses: tool
  with: { tool: subfinder, target: "{{ target }}", args: ["-all"] }
```

- **subdomain**: subfinder · amass · assetfinder · findomain · chaos ·
  shuffledns · dnsgen · github-subdomains
- **dns/net**: dnsx · puredns · massdns · dnsvalidator · tlsx · asnmap · mapcidr
- **http/probe**: httpx · httprobe
- **crawl/urls**: katana · gau · waybackurls · gospider · hakrawler · waymore · unfurl
- **ports**: naabu · nmap
- **fuzzing**: ffuf · gobuster · feroxbuster · arjun
- **vuln**: nuclei · dalfox · sqlmap · interactsh-client
- **sast**: semgrep · trivy
- **classify/fingerprint**: cdncheck · whatweb · wafw00f
- **takeover**: subjack · subzy
- **utility**: gf · anew · notify · gowitness

`saarthi2 health` shows which are installed; `saarthi2 install` prints (or with
`--execute` runs) the curated install commands. `GET /api/tools` lists them all.
Binaries resolve to the real compiled tool even when a Python package ships a
console script of the same name (e.g. the `httpx` library shadowing ProjectDiscovery
`httpx`): a `#!...python` wrapper on PATH is skipped in favor of the actual tool.

## Functions (55)

Glue tool steps into a pipeline (Osmedeus-style). Grouped like Osmedeus's
`internal/functions`:

```yaml
- id: merge
  uses: function
  with: { func: join, inputs: [subfinder.txt, assetfinder.txt], output: subs.txt }
```

- **file/unix**: sort_unique · deduplicate · cat · join · count · grep · replace ·
  head · tail · create_folder · write · append · read · lines_to_json ·
  file_exists · delete_file · copy_file · move_file · list_dir · clean_empty · wc
- **string**: upper · lower · trim · title · split · str_join · replace_regex ·
  regex_extract · contains · base64_encode · base64_decode · length ·
  prepend_each · append_each
- **url**: extract_ips · extract_urls · extract_hosts · url_parse · strip_scheme ·
  apex_domain · url_join
- **util**: uuid · timestamp · env
- **json (jq-lite)**: json_get · json_keys · json_pretty · to_json
- **markdown**: md_table · md_heading · md_bullets
- **parse/classify**: parse_sarif · parse_nuclei · classify_cdn_waf

Functions that emit `findings` (parse_sarif/parse_nuclei) auto-persist to the
findings store. `saarthi2 function list` and `GET /api/functions` list them all;
run one ad-hoc with `saarthi2 function run <name> --arg k=v`.

## Notifications

Set `SAARTHI2_SLACK_WEBHOOK` / `SAARTHI2_DISCORD_WEBHOOK` /
`SAARTHI2_TELEGRAM_TOKEN` + `SAARTHI2_TELEGRAM_CHAT`, then use a `notify` step
(`with: {message: "...", channels: [slack]}`; omit `channels` to hit all).

## Distributed (master/worker)

```bash
export SAARTHI2_REDIS_URL=redis://localhost:6379/0   # for a cross-machine fleet
saarthi2 enqueue recon -t example.com                # master pushes a job
saarthi2 worker                                      # workers pop + run
```
Without a Redis URL an in-process queue is used (single machine / tests).

## Cloud provisioning

```bash
saarthi2 cloud providers
saarthi2 cloud provision --provider digitalocean --name box1 \
  --size s-1vcpu-1gb --image ubuntu-22-04-x64 --region nyc1   # prints the doctl command
# add --execute to actually run it (needs the provider CLI authenticated),
# then target the box with a tool step using runner: ssh.
```

## Reports, snapshots & workspaces

```bash
saarthi2 db runs                       # recent runs
saarthi2 db workspaces                 # runs grouped per target
saarthi2 db findings --run-id run-...  # recorded findings
saarthi2 report run-... --format markdown -o report.md      # or --format json
saarthi2 snapshot export run-... -o ./snap   # snapshot.json + report.md + manifest
saarthi2 snapshot import ./snap/snapshot.json    # re-import into any DB (--run-id to rename)
```
Every run is tagged with a **workspace** (the target slug, or a `workspace` var).
Findings from `parse_sarif`/`parse_nuclei` steps persist automatically and surface
in `db findings`, the reports, and the `/api/findings` + `/api/stats` API.

## Cloud object-storage upload

Ship a snapshot/report off-box via an authenticated provider CLI (credential-free):

```bash
saarthi2 storage providers
saarthi2 storage upload ./snap/report.md --provider s3 --bucket loot   # prints the aws command
saarthi2 storage upload ./r.md --provider s3c --bucket b --endpoint https://minio:9000 --execute
```
Providers: `s3` (aws), `s3c` (S3-compatible: MinIO/Wasabi/R2), `gcs` (gsutil), `azure` (az).

## Scheduling, watch & webhooks

```bash
saarthi2 schedule recon -t example.com --every 3600           # fixed interval
saarthi2 schedule recon -t example.com --cron "0 */6 * * *"   # 5-field cron
saarthi2 watch vuln --path ./targets.txt -t example.com       # fire on file change
# webhook trigger: POST/GET /api/hooks/recon?target=example.com
```

## Database backend

Local SQLite by default (`~/.saarthi2/saarthi2.db`). Point at PostgreSQL for a
shared/team backend:

```bash
pip install 'saarthi2[postgres]'
export SAARTHI2_DATABASE_URL=postgresql://user:pass@host:5432/saarthi2
```

## Auth

Set `SAARTHI2_API_KEY` to require `X-API-Key` on all `/api/*` routes
(`/api/health` stays open).

## Layout

```
src/saarthi2/
  engine/    models · loader · context(interpolation) · runner · graph(mermaid)
  steps/     tool · http · llm · function · notify · subagent
  ai/        ollama(client) · agent(tool-calling loop)
  adapters.py  45 named tool adapters
  functions.py file/unix functions + registry (merges stdlib)
  stdlib.py    string/url/util/json/markdown functions
  parsers.py   SARIF/nuclei → findings, CDN/WAF classify, extractors
  report.py    Markdown/JSON run reports
  cron.py      5-field cron parser (triggers)
  scheduler.py interval + cron schedule loops
  triggers.py  file-watch trigger (mtime poll)
  distributed.py queue + worker (memory/Redis)
  cloud.py     compute provisioners (DO/AWS/GCP/Linode/Azure)
  storage.py   object-storage upload (S3/GCS/Azure)
  notify.py    Slack/Discord/Telegram
  subagents.py ACP sub-agent commands
  plugins.py   plugin loader (dir + entry points -> functions/adapters/steps)
  tools.py     AI tool registry (run_command, http_get)
  policy.py    Gate (permissive default + scoped opt-in)
  state.py     SQLite/PostgreSQL (runs/steps/findings) + evidence + audit + stats
  runtime.py   real deps (subprocess/httpx/ollama)
  server/      FastAPI app + run manager
  cli.py       typer CLI
  workflows/   recon · vuln · full · general · passive-intel · ai-hunt
tests/
```
