# Saarthi OPS

**A local-first, privacy-first, AI-assisted VAPT platform.**
Reconnaissance through controlled attack validation, driven by a local-LLM
co-pilot — entirely on the operator's own machine. No target data, credentials,
or evidence ever leaves the box.

`LOCAL-FIRST · PRIVACY-FIRST · OPERATOR-FIRST`

![Saarthi OPS operator console](docs/screenshots/saarthi-ops-console.png)

## Why

Offensive workflows increasingly want AI assistance — but shipping a client's
data to a cloud LLM is a non-starter under most engagement rules. Saarthi OPS
runs the whole authorized engagement **and** its AI co-pilot locally using
[Ollama](https://ollama.com/). Everything is evidence-driven, permission-gated,
bounded, reversible, and fully audited.

## What it does

From a single authorized URL, Saarthi orchestrates:

- **Recon (Phase 3)** — DNS, subdomains, live-host & HTTP intelligence,
  crawling, JavaScript intelligence, historical-URL discovery (Wayback CDX),
  and local page archiving.
- **Safe direct checks (Phase 4)** — security headers, TLS, CORS, redirects,
  technology fingerprinting.
- **Assessment orchestration (Phase 5)** — planning, dependency and outcome
  handling.
- **Controlled attack validation (Phase 6)**
  - **6A** Attack Hypothesis Engine
  - **6B** Policy & Approval Gate
  - **6C** Low-Risk Surface Validators (injection, browser, server/parser,
    clickjacking, CSRF, HTTP parameters, session cookies, file upload, API
    data-exposure)
  - **6D** Authenticated Workflows — auto-login multiple accounts and replay
    requests across them to surface IDOR/BOLA, vertical privilege escalation,
    and tenant-isolation breaks, plus JWT/session-token hygiene.
  - **6E–6H** evidence-only impact confirmation, offline post-exploitation
    simulation, cleanup accounting, and hash-verified findings consolidation.

Interrupted local runs are recovered automatically at the next TUI startup.
Only `RUNNING` or `ANALYZING` records inactive for at least six hours are
closed, and every recovery is recorded in the local audit trail.

Throughout, an **AI co-pilot** watches each phase live, triages and ranks
findings, cross-checks them with independent tools (e.g., ghauri confirming
sqlmap) to cut false positives, and produces an evidence-backed report — all
offline. **Adaptive control** auto-tunes scanners around WAF and rate-limiting
so scans complete without getting blocked.

**Integrated tooling:** subfinder · amass · assetfinder · crt.sh · httpx ·
katana · Wayback CDX · local page archive · nuclei · sqlmap · ghauri ·
XSStrike — alongside Saarthi's own JavaScript-intelligence,
attack-hypothesis, and authenticated-workflow engines.

![Workflow status and enabled tools](docs/screenshots/saarthi-ops-workflow.png)

## Design principle: autonomous yet accountable

Every AI and tool action is:

- **Evidence-driven** — every decision traces to captured evidence.
- **Permission-gated** — a single operator authorization ("Authorize & Run")
  governs the engagement, scope-locked to a declared allowed-host list.
- **Bounded & reversible** — request budgets, timeouts, non-destructive by
  default.
- **Audited** — a complete local audit trail; credentials and secrets are
  **never persisted** (only labels + SHA-256 fingerprints).

## Quickstart

Built for Apple Silicon macOS. Prerequisites:
[`uv`](https://docs.astral.sh/uv/), [Ollama](https://ollama.com/), and ~24 GB
unified memory for the default 9B model.

```bash
git clone <this-repo-url>
cd saarthi-ai-starter
cp .env.example .env
./scripts/setup_mac.sh          # install deps and pull the local model
uv run saarthi-ai               # launch the operator console (TUI)
```

Other entry points:

```bash
uv run saarthi doctor           # environment diagnostics
uv run saarthi authenticated run --config authenticated-sessions.json --approved
```

### Local CVE intelligence

The CVE catalog is separate from active testing. When an operator selects
**Authorize & Run** in the TUI, Phase 3C collects CPE fingerprints and Phase 5E
automatically refreshes the local NVD/CISA KEV cache when stale, queries the
public NVD CVE API for observed CPEs, matches candidates, and writes hashed
evidence. Online requests include product CPEs, but never the target URL or
hostname. A feed/API outage does not stop the assessment; Phase 5E uses the
existing cache and records the online status. Product/CPE matching does not
confirm a vulnerability. The cache lives at `~/.saarthi/cve.db`.

```bash
uv run saarthi cve sync --days 7
uv run saarthi cve status
uv run saarthi cve match --cpe 'cpe:2.3:a:vendor:product:1.2:*:*:*:*:*:*:*'
```

For offline use, export official NVD API 2.0 and CISA KEV JSON files, then use
`saarthi cve import-nvd FILE` and `saarthi cve import-kev FILE`. The sync command
is an incremental modified-date import, not a full historical NVD mirror.
Version-unknown and complex configuration matches require manual review. Online
CPE lookup is bounded to five distinct CPEs and two API pages per CPE; evidence
marks a partial result if those limits are reached. The TUI's Phase 5E activity
line reports CPE/candidate counts and online status; the evidence catalog
contains the full result JSON.

Default local model: `qwen3.5:9b` (configurable in `.env`).

### Operator-controlled AI skills

Press **S** in the TUI to open **Skills**. Choose **Import 83 skills** once to
download the markdown reference material from a pinned revision of
[Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter/tree/main/skills),
then select a row and press **Space** to enable or disable it. All skills start
disabled. Saarthi stores the imported references and toggle state under
`~/.saarthi/skills` (override with `SAARTHI_SKILLS_DIR`). Import requires
internet access; subsequent local AI analysis does not.

Enabled skills provide bounded, topic-matched reference excerpts to the local
Ollama model. This is **not model fine-tuning** and does not retrain weights.
Skills cannot change authorization, tool execution, or evidence requirements;
Saarthi never executes upstream scripts. A maximum of three relevant enabled
skills are included per model request. Imported documentation is attributed to
its authors and licensed under [CC BY 4.0](https://github.com/elementalsouls/Claude-BugHunter/blob/main/LICENSE-CONTENT);
the local `ATTRIBUTION.txt` records the pinned source revision.

Saved three-pass AI quality analyses record which skill references were actually
supplied in each pass, the summaries behind cited evidence IDs, missing evidence,
and finding-disposition counts. An enabled skill is not necessarily selected,
and a supplied skill is not proof that it caused a finding.

## Authorized use only

Saarthi OPS is for **authorized** security testing — your own systems, or
engagements / bug-bounty scopes you have **written permission** to test. It is
scope-locked to hosts you explicitly declare and must not be used against
systems you do not own or are not authorized to assess.

## Roadmap

Phases 1–6H are implemented, including evidence-grounded AI review, verified
Phase 6E impact confirmation, offline Phase 6F impact simulation, and Phase 6G
cleanup accounting. Phase 6H verifies evidence integrity and consolidates
redacted findings into a hash-linked bundle for the TUI and reports. Phase 6E
confirms impact only from integrity-checked evidence already produced by the
authorized workflow; it does not perform new exploitation or data extraction.
Upcoming: **Phase 7** (attack chaining) and the remaining **Phase 8**
reporting/remediation work, with policy controls for higher-risk actions.

## Author

**Pratik Chotalia** — security consultant (Dubai, UAE). OSCP, OSEP, OSED,
CARTP, CRTP, OffSec AI-300 (OSAI). Invite-only Synack Red Team; recognized in
the NASA and NCIIPC Halls of Fame.
LinkedIn: <https://www.linkedin.com/in/pratik-chotalia-142aaab1/>

## License

Released under the [MIT License](LICENSE).
