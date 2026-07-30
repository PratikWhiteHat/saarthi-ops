# Saarthi AI Project Skill

## Mission
Build a local-first, security-specialized AI assistant for authorized security assessments,
controlled labs, secure architecture review, vulnerability analysis, and reporting.

## Current Milestone: Phase 0 — Foundation

### Objective
Establish a reproducible macOS development environment and verify local inference through
Ollama before adding datasets, RAG, fine-tuning, memory, or security tools.

### Required outcomes
1. `uv` manages Python, dependencies, virtual environment, and lockfile.
2. Ollama serves the configured open-weight model locally.
3. FastAPI exposes health and chat endpoints.
4. The terminal CLI can query the same local model.
5. Tests and lint checks pass.
6. All potentially impactful tool execution will later require scope validation and approval.

## Phases

### Phase 0 — Foundation
- Repository structure
- Configuration and secrets handling
- Local model runtime
- API and terminal interface
- Tests, linting, and documentation

### Phase 1 — Dataset engineering
- Define JSONL schemas
- Build provenance and license metadata
- Sanitize confidential material
- Create train, validation, and held-out test splits
- Add quality review and deduplication

### Phase 2 — Baseline evaluation
- Create security-domain benchmarks before training
- Measure factual accuracy, uncertainty, reporting quality, and safe scope handling
- Compare the base model against future Saarthi checkpoints

### Phase 3 — RAG
- Ingest approved OWASP, MITRE ATT&CK, CWE, NIST, CVE, and internal documents
- Add chunking, embeddings, citations, freshness metadata, and retrieval evaluation

### Phase 4 — Fine-tuning
- Select an open-weight base checkpoint with a compatible license
- Run supervised fine-tuning using LoRA/QLoRA on cloud GPU when required
- Record data, hyperparameters, hashes, evaluations, and model card details

### Phase 5 — Agent and tool system
- Typed tool schemas
- Human approval before execution
- Allowlisted commands and arguments
- Sandboxed execution
- Timeouts, output limits, logs, and audit trails
- No operation outside explicitly authorized scope

### Phase 6 — Memory and engagement state
- Store scope, assets, evidence, findings, decisions, and provenance
- Encrypt sensitive material and define retention/deletion controls

### Phase 7 — Reporting
- Evidence-grounded findings
- Clear separation of observation, inference, and recommendation
- Standard severity, remediation, and reference fields

### Phase 8 — Deployment and improvement
- Authentication, authorization, monitoring, backups, versioning, and rollback
- Feedback-to-dataset pipeline with human review
- Regression evaluation before every release

## Engineering rules
- Local-first during prototyping
- Quality and provenance over dataset volume
- Never train on secrets or unsanitized client data
- Never claim execution without captured tool evidence
- Structured outputs for machine-readable workflows
- Human-in-the-loop for impactful actions
- Reproducible builds and evaluations
