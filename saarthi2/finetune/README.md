# Fine-tuning a local Saarthi bug-hunter model

Turn the [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
skill corpus (~80 vuln-class playbooks) into a **LoRA fine-tune** of a local model,
then import it into Ollama as `saarthi-bughunter` and point Saarthi 2.0 at it.

This runs on **Apple Silicon** via [`mlx-lm`](https://github.com/ml-explore/mlx-lm).
The dataset build runs anywhere; the training step needs your Mac (multi-GB model
download + a while of compute).

## What's here
- `build_dataset.py` — skills → `data/{train,valid}.jsonl` (chat-format instruction pairs)
- `Makefile` — `setup → dataset → train → fuse → ollama`
- `Modelfile` — import the fused model into Ollama
- `fetch_skills.sh` — (optional) refresh the third-party corpus into `./skills`

By default the dataset is built from **your own** skill library at
`~/.saarthi2/skills` (`SKILLS_DIR`), so whatever you add/edit there is what the
model learns. Point `SKILLS_DIR` elsewhere to train on a different corpus.

## Prerequisites
mlx-lm needs Apple Silicon and a Python it has wheels for (3.12 — **not** 3.13/3.14).
`make setup` creates an isolated `.venv` with `python3.12` and installs mlx-lm, so
you don't touch your system Python. Ollama must be installed (it is).

## Steps
```bash
cd finetune

# 1. one-time toolchain + dataset (fast, no GPU)
make setup          # -> .venv (python3.12 + mlx-lm)
make dataset        # -> data/{train,valid}.jsonl from ~/.saarthi2/skills

# 2. LoRA fine-tune (LONG; downloads the ~4 GB base model on first run)
make train          # BASE=mlx-community/Qwen2.5-7B-Instruct-4bit ITERS=600
make chat           # sanity-check the adapter's answers

# 3. fuse the adapter, convert to GGUF, and import into Ollama
make fuse           # -> ./fused-model  (de-quantized)
make convert-setup  # -> llama.cpp + .venv-convert (one-time)
make gguf           # -> saarthi-bughunter-q8_0.gguf
make ollama         # -> ollama model `saarthi-bughunter`

# 4. point Saarthi at it
export SAARTHI2_OLLAMA_MODEL=saarthi-bughunter
saarthi2 serve --reload
```

On a 24 GB M-series Mac the 7B 4-bit LoRA (600 iters, 8 layers, seq 2048, batch 1,
grad-checkpoint) fits comfortably; close other heavy apps and avoid serving a big
Ollama model at the same time. Retrain any time you change your skills:
`make dataset && make train && make fuse && make ollama`.

Tune scale with `make train BASE=... ITERS=... SEQ=... LAYERS=...`. A 7B 4-bit
base LoRA at 600 iters is a reasonable first run; raise `ITERS`/`LAYERS` for more
adaptation, lower them if you hit memory limits.

## Choosing the base model
Fine-tune the **same family** you'll serve. `mlx-community/Qwen2.5-7B-Instruct-4bit`
is a solid default (QLoRA-friendly). For the larger local model use
`mlx-community/Qwen2.5-14B-Instruct-4bit` (more RAM + time). Whatever you pick,
`fetch`/`dataset` are unchanged — only `BASE` differs.

## GGUF path (required for current Ollama)
Ollama (0.34.x) can't import the MLX-fused safetensors directly — it fails with
`unsupported MLX architecture: Qwen2ForCausalLM`. So the default flow converts the
fused model to GGUF and imports that (`Modelfile.gguf`, which carries the Qwen
ChatML template). It's wired into the Makefile:
```bash
make convert-setup   # clone llama.cpp + .venv-convert (isolated: its transformers
                     # pin conflicts with mlx-lm, so it gets its own venv)
make gguf            # fused-model -> saarthi-bughunter-q8_0.gguf (~7.5 GB, q8_0)
make ollama          # ollama create saarthi-bughunter -f Modelfile.gguf
```
Notes:
- q8_0 keeps quality high and fits 24 GB comfortably; for a smaller/faster model,
  build llama.cpp and `llama-quantize` the gguf to `Q4_K_M`, then point
  `Modelfile.gguf` at it.
- `make gguf` first refreshes `fused-model`'s tokenizer from the base snapshot —
  `mlx_lm.fuse` writes an `extra_special_tokens` list that newer `transformers`
  rejects during conversion.

## Dataset design (why it works)
`build_dataset.py` synthesizes chat pairs from each skill instead of dumping raw
docs: an *overview / when-to-use* pair, one pair **per `##` section** (question
templated from the heading — methodology, attack-surface signals, payloads, root
causes, bypasses, validation, impact, chains), a *full-methodology* pair, and a
*which-skill-for-X* routing pair. Every pair carries the same authorized-use
system prompt, so the model learns the methodology and the routing without
overfitting to one phrasing.

## Note: fine-tune vs. retrieval
LoRA bakes methodology and tone into the weights (offline, private). It does **not**
memorize exact payloads verbatim — for pixel-perfect recall of a specific skill,
retrieval (RAG) over the corpus complements the fine-tune. The **RAG path is
already wired** into Saarthi (`saarthi2 skills fetch`, the `llm`-step `skills:`
option, the `search_skills` agent tool, and the Web UI Skills tab) — see the "Skill
RAG" section in the top-level README. Use RAG for recall now, and this LoRA to bake
in the methodology when you want a self-contained model.

> Corpus credit: skills authored by the Claude-BugHunter project. Use only against
> assets you are authorized to test.
