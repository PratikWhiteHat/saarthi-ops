# Fine-tuning a local Saarthi bug-hunter model

Turn the [Claude-BugHunter](https://github.com/elementalsouls/Claude-BugHunter)
skill corpus (~80 vuln-class playbooks) into a **LoRA fine-tune** of a local model,
then import it into Ollama as `saarthi-bughunter` and point Saarthi 2.0 at it.

This runs on **Apple Silicon** via [`mlx-lm`](https://github.com/ml-explore/mlx-lm).
The dataset build runs anywhere; the training step needs your Mac (multi-GB model
download + a while of compute).

## What's here
- `fetch_skills.sh` — download the skills corpus into `./skills`
- `build_dataset.py` — skills → `data/{train,valid}.jsonl` (chat-format instruction pairs)
- `Makefile` — `fetch → dataset → train → fuse → ollama`
- `Modelfile` — import the fused model into Ollama

## Prerequisites
```bash
python -m pip install -U mlx-lm         # Apple Silicon LoRA trainer
# Ollama already installed; a recent version can import safetensors directly.
```

## Steps
```bash
cd finetune

# 1. corpus + dataset (fast, no GPU)
make fetch          # -> ./skills  (83 SKILL.md)
make dataset        # -> data/train.jsonl (~1.3k), data/valid.jsonl (~150)

# 2. LoRA fine-tune (this is the long step; runs on your Mac)
make train          # BASE=mlx-community/Qwen2.5-7B-Instruct-4bit ITERS=600
make chat           # sanity-check the adapter's answers

# 3. fuse the adapter into a standalone model, then import into Ollama
make fuse           # -> ./fused-model  (de-quantized, import-ready)
make ollama         # -> ollama model `saarthi-bughunter`

# 4. point Saarthi at it
export SAARTHI2_OLLAMA_MODEL=saarthi-bughunter
saarthi2 serve --reload
```

Tune scale with `make train BASE=... ITERS=... SEQ=... LAYERS=...`. A 7B 4-bit
base LoRA at 600 iters is a reasonable first run; raise `ITERS`/`LAYERS` for more
adaptation, lower them if you hit memory limits.

## Choosing the base model
Fine-tune the **same family** you'll serve. `mlx-community/Qwen2.5-7B-Instruct-4bit`
is a solid default (QLoRA-friendly). For the larger local model use
`mlx-community/Qwen2.5-14B-Instruct-4bit` (more RAM + time). Whatever you pick,
`fetch`/`dataset` are unchanged — only `BASE` differs.

## GGUF fallback (older Ollama)
If `ollama create` can't import `./fused-model` directly, convert to GGUF with
llama.cpp and point the `Modelfile` at the `.gguf`:
```bash
git clone https://github.com/ggml-org/llama.cpp && pip install -r llama.cpp/requirements.txt
python llama.cpp/convert_hf_to_gguf.py fused-model --outfile saarthi-bughunter-f16.gguf --outtype f16
./llama.cpp/llama-quantize saarthi-bughunter-f16.gguf saarthi-bughunter-q4_k_m.gguf Q4_K_M
# edit Modelfile: FROM ./saarthi-bughunter-q4_k_m.gguf  (+ a ChatML TEMPLATE for Qwen)
ollama create saarthi-bughunter -f Modelfile
```

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
