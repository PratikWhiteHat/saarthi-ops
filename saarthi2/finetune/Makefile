# Saarthi bug-hunter LoRA fine-tune (Apple Silicon / mlx-lm).
# Trains on YOUR OWN skill library (SKILLS_DIR) and imports the result into Ollama.
#
#   make setup       # one-time: create .venv (python3.12) + install mlx-lm
#   make dataset     # build data/{train,valid}.jsonl from your skills
#   make train       # LoRA fine-tune (LONG; downloads the base model on first run)
#   make chat        # sanity-check the adapter's answers
#   make fuse        # fuse the adapter into ./fused-model
#   make ollama      # import as ollama model `saarthi-bughunter`
#
# Override anything:  make train BASE=mlx-community/Qwen2.5-14B-Instruct-4bit ITERS=800
# Fine-tune a different corpus: make dataset SKILLS_DIR=/path/to/skills

# 14B gives noticeably better agentic/assessment behavior than 7B and, at q4_K_M,
# still fits a 24 GB Mac (~9 GB model). Override BASE=...7B... for a lighter build.
BASE       ?= mlx-community/Qwen2.5-14B-Instruct-4bit
ITERS      ?= 600
SEQ        ?= 2048
LAYERS     ?= 8
# SKILLS_DIR = your live skill library (built into the training set by default).
SKILLS_DIR ?= $(HOME)/.saarthi2/skills
VENV       ?= .venv
PY         ?= $(VENV)/bin/python
# PYBASE: mlx-lm has no wheels for Python 3.13/3.14 yet — use 3.12.
PYBASE     ?= python3.12

.PHONY: help setup fetch dataset train chat fuse ollama all clean
help:
	@echo "make setup     # create .venv + install mlx-lm (run once)"
	@echo "make dataset   # build data/{train,valid}.jsonl from $(SKILLS_DIR)"
	@echo "make train     # LoRA fine-tune (BASE=$(BASE), ITERS=$(ITERS)) — long"
	@echo "make chat      # quick sanity generation with the adapter"
	@echo "make fuse          # fuse LoRA -> ./fused-model (de-quantized)"
	@echo "make convert-setup # one-time: clone llama.cpp + .venv-convert (GGUF tools)"
	@echo "make gguf          # fused-model -> $(GGUF)"
	@echo "make ollama        # ollama create saarthi-bughunter -f Modelfile.gguf"
	@echo "make all           # setup -> dataset -> train -> fuse -> convert-setup -> gguf -> ollama"

setup:
	$(PYBASE) -m venv $(VENV)
	$(PY) -m pip install -U pip
	$(PY) -m pip install -U mlx-lm

# Optional: refresh the bundled third-party corpus from GitHub into ./skills.
# Not needed for training on your own skills (that's SKILLS_DIR, default ~/.saarthi2/skills).
fetch:
	./fetch_skills.sh

# build_dataset.py is dependency-free (stdlib), so plain python3 is fine here.
dataset:
	python3 build_dataset.py --skills "$(SKILLS_DIR)" --out data

train:
	$(VENV)/bin/mlx_lm.lora --model $(BASE) --train --data data --iters $(ITERS) \
	  --batch-size 1 --num-layers $(LAYERS) --max-seq-length $(SEQ) \
	  --adapter-path adapters --grad-checkpoint

chat:
	$(VENV)/bin/mlx_lm.generate --model $(BASE) --adapter-path adapters --max-tokens 400 \
	  --prompt "How do I hunt IDOR vulnerabilities on an authorized target?"

fuse:
	$(VENV)/bin/mlx_lm.fuse --model $(BASE) --adapter-path adapters --save-path fused-model --dequantize

# --- GGUF path (required for Ollama, which can't import MLX-fused safetensors) ---
# Isolated venv: llama.cpp's converter pins transformers<5, which conflicts with
# mlx-lm — keep them apart so `make train` keeps working.
CVENV   ?= .venv-convert
GGUF_Q8 ?= saarthi-14b-q8_0.gguf
GGUF    ?= saarthi-bughunter-q4_k_m.gguf

# One-time: clone llama.cpp, make the isolated convert venv (its transformers pin
# conflicts with mlx-lm), and BUILD llama-quantize (needs cmake: `brew install cmake`).
convert-setup:
	test -d llama.cpp || git clone --depth 1 https://github.com/ggml-org/llama.cpp
	$(PYBASE) -m venv $(CVENV)
	$(CVENV)/bin/python -m pip install -U pip
	$(CVENV)/bin/python -m pip install -r llama.cpp/requirements/requirements-convert_hf_to_gguf.txt
	cmake -S llama.cpp -B llama.cpp/build -DCMAKE_BUILD_TYPE=Release -DLLAMA_CURL=OFF
	cmake --build llama.cpp/build --target llama-quantize -j4

# fused-model -> q8_0 GGUF -> q4_K_M (fits 24 GB at inference). mlx_lm.fuse writes an
# extra_special_tokens list newer transformers rejects, so refresh the tokenizer from
# the base snapshot first. q8 intermediate is deleted to keep disk use low.
gguf:
	$(CVENV)/bin/python -c "from huggingface_hub import snapshot_download as s; import shutil,os; d=s('$(BASE)'); [shutil.copy(os.path.join(d,f),os.path.join('fused-model',f)) for f in ['tokenizer.json','tokenizer_config.json','vocab.json','merges.txt','added_tokens.json','special_tokens_map.json'] if os.path.exists(os.path.join(d,f))]"
	$(CVENV)/bin/python llama.cpp/convert_hf_to_gguf.py fused-model --outfile $(GGUF_Q8) --outtype q8_0
	./llama.cpp/build/bin/llama-quantize --allow-requantize $(GGUF_Q8) $(GGUF) Q4_K_M
	rm -f $(GGUF_Q8)

ollama:
	ollama create saarthi-bughunter -f Modelfile.gguf

all: setup dataset train fuse convert-setup gguf ollama

# Note: does NOT delete ./skills, ./llama.cpp, or your ~/.saarthi2/skills.
clean:
	rm -rf data adapters fused-model repo.tar.gz *.gguf
