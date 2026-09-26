# Saarthi bug-hunter LoRA fine-tune (Apple Silicon / mlx-lm).
# Override the base or iters:  make train BASE=mlx-community/Qwen2.5-14B-Instruct-4bit ITERS=800

BASE  ?= mlx-community/Qwen2.5-7B-Instruct-4bit
ITERS ?= 600
SEQ   ?= 2048
LAYERS?= 8

.PHONY: help fetch dataset train chat fuse ollama all clean
help:
	@echo "make fetch     # download the skills corpus"
	@echo "make dataset   # build data/{train,valid}.jsonl from skills"
	@echo "make train     # LoRA fine-tune with mlx-lm (BASE=$(BASE), ITERS=$(ITERS))"
	@echo "make chat      # quick sanity generation with the adapter"
	@echo "make fuse      # fuse LoRA -> ./fused-model (de-quantized, GGUF/Ollama-ready)"
	@echo "make ollama    # ollama create saarthi-bughunter -f Modelfile"
	@echo "make all       # fetch -> dataset -> train -> fuse -> ollama"

fetch:
	./fetch_skills.sh

dataset:
	python build_dataset.py --skills skills --out data

train:
	mlx_lm.lora --model $(BASE) --train --data data --iters $(ITERS) \
	  --batch-size 1 --num-layers $(LAYERS) --max-seq-length $(SEQ) \
	  --adapter-path adapters --grad-checkpoint

chat:
	mlx_lm.generate --model $(BASE) --adapter-path adapters --max-tokens 400 \
	  --prompt "How do I hunt IDOR vulnerabilities on an authorized target?"

fuse:
	mlx_lm.fuse --model $(BASE) --adapter-path adapters --save-path fused-model --de-quantize

ollama:
	ollama create saarthi-bughunter -f Modelfile

all: fetch dataset train fuse ollama

clean:
	rm -rf skills data adapters fused-model repo.tar.gz *.gguf
