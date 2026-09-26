"""Retrieval over the bug-hunting skill library (dependency-free BM25-lite).

Grounds the local model in the Claude-BugHunter playbooks *without* fine-tuning:
load ``SKILL.md`` files from a directory, chunk them by ``##`` section, and
retrieve the most relevant chunks for a query. Pure-Python lexical scoring — no
embedding model or extra dependency required, so it runs offline and is testable.
The retrieved text is injected into an ``llm`` step / AI-Analyze prompt, or pulled
on demand by the agent's ``search_skills`` tool.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9]{2,}")
_K1 = 1.5
_B = 0.75


def _tokenize(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def _parse_frontmatter(text: str) -> tuple[dict, str]:
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    meta: dict = {}
    for line in text[3:end].strip().splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    return meta, text[end + 4 :].lstrip("\n")


def _split_sections(body: str) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []
    head, buf = "Overview", []
    for line in body.splitlines():
        if line.startswith("## "):
            if "".join(buf).strip():
                sections.append((head, "\n".join(buf).strip()))
            head, buf = line[3:].strip(), []
        else:
            buf.append(line)
    if "".join(buf).strip():
        sections.append((head, "\n".join(buf).strip()))
    return sections


@dataclass
class Chunk:
    skill: str
    heading: str
    text: str
    tokens: list[str] = field(default_factory=list)


class SkillLibrary:
    """A searchable corpus of skill sections."""

    def __init__(self, chunks: list[Chunk], descriptions: dict[str, str]) -> None:
        self.chunks = chunks
        self.descriptions = descriptions
        self._df: dict[str, int] = {}
        for ch in chunks:
            for term in set(ch.tokens):
                self._df[term] = self._df.get(term, 0) + 1
        lengths = [len(ch.tokens) for ch in chunks]
        self._avgdl = (sum(lengths) / len(lengths)) if lengths else 0.0
        self._n = len(chunks)

    # --- construction --------------------------------------------------------

    @classmethod
    def from_dir(cls, skills_dir: str | Path) -> SkillLibrary:
        root = Path(skills_dir).expanduser()
        chunks: list[Chunk] = []
        descriptions: dict[str, str] = {}
        if root.is_dir():
            for skill_md in sorted(root.glob("*/SKILL.md")):
                raw = skill_md.read_text(encoding="utf-8", errors="replace")
                meta, body = _parse_frontmatter(raw)
                name = meta.get("name") or skill_md.parent.name
                descriptions[name] = meta.get("description", "")
                for heading, text in _split_sections(body):
                    if text.strip():
                        tokens = _tokenize(f"{name} {heading} {text}")
                        chunks.append(Chunk(name, heading, text, tokens))
                for ref in sorted(skill_md.parent.glob("references/*.md")):
                    ref_text = ref.read_text(encoding="utf-8", errors="replace")
                    chunks.append(Chunk(f"{name}/{ref.stem}", "reference", ref_text,
                                        _tokenize(f"{name} {ref.stem} {ref_text}")))
        return cls(chunks, descriptions)

    def __len__(self) -> int:
        return self._n

    @property
    def is_empty(self) -> bool:
        return self._n == 0

    # --- retrieval -----------------------------------------------------------

    def _score(self, q_terms: list[str], ch: Chunk) -> float:
        if not ch.tokens:
            return 0.0
        tf: dict[str, int] = {}
        for t in ch.tokens:
            tf[t] = tf.get(t, 0) + 1
        dl = len(ch.tokens)
        score = 0.0
        for term in q_terms:
            f = tf.get(term, 0)
            if not f:
                continue
            df = self._df.get(term, 0) or 1
            idf = math.log(1 + (self._n - df + 0.5) / (df + 0.5))
            denom = f + _K1 * (1 - _B + _B * dl / (self._avgdl or 1))
            score += idf * (f * (_K1 + 1)) / denom
        return score

    def retrieve(self, query: str, k: int = 3) -> list[Chunk]:
        q_terms = _tokenize(query)
        if not q_terms or self.is_empty:
            return []
        scored = ((self._score(q_terms, ch), ch) for ch in self.chunks)
        ranked = sorted((s for s in scored if s[0] > 0), key=lambda s: s[0], reverse=True)
        return [ch for _score, ch in ranked[:k]]

    def context_for(self, query: str, k: int = 3, max_chars: int = 4000) -> str:
        """A prompt-ready block of the top-k skill sections for ``query``."""

        hits = self.retrieve(query, k=k)
        if not hits:
            return ""
        parts, used = [], 0
        for ch in hits:
            block = f"### skill: {ch.skill} — {ch.heading}\n{ch.text}"
            if used + len(block) > max_chars:
                block = block[: max(0, max_chars - used)]
            parts.append(block)
            used += len(block)
            if used >= max_chars:
                break
        return "Relevant hunting playbooks (reference only):\n\n" + "\n\n".join(parts)

    def search(self, query: str, k: int = 5) -> list[dict]:
        """Search results for the API/CLI (skill, heading, preview)."""

        return [
            {"skill": ch.skill, "heading": ch.heading, "preview": ch.text[:200].replace("\n", " ")}
            for ch in self.retrieve(query, k=k)
        ]

    def catalog(self) -> list[dict]:
        counts: dict[str, int] = {}
        for ch in self.chunks:
            counts[ch.skill] = counts.get(ch.skill, 0) + 1
        return [
            {"name": name, "description": self.descriptions.get(name, ""), "sections": counts[name]}
            for name in sorted(counts)
        ]
