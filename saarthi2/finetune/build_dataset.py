#!/usr/bin/env python3
"""Turn the Claude-BugHunter SKILL.md corpus into an mlx-lm LoRA training set.

Each skill is a reference-methodology doc (YAML frontmatter + ``##`` sections).
We synthesize chat-format instruction/response pairs — an overview pair, one pair
per section (question templated from the heading), a full-methodology pair, and a
"which skill for X" routing pair — then write train/valid JSONL in the format
``mlx_lm.lora`` expects (one JSON object per line with a "messages" list).

Usage:
    python build_dataset.py --skills skills --out data [--valid-frac 0.1] [--seed 7]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

SYSTEM_PROMPT = (
    "You are Saarthi, an expert bug-bounty and penetration-testing assistant "
    "operating strictly under explicit, authorized engagement. Give precise, "
    "practical hunting methodology: attack-surface signals, step-by-step "
    "procedures, payloads, detection, validation gates, and realistic impact. "
    "Only ever target assets the operator is authorized to test."
)

# Map common section headings to a natural question. Matched case-insensitively
# on a substring so slight heading variations still route.
_HEADING_QUESTIONS: list[tuple[str, str]] = [
    ("crown jewel", "What are the highest-value targets to look for when hunting {x}?"),
    ("attack surface", "What attack-surface signals indicate {x}?"),
    ("methodology", "Walk me through the step-by-step methodology to hunt {x}."),
    ("payload", "What payloads and detection patterns should I use for {x}?"),
    ("detection", "How do I detect {x}?"),
    ("root cause", "What are the common root causes of {x}?"),
    ("bypass", "How do I bypass defenses against {x}?"),
    ("gate", "How do I validate a {x} finding before reporting it?"),
    ("validation", "How do I validate a {x} finding before reporting it?"),
    ("impact", "Give real-world impact examples for {x}."),
    ("chain", "How can I chain {x} into higher-severity findings?"),
    ("tool", "Which tools help when hunting {x}?"),
    ("report", "How should I write up a {x} finding?"),
    ("recon", "How do I do recon for {x}?"),
]

_MAX_SECTION = 6000
_MAX_FULL = 9000


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Split leading ``--- ... ---`` YAML-ish frontmatter from the body."""

    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    raw = text[3:end].strip()
    body = text[end + 4 :].lstrip("\n")
    meta: dict = {}
    for line in raw.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    return meta, body


def split_sections(body: str) -> list[tuple[str, str]]:
    """Split a markdown body into (heading, content) for each top-level ``## `` section.

    Text before the first ``## `` is returned under the "Overview" heading.
    """

    sections: list[tuple[str, str]] = []
    current_head = "Overview"
    buf: list[str] = []
    for line in body.splitlines():
        if line.startswith("## "):
            if buf and "".join(buf).strip():
                sections.append((current_head, "\n".join(buf).strip()))
            current_head = line[3:].strip()
            buf = []
        else:
            buf.append(line)
    if buf and "".join(buf).strip():
        sections.append((current_head, "\n".join(buf).strip()))
    return sections


def pretty_name(name: str) -> str:
    """``hunt-idor`` -> ``IDOR``; ``bb-methodology`` -> ``bug-bounty methodology``."""

    base = re.sub(r"^hunt-", "", name)
    base = base.replace("bb-", "bug-bounty ").replace("-", " ")
    # uppercase short tokens that look like acronyms (idor, ssrf, xss, sqli, jwt…)
    words = [w.upper() if 2 <= len(w) <= 5 and w.isalpha() else w for w in base.split()]
    return " ".join(words).strip() or name


def question_for(heading: str, x: str) -> str:
    low = heading.lower()
    for needle, template in _HEADING_QUESTIONS:
        if needle in low:
            return template.format(x=x)
    return f"For hunting {x}, explain: {heading}."


def _msg(user: str, assistant: str) -> dict:
    return {
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }


def build_pairs(name: str, description: str, body: str) -> list[dict]:
    """Generate instruction/response pairs for one skill."""

    x = pretty_name(name)
    pairs: list[dict] = []
    sections = split_sections(body)

    # 1) Overview / when-to-use
    overview = next((c for h, c in sections if h == "Overview"), "")
    intro = (description + ("\n\n" + overview if overview else "")).strip()[:_MAX_SECTION]
    if intro:
        pairs.append(_msg(f"How do I hunt {x} vulnerabilities?", intro))
        when = (description or intro)[:_MAX_SECTION]
        pairs.append(_msg(f"When should I use the {name} skill?", when))

    # 2) One pair per real section
    for heading, content in sections:
        if heading == "Overview" or not content.strip():
            continue
        pairs.append(_msg(question_for(heading, x), content[:_MAX_SECTION]))

    # 3) Full methodology (capped)
    if body.strip():
        full = body.strip()[:_MAX_FULL]
        pairs.append(_msg(f"Give me the complete methodology for hunting {x}.", full))

    return pairs


def router_pair(name: str, description: str) -> dict:
    return _msg(
        f"Which Saarthi hunting skill covers this: {description}",
        f"Use the `{name}` skill. {description}",
    )


def load_skills(skills_dir: Path) -> list[tuple[str, str, str]]:
    """Return (name, description, body) for every SKILL.md and references/*.md."""

    out: list[tuple[str, str, str]] = []
    for skill_md in sorted(skills_dir.glob("*/SKILL.md")):
        meta, body = parse_frontmatter(skill_md.read_text(encoding="utf-8", errors="replace"))
        name = meta.get("name") or skill_md.parent.name
        out.append((name, meta.get("description", ""), body))
        # fold in any reference sub-docs under this skill
        for ref in sorted(skill_md.parent.glob("references/*.md")):
            ref_body = ref.read_text(encoding="utf-8", errors="replace")
            ref_desc = f"{name} reference: {ref.stem.replace('-', ' ')}"
            out.append((f"{name}/{ref.stem}", ref_desc, ref_body))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skills", default="skills", type=Path)
    ap.add_argument("--out", default="data", type=Path)
    ap.add_argument("--valid-frac", default=0.1, type=float)
    ap.add_argument("--seed", default=7, type=int)
    args = ap.parse_args()

    skills = load_skills(args.skills)
    if not skills:
        raise SystemExit(f"no skills found under {args.skills} (run fetch_skills.sh first)")

    pairs: list[dict] = []
    for name, description, body in skills:
        pairs.extend(build_pairs(name, description, body))
        if description:
            pairs.append(router_pair(name, description))

    # Deterministic shuffle (index-based) so runs are reproducible without RNG state.
    order = sorted(range(len(pairs)), key=lambda i: ((i * 2654435761 + args.seed) % 2147483647))
    pairs = [pairs[i] for i in order]

    n_valid = max(1, int(len(pairs) * args.valid_frac))
    valid, train = pairs[:n_valid], pairs[n_valid:]

    args.out.mkdir(parents=True, exist_ok=True)
    for split, rows in (("train", train), ("valid", valid)):
        path = args.out / f"{split}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        print(f"wrote {len(rows):5d} examples -> {path}")
    print(f"skills={len(skills)} total_examples={len(pairs)}")


if __name__ == "__main__":
    main()
