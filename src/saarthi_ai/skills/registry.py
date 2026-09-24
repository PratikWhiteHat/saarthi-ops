"""Pinned third-party skill catalog; content is advisory data, never executable policy."""

from __future__ import annotations

import io
import json
import os
import re
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from saarthi_ai.config import skills_dir

SOURCE_COMMIT = "4d7b4cdfddb7ec67fba87821e54c768248a544bd"
SOURCE_URL = "https://github.com/elementalsouls/Claude-BugHunter"
ARCHIVE_URL = f"https://codeload.github.com/elementalsouls/Claude-BugHunter/tar.gz/{SOURCE_COMMIT}"
CONTENT_LICENSE_URL = f"{SOURCE_URL}/blob/{SOURCE_COMMIT}/LICENSE-CONTENT"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_MARKDOWN_BYTES = 200 * 1024
MAX_TOTAL_MARKDOWN_BYTES = 6 * 1024 * 1024
MAX_SKILLS_PER_PROMPT = 3
MAX_SKILL_CONTEXT_CHARS = 7_500

SKILL_IDS = (
    "apk-redteam-pipeline", "bb-local-toolkit", "bb-methodology", "bug-bounty",
    "bugcrowd-reporting", "cloud-iam-deep", "enterprise-vpn-attack", "evidence-hygiene",
    "hunt-api-misconfig", "hunt-aspnet", "hunt-ato", "hunt-auth-bypass",
    "hunt-brute-force", "hunt-business-logic", "hunt-cache-poison", "hunt-captcha-bypass",
    "hunt-cicd", "hunt-clickjacking", "hunt-cloud-misconfig", "hunt-cors",
    "hunt-csrf", "hunt-deserialization", "hunt-dispatch", "hunt-dom",
    "hunt-exceptional-conditions", "hunt-file-upload", "hunt-fintech-graphql",
    "hunt-forgot-password", "hunt-graphql", "hunt-grpc", "hunt-host-header",
    "hunt-html-injection", "hunt-http-smuggling", "hunt-idor", "hunt-jwt-crypto",
    "hunt-k8s", "hunt-laravel", "hunt-ldap", "hunt-lfi", "hunt-llm-ai",
    "hunt-mfa-bypass", "hunt-misc", "hunt-nextjs", "hunt-nodejs", "hunt-nosqli",
    "hunt-ntlm-info", "hunt-oauth", "hunt-open-redirect", "hunt-race-condition",
    "hunt-rag-vector", "hunt-rce", "hunt-saml", "hunt-session", "hunt-shadow-api",
    "hunt-sharepoint", "hunt-source-leak", "hunt-spa-api", "hunt-springboot",
    "hunt-sqli", "hunt-ssrf", "hunt-ssti", "hunt-subdomain", "hunt-tls-network",
    "hunt-websocket", "hunt-xss", "hunt-xxe", "ios-redteam-pipeline",
    "m365-entra-attack", "meme-coin-audit", "mid-engagement-ir-detection",
    "offensive-osint", "okta-attack", "osint-methodology", "recon-scope-triage",
    "redteam-mindset", "redteam-report-template", "report-writing", "security-arsenal",
    "supply-chain-attack-recon", "triage-validation", "vmware-vcenter-attack",
    "web2-recon", "web3-audit",
)
_SKILL_SET = frozenset(SKILL_IDS)
_WORD = re.compile(r"[a-z0-9]+")
_FENCE = re.compile(r"(?ms)^```.*?^```\s*$")
_HEADING = re.compile(r"(?m)^#{1,3}\s+(.+)$")
_UNSAFE_HEADING = re.compile(
    r"payload|exploit|bypass|step.by.step|autonomous|command|attack.chain|"
    r"proof.of.concept|poc|tool.invocation", re.IGNORECASE,
)
_ALIASES = {
    "hunt-sqli": ("sql injection", "sqli", "sqlmap"),
    "hunt-xss": ("cross site scripting", "xss", "xsstrike"),
    "hunt-nosqli": ("nosql", "mongodb injection"),
    "hunt-ssrf": ("server side request forgery", "ssrf"),
    "hunt-idor": ("insecure direct object reference", "idor", "bola"),
    "hunt-csrf": ("cross site request forgery", "csrf"),
    "hunt-cors": ("cross origin resource sharing", "cors"),
    "hunt-lfi": ("local file inclusion", "lfi"),
    "hunt-xxe": ("xml external entity", "xxe"),
    "hunt-ssti": ("server side template injection", "ssti"),
    "hunt-file-upload": ("file upload", "multipart"),
    "hunt-auth-bypass": ("authentication bypass", "auth bypass"),
    "hunt-graphql": ("graphql",),
    "hunt-oauth": ("oauth", "openid connect", "oidc"),
    "hunt-jwt-crypto": ("jwt", "json web token"),
    "hunt-clickjacking": ("clickjacking", "frame ancestor"),
    "hunt-subdomain": ("subdomain", "dns enumeration"),
    "web2-recon": ("reconnaissance", "web recon"),
    "evidence-hygiene": ("evidence", "redaction", "provenance"),
    "triage-validation": ("triage", "validation", "false positive"),
    "report-writing": ("report", "remediation"),
}
_STOP_WORDS = frozenset({
    "hunt", "attack", "redteam", "security", "skill", "for", "with", "from",
    "that", "this", "the", "and", "web", "app", "analysis", "target", "phase",
})


class SkillImportError(RuntimeError):
    """Raised when the pinned source archive cannot be safely imported."""


@dataclass(frozen=True)
class SkillRecord:
    skill_id: str
    installed: bool
    enabled: bool
    description: str


def _words(value: str) -> set[str]:
    return {
        word for word in _WORD.findall(value.lower())
        if word not in _STOP_WORDS and len(word) > 2
    }


def _description(content: str) -> str:
    if not content.startswith("---\n"):
        return ""
    end = content.find("\n---", 4)
    if end < 0:
        return ""
    for line in content[4:end].splitlines():
        if line.startswith("description:"):
            return line.partition(":")[2].strip().strip('"\'')[:350]
    return ""


def _reference_excerpt(content: str, query: str, *, limit: int = 2_200) -> str:
    """Keep evidence-analysis guidance; never inject fenced payloads or full recipes."""

    body = content.split("\n---", 1)[-1] if content.startswith("---\n") else content
    body = _FENCE.sub("", body)
    sections = _HEADING.split(body)
    query_words = _words(query)
    ranked: list[tuple[int, str]] = []
    for index in range(1, len(sections), 2):
        heading = sections[index].strip()
        if _UNSAFE_HEADING.search(heading):
            continue
        section = sections[index + 1].strip() if index + 1 < len(sections) else ""
        if not section:
            continue
        score = 3 * len(_words(heading) & query_words) + len(_words(section[:1200]) & query_words)
        ranked.append((score, f"## {heading}\n{section}"))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return "\n\n".join(section[:1100] for _, section in ranked[:2])[:limit]


class SkillStore:
    """Persist toggles locally and select bounded skill references for analysis."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or skills_dir()

    @property
    def bundle_dir(self) -> Path:
        return self.root / SOURCE_COMMIT / "skills"

    @property
    def state_path(self) -> Path:
        return self.root / "enabled.json"

    def skill_path(self, skill_id: str) -> Path:
        if skill_id not in _SKILL_SET:
            raise ValueError(f"Unknown skill: {skill_id}")
        return self.bundle_dir / skill_id / "SKILL.md"

    def enabled_ids(self) -> set[str]:
        if not self.state_path.is_file():
            return set()
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return set()
        values = data.get("enabled", []) if isinstance(data, dict) else []
        return {value for value in values if isinstance(value, str)} & _SKILL_SET if isinstance(
            values, list
        ) else set()

    def list_skills(self) -> list[SkillRecord]:
        enabled = self.enabled_ids()
        records = []
        for skill_id in SKILL_IDS:
            path = self.skill_path(skill_id)
            installed = path.is_file() and not path.is_symlink()
            description = ""
            if installed:
                try:
                    description = _description(path.read_text(encoding="utf-8")[:10000])
                except (OSError, UnicodeError):
                    installed = False
            records.append(SkillRecord(skill_id, installed, skill_id in enabled, description))
        return records

    def set_enabled(self, skill_id: str, enabled: bool) -> None:
        path = self.skill_path(skill_id)
        if not path.is_file() or path.is_symlink():
            raise ValueError("Import the skill bundle before enabling skills.")
        selected = self.enabled_ids()
        if enabled:
            selected.add(skill_id)
        else:
            selected.discard(skill_id)
        self.root.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=self.root, delete=False,
        ) as handle:
            temporary = Path(handle.name)
            json.dump({"source_commit": SOURCE_COMMIT, "enabled": sorted(selected)}, handle)
            handle.write("\n")
        os.replace(temporary, self.state_path)

    def install_pinned_bundle(self) -> int:
        """Download markdown-only skill references from a fixed upstream commit."""

        payload = bytearray()
        with httpx.Client(timeout=60, follow_redirects=False) as client:
            with client.stream("GET", ARCHIVE_URL) as response:
                response.raise_for_status()
                for chunk in response.iter_bytes():
                    payload.extend(chunk)
                    if len(payload) > MAX_ARCHIVE_BYTES:
                        raise SkillImportError("Skill archive exceeds 10 MiB.")
        files: dict[tuple[str, ...], bytes] = {}
        total = 0
        try:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                for member in archive:
                    parts = Path(member.name).parts
                    if len(parts) < 4 or parts[1] != "skills" or parts[2] not in _SKILL_SET:
                        continue
                    if not member.isfile() or member.name.endswith(".py"):
                        continue
                    relative = parts[2:]
                    if not relative[-1].endswith(".md") or any(
                        part in {".", ".."} for part in relative
                    ):
                        continue
                    if member.size > MAX_MARKDOWN_BYTES:
                        raise SkillImportError("A skill document exceeds the per-file limit.")
                    content_file = archive.extractfile(member)
                    if content_file is None:
                        raise SkillImportError("A skill document could not be read.")
                    content = content_file.read(MAX_MARKDOWN_BYTES + 1)
                    if len(content) != member.size:
                        raise SkillImportError("A skill document is incomplete.")
                    content.decode("utf-8")
                    files[relative] = content
                    total += len(content)
                    if total > MAX_TOTAL_MARKDOWN_BYTES:
                        raise SkillImportError("Skill markdown exceeds the total size limit.")
        except (tarfile.TarError, UnicodeError) as exc:
            raise SkillImportError("Invalid skill archive or non-UTF-8 content.") from exc
        found = {parts[0] for parts in files if parts[-1] == "SKILL.md"}
        if found != _SKILL_SET:
            raise SkillImportError(f"Expected {len(_SKILL_SET)} skills; found {len(found)}.")
        for parts, content in files.items():
            destination = self.bundle_dir.joinpath(*parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
        attribution = self.root / SOURCE_COMMIT / "ATTRIBUTION.txt"
        attribution.write_text(
            "Claude-BugHunter skill documentation by Sachin Sharma and contributors.\n"
            f"Source: {SOURCE_URL}/tree/{SOURCE_COMMIT}/skills\n"
            f"Content license: CC BY 4.0 ({CONTENT_LICENSE_URL})\n"
            "Imported unchanged as local analysis references; no scripts are installed.\n",
            encoding="utf-8",
        )
        return len(found)

    def context_for(self, messages: object) -> str:
        """Return topic-matched excerpts; disabled skills never reach the model."""

        _selected_ids, context = self.context_selection_for(messages)
        return context

    def context_selection_for(self, messages: object) -> tuple[tuple[str, ...], str]:
        """Return the exact skill IDs and excerpts selected for one request."""

        enabled = self.enabled_ids()
        if not enabled:
            return (), ""
        query = "\n".join(
            str(getattr(message, "content", ""))[:12000]
            for message in messages  # type: ignore[union-attr]
        )[-24000:]
        query_lower = query.lower()
        query_words = _words(query)
        ranked: list[tuple[int, str, str]] = []
        for skill_id in enabled:
            path = self.skill_path(skill_id)
            if not path.is_file() or path.is_symlink():
                continue
            try:
                content = path.read_text(encoding="utf-8")[:MAX_MARKDOWN_BYTES]
            except (OSError, UnicodeError):
                continue
            description = _description(content)
            slug_words = _words(skill_id.replace("-", " "))
            score = 4 * len(slug_words & query_words)
            score += 8 * sum(alias in query_lower for alias in _ALIASES.get(skill_id, ()))
            if score == 0:
                continue
            score += min(3, len(_words(description) & query_words))
            ranked.append((score, skill_id, content))
        ranked.sort(key=lambda item: (-item[0], item[1]))
        excerpts = []
        selected_ids = []
        for _, skill_id, content in ranked[:MAX_SKILLS_PER_PROMPT]:
            excerpt = _reference_excerpt(content, query)
            description = _description(content)
            excerpts.append(f"[{skill_id}] {description}\n{excerpt}".strip())
            selected_ids.append(skill_id)
        context = "\n\n".join(excerpts)[:MAX_SKILL_CONTEXT_CHARS]
        included_ids = tuple(
            skill_id
            for skill_id in selected_ids
            if re.search(rf"(?m)^\[{re.escape(skill_id)}\]", context)
        )
        return included_ids, context
