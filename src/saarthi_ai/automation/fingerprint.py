"""Target technology fingerprinting and AI-selected nuclei template tags.

The autonomous loop uses this to "analyze the target's tech stack, then run only
the matching nuclei templates" instead of the whole template set. Two layers of
containment keep it safe:

* the detected technologies come from Saarthi's own recon evidence (Phase 3C
  httpx tech-detection), read back with sha256 verification and scope-filtered;
* the model may only pick from a FIXED vocabulary of well-known, non-intrusive
  nuclei tags (``ALLOWED_NUCLEI_TAGS``). Anything it returns is intersected with
  the deterministic candidate set, so it can never inject an arbitrary tag or
  argument. The dangerous-tag exclusion in the nuclei adapter still applies on
  top of whatever is selected.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from saarthi_ai.llm.ollama_client import SaarthiOllamaClient
from saarthi_ai.persistence.database import SaarthiDatabase
from saarthi_ai.persistence.models import EvidenceType
from saarthi_ai.schemas.chat import Message

MAX_TECHNOLOGIES = 40
MAX_HTTP_INTEL_EVIDENCE_BYTES = 10 * 1024 * 1024
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")

# Fixed vocabulary of well-known, detection-oriented (non-intrusive) nuclei
# tags. The model can only ever select from this set. Deliberately excludes
# aggressive tags (fuzz, brute-force, dos, intrusive) — those also stay in the
# adapter's DANGEROUS_NUCLEI_TAGS exclusion regardless.
ALLOWED_NUCLEI_TAGS: frozenset[str] = frozenset(
    {
        "cve", "tech", "misconfig", "exposure", "exposures", "config",
        "default-login", "takeover", "ssl", "tls", "panel", "login",
        "wordpress", "wp-plugin", "wp-theme", "joomla", "drupal", "magento",
        "typo3", "ghost", "cms",
        "php", "laravel", "symfony", "codeigniter",
        "aspnet", "asp", "dotnet", "iis",
        "java", "spring", "struts", "tomcat", "jboss", "weblogic", "websphere",
        "nodejs", "express", "django", "flask", "python", "ruby", "rails",
        "nginx", "apache", "apache-httpd", "openresty", "caddy", "haproxy",
        "jira", "confluence", "jenkins", "gitlab", "gitea", "bitbucket",
        "grafana", "kibana", "elastic", "elasticsearch", "kubernetes", "docker",
        "graphql", "swagger", "openapi", "api", "jetty", "coldfusion",
        "phpmyadmin", "adminer", "citrix", "fortinet", "vpn",
        "cloudflare", "aws", "azure", "gcp", "firebase", "wordpress-plugin",
    }
)

# Lowercase technology-name substring -> nuclei tags. Matched against each
# detected technology / webserver / CPE string. Kept conservative and generic.
_TECH_TAG_MAP: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("wordpress", ("wordpress", "wp-plugin", "cms")),
    ("woocommerce", ("wordpress", "wp-plugin")),
    ("joomla", ("joomla", "cms")),
    ("drupal", ("drupal", "cms")),
    ("magento", ("magento", "cms")),
    ("typo3", ("typo3", "cms")),
    ("ghost", ("ghost", "cms")),
    ("laravel", ("laravel", "php")),
    ("symfony", ("symfony", "php")),
    ("codeigniter", ("codeigniter", "php")),
    ("php", ("php",)),
    ("asp.net", ("aspnet", "dotnet")),
    ("aspnet", ("aspnet", "dotnet")),
    (".net", ("dotnet",)),
    ("iis", ("iis",)),
    ("microsoft-iis", ("iis",)),
    ("tomcat", ("tomcat", "java")),
    ("jboss", ("jboss", "java")),
    ("weblogic", ("weblogic", "java")),
    ("websphere", ("websphere", "java")),
    ("spring", ("spring", "java")),
    ("struts", ("struts", "java")),
    ("java", ("java",)),
    ("express", ("express", "nodejs")),
    ("node.js", ("nodejs",)),
    ("nodejs", ("nodejs",)),
    ("django", ("django", "python")),
    ("flask", ("flask", "python")),
    ("python", ("python",)),
    ("ruby on rails", ("rails", "ruby")),
    ("rails", ("rails", "ruby")),
    ("nginx", ("nginx",)),
    ("openresty", ("openresty", "nginx")),
    ("apache", ("apache",)),
    ("httpd", ("apache",)),
    ("caddy", ("caddy",)),
    ("haproxy", ("haproxy",)),
    ("jira", ("jira",)),
    ("confluence", ("confluence",)),
    ("jenkins", ("jenkins",)),
    ("gitlab", ("gitlab",)),
    ("gitea", ("gitea",)),
    ("grafana", ("grafana",)),
    ("kibana", ("kibana",)),
    ("elasticsearch", ("elasticsearch", "elastic")),
    ("kubernetes", ("kubernetes",)),
    ("docker", ("docker",)),
    ("graphql", ("graphql", "api")),
    ("swagger", ("swagger", "openapi", "api")),
    ("phpmyadmin", ("phpmyadmin",)),
    ("adminer", ("adminer",)),
    ("coldfusion", ("coldfusion",)),
    ("citrix", ("citrix",)),
    ("fortinet", ("fortinet", "vpn")),
    ("cloudflare", ("cloudflare",)),
)


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def _read_verified_json(path: str, expected_sha256: str | None) -> dict | None:
    """Read one bounded, sha256-verified evidence JSON object."""

    try:
        file_path = Path(path).expanduser()
        if not file_path.is_file():
            return None
        if file_path.stat().st_size > MAX_HTTP_INTEL_EVIDENCE_BYTES:
            return None
        content = file_path.read_bytes()
    except OSError:
        return None

    if expected_sha256:
        if hashlib.sha256(content).hexdigest().lower() != expected_sha256.strip().lower():
            return None

    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def detect_target_technologies(
    database: SaarthiDatabase,
    *,
    orchestration_id: str | None,
    allowed_hosts: tuple[str, ...],
) -> tuple[str, ...]:
    """Return technologies observed on in-scope hosts for this orchestration.

    Reads Phase 3C HTTP-intelligence evidence (httpx tech-detection), verifies
    each file's sha256, and collects ``technologies``, ``webserver`` and CPE
    strings for records whose host is inside ``allowed_hosts``. Best-effort:
    returns an empty tuple when nothing is available.
    """

    if not orchestration_id:
        return ()

    allowed = {_normalize_host(host) for host in allowed_hosts if host.strip()}
    found: dict[str, None] = {}  # ordered set

    for execution in database.list_executions(limit=1_000):
        metadata = execution.metadata or {}
        if metadata.get("orchestration_id") != orchestration_id:
            continue
        for evidence in database.list_evidence(
            execution.execution_id,
            evidence_type=EvidenceType.HTTP_INTELLIGENCE_RESULT,
        ):
            payload = _read_verified_json(evidence.path, evidence.sha256)
            if payload is None:
                continue
            records = payload.get("records")
            if not isinstance(records, list):
                continue
            for record in records:
                if not isinstance(record, dict):
                    continue
                host = _normalize_host(str(record.get("host", "")))
                if allowed and host not in allowed:
                    continue
                values: list[str] = []
                techs = record.get("technologies")
                if isinstance(techs, list):
                    values.extend(str(item) for item in techs)
                if isinstance(record.get("webserver"), str):
                    values.append(record["webserver"])
                cpes = record.get("cpes")
                if isinstance(cpes, list):
                    values.extend(str(item) for item in cpes)
                for value in values:
                    cleaned = value.strip()
                    if cleaned:
                        found.setdefault(cleaned, None)
                        if len(found) >= MAX_TECHNOLOGIES:
                            return tuple(found)

    return tuple(found)


def map_technologies_to_nuclei_tags(technologies: tuple[str, ...]) -> tuple[str, ...]:
    """Deterministically map detected technologies to safe nuclei tags."""

    tags: dict[str, None] = {}
    for technology in technologies:
        lowered = technology.lower()
        for needle, mapped in _TECH_TAG_MAP:
            if needle in lowered:
                for tag in mapped:
                    if tag in ALLOWED_NUCLEI_TAGS:
                        tags.setdefault(tag, None)

    if not tags:
        return ()

    # Always add generic high-signal, non-intrusive tags so a targeted run
    # still catches version CVEs and misconfigurations for the detected stack.
    for generic in ("cve", "misconfig", "exposure"):
        tags.setdefault(generic, None)

    return tuple(sorted(tags))


def valid_nuclei_tags(tags: tuple[str, ...]) -> tuple[str, ...]:
    """Keep only well-formed tags that are inside the allowed vocabulary."""

    return tuple(
        tag
        for tag in tags
        if isinstance(tag, str)
        and _TAG_RE.match(tag)
        and tag in ALLOWED_NUCLEI_TAGS
    )


NUCLEI_TAG_SELECT_SYSTEM_PROMPT = (
    "You are selecting nuclei template TAGS for an AUTHORIZED VAPT scan. You are "
    "given the target's detected technologies and a NUMBERED list of candidate "
    "tags. Choose the subset most relevant to the detected stack so the scan is "
    "focused. You may ONLY reference the given indices — never invent a tag. "
    'Reply with a JSON array of integers, e.g. [0,2,3]. No prose.'
)


def _parse_indices(content: str, count: int) -> list[int]:
    text = content.strip()
    start, end = text.find("["), text.rfind("]")
    if start == -1 or end == -1 or end <= start:
        return []
    try:
        raw = json.loads(text[start : end + 1])
    except (ValueError, TypeError):
        return []
    out: list[int] = []
    seen: set[int] = set()
    for item in raw if isinstance(raw, list) else []:
        if isinstance(item, bool):
            continue
        if isinstance(item, int) and 0 <= item < count and item not in seen:
            seen.add(item)
            out.append(item)
    return out


async def select_nuclei_tags(
    client: SaarthiOllamaClient,
    technologies: tuple[str, ...],
    candidate_tags: tuple[str, ...],
    *,
    num_predict: int = 160,
) -> tuple[str, ...]:
    """Let the model pick a subset of the candidate tags for this target.

    The result is always intersected with ``candidate_tags`` (already inside the
    allowed vocabulary), so the model can never widen scope or inject a tag. Any
    failure falls back to the full deterministic candidate set.
    """

    safe_candidates = valid_nuclei_tags(candidate_tags)
    if not safe_candidates:
        return ()

    menu = "\n".join(f"{index}. {tag}" for index, tag in enumerate(safe_candidates))
    tech_line = ", ".join(technologies[:MAX_TECHNOLOGIES]) or "(none detected)"
    prompt = (
        f"Detected technologies: {tech_line}\n\n"
        f"Candidate nuclei tags:\n{menu}\n\n"
        "Select the relevant tag indices as a JSON array."
    )
    try:
        content, _ = await client.chat(
            [Message(role="user", content=prompt)],
            system_prompt=NUCLEI_TAG_SELECT_SYSTEM_PROMPT,
            num_predict=num_predict,
            use_skills=False,
        )
    except Exception:
        return safe_candidates

    indices = _parse_indices(content, len(safe_candidates))
    chosen = tuple(safe_candidates[index] for index in indices)
    # Empty / unparseable selection -> keep the full deterministic set.
    return chosen or safe_candidates
