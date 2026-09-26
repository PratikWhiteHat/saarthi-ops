"""Parse security-tool output into normalized findings + CDN/WAF classification."""

from __future__ import annotations

import json
import re

_SARIF_LEVEL = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def parse_sarif(text: str) -> list[dict]:
    """Parse SARIF JSON (Semgrep/Trivy/CodeQL) into normalized findings."""

    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return []
    findings: list[dict] = []
    for run in doc.get("runs", []) if isinstance(doc, dict) else []:
        tool = (
            run.get("tool", {}).get("driver", {}).get("name", "sarif")
            if isinstance(run, dict)
            else "sarif"
        )
        for result in run.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            level = str(result.get("level", "warning")).lower()
            message = ""
            if isinstance(result.get("message"), dict):
                message = str(result["message"].get("text", ""))
            location = ""
            locs = result.get("locations") or []
            if locs and isinstance(locs[0], dict):
                phys = locs[0].get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                location = str(art.get("uri", ""))
            findings.append(
                {
                    "tool": tool,
                    "rule_id": result.get("ruleId", ""),
                    "severity": _SARIF_LEVEL.get(level, "info"),
                    "message": message,
                    "location": location,
                }
            )
    return findings


def parse_nuclei_jsonl(text: str) -> list[dict]:
    """Parse nuclei -jsonl output into normalized findings."""

    findings: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = record.get("info", {}) or {}
        findings.append(
            {
                "tool": "nuclei",
                "rule_id": record.get("template-id") or record.get("templateID", ""),
                "severity": str(info.get("severity", "info")).lower(),
                "message": info.get("name", ""),
                "location": record.get("matched-at") or record.get("host", ""),
            }
        )
    return findings


# --- CDN / WAF classification ------------------------------------------------

# provider -> substrings that, if present in any header name/value, indicate it.
_CDN_SIGNATURES: dict[str, tuple[str, ...]] = {
    "cloudflare": ("cloudflare", "cf-ray", "__cfduid"),
    "akamai": ("akamai", "akamaighost", "x-akamai"),
    "fastly": ("fastly", "x-served-by", "x-fastly"),
    "cloudfront": ("cloudfront", "x-amz-cf-id"),
    "sucuri": ("sucuri", "x-sucuri-id"),
    "incapsula": ("incapsula", "x-iinfo", "visid_incap"),
    "azure-cdn": ("x-azure-ref", "x-msedge-ref"),
    "google": ("gws", "x-goog"),
}

_WAF_SIGNATURES: dict[str, tuple[str, ...]] = {
    "cloudflare": ("cloudflare", "cf-ray"),
    "aws-waf": ("awswaf", "x-amzn-waf"),
    "akamai-kona": ("akamai", "x-akamai-transformed"),
    "imperva-incapsula": ("incapsula", "x-iinfo"),
    "f5-big-ip": ("bigip", "x-waf", "ts01"),
    "sucuri": ("sucuri", "x-sucuri"),
    "wordfence": ("wordfence",),
    "modsecurity": ("mod_security", "modsecurity"),
}


def _match(signatures: dict[str, tuple[str, ...]], blob: str) -> list[str]:
    return sorted(
        provider
        for provider, needles in signatures.items()
        if any(needle in blob for needle in needles)
    )


def classify_cdn_waf(headers: dict, body: str = "") -> dict:
    """Classify CDN + WAF from response headers (+ optional body)."""

    blob = " ".join(f"{k}:{v}" for k, v in headers.items()).lower() + " " + body.lower()
    return {"cdn": _match(_CDN_SIGNATURES, blob), "waf": _match(_WAF_SIGNATURES, blob)}


# --- extraction helpers ------------------------------------------------------

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_HOST_RE = re.compile(r"https?://([^/\s:\"'<>]+)")


def extract_ips(text: str) -> list[str]:
    return sorted({m for m in _IP_RE.findall(text)})


def extract_urls(text: str) -> list[str]:
    return sorted(set(_URL_RE.findall(text)))


def extract_hosts(text: str) -> list[str]:
    hosts = set(_HOST_RE.findall(text))
    # also treat bare host lines as hosts
    for line in text.splitlines():
        line = line.strip()
        if line and "/" not in line and " " not in line and "." in line:
            hosts.add(line)
    return sorted(hosts)
