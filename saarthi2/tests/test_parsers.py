"""SARIF/nuclei parsing, CDN/WAF classification, and extractors."""

from __future__ import annotations

import json

from saarthi2.parsers import (
    classify_cdn_waf,
    extract_hosts,
    extract_ips,
    extract_urls,
    parse_nuclei_jsonl,
    parse_sarif,
)

_SARIF = json.dumps(
    {
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep"}},
                "results": [
                    {
                        "ruleId": "python.lang.security.audit",
                        "level": "error",
                        "message": {"text": "eval used"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}
                        ],
                    }
                ],
            }
        ]
    }
)


def test_parse_sarif() -> None:
    findings = parse_sarif(_SARIF)
    assert len(findings) == 1
    f = findings[0]
    assert f["tool"] == "semgrep"
    assert f["severity"] == "high"
    assert f["location"] == "app.py"
    assert f["rule_id"].startswith("python.lang")


def test_parse_sarif_bad_input() -> None:
    assert parse_sarif("not json") == []


def test_parse_nuclei_jsonl() -> None:
    line = json.dumps(
        {"template-id": "CVE-2021-1", "info": {"severity": "critical", "name": "RCE"},
         "matched-at": "https://x/a"}
    )
    findings = parse_nuclei_jsonl(line + "\n\ngarbage\n")
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical"
    assert findings[0]["rule_id"] == "CVE-2021-1"


def test_classify_cdn_waf() -> None:
    result = classify_cdn_waf({"Server": "cloudflare", "CF-RAY": "abc"})
    assert "cloudflare" in result["cdn"]
    assert "cloudflare" in result["waf"]
    assert classify_cdn_waf({"Server": "nginx"}) == {"cdn": [], "waf": []}


def test_extractors() -> None:
    text = "http://a.com/x\nhttps://b.com/y\n10.0.0.1 and 8.8.8.8\n"
    assert extract_ips(text) == ["10.0.0.1", "8.8.8.8"]
    assert extract_urls(text) == ["http://a.com/x", "https://b.com/y"]
    assert extract_hosts(text) == ["a.com", "b.com"]
