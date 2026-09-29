"""VERIFY — the ORACLE. Deterministic code, NO LLM. Suspected -> confirmed.

A finding is promoted to ``confirmed`` only by reproducible, mechanical evidence:

    sqli_boolean       stable content/status differential (TRUE vs FALSE) across
                       >=2 retries, after neutralizing payload reflection
    sqli_error         a SQL error appears WITH the quote and not at baseline
    sqli_time / cmd    injected delay reproduces across >=2 trials AND scales with
                       the requested sleep; rejected if the baseline is noisy
    reflected_xss      payload reflects AND actually EXECUTES (a headless-browser
                       marker fired) — never on reflection alone
    idor_bola          a neighbour id returns different, data-bearing, non-denied
                       content the endpoint treats as a distinct object
    open_redirect      the redirect Location resolves to the attacker host
    ssrf/blind         an OOB callback carrying the minted token arrived

The oracle NEVER confirms on the model's word. If it cannot prove a class
(no browser, no OOB collector, non-numeric id, …) the finding stays suspected.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from statistics import median
from typing import Any
from urllib.parse import quote, quote_plus, urlsplit

from saarthi2.vulnengine import signals as sig
from saarthi2.vulnengine.http import HttpSender
from saarthi2.vulnengine.models import InputSurface, TestTask
from saarthi2.vulnengine.payloads import PreparedPayload
from saarthi2.vulnengine.probe import send_payload

_DENIED_RE = re.compile(
    r"(please log ?in|login required|access denied|unauthori[sz]ed|forbidden|"
    r"not permitted|sign in to continue|session expired)",
    re.IGNORECASE,
)
_WS_RE = re.compile(r"\s+")
_MIN_DATA_LEN = 32
# A boolean-SQLi differential must exceed this many characters (after neutralizing
# reflection) to count. Two near-identical TRUE/FALSE payloads reflected back differ
# by only a few chars; a real row-set differential is far larger. This is what keeps
# a merely-reflective (but safe) parameter from being confirmed as SQLi.
_MIN_BOOL_DIFF = 24


@dataclass
class Verdict:
    """The oracle's decision for one task."""

    confirmed: bool = False
    suspected: bool = False
    technique: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    reason: str = ""


def _normalize(body: str, drop: list[str]) -> str:
    """Neutralize payload reflection + whitespace so a diff reflects real state.

    Each dropped token is removed in its raw, HTML-escaped, and URL-encoded forms,
    so an app that merely echoes the (differing) payloads — encoded or not — does
    not read as a state differential.
    """

    out = body or ""
    for token in drop:
        if not token:
            continue
        for variant in (token, html.escape(token), quote(token, safe=""), quote_plus(token)):
            out = out.replace(variant, "")
    return _WS_RE.sub(" ", out).strip()


def _looks_denied(body: str) -> bool:
    return bool(_DENIED_RE.search(body or ""))


def _looks_data(body: str) -> bool:
    return len((body or "").strip()) >= _MIN_DATA_LEN


def _redirect_host_matches(location: str, host: str) -> bool:
    if not location:
        return False
    loc = location.strip().replace("\\", "/")
    if loc.startswith("//"):
        loc = "http:" + loc
    parsed = urlsplit(loc)
    return (parsed.hostname or "").lower() == host.lower()


async def _verify_boolean(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
    *, trials: int = 2,
) -> Verdict:
    tv, fv = payload.values.get("true", ""), payload.values.get("false", "")
    true_sigs: list[tuple[int, str]] = []
    false_sigs: list[tuple[int, str]] = []
    for _ in range(max(2, trials)):
        rt = await send_payload(sender, surface, task.param, tv, allow_redirects=True)
        rf = await send_payload(sender, surface, task.param, fv, allow_redirects=True)
        true_sigs.append((rt.status_code, _normalize(rt.text, [tv, fv])))
        false_sigs.append((rf.status_code, _normalize(rf.text, [tv, fv])))

    stable_true = len(set(true_sigs)) == 1
    stable_false = len(set(false_sigs)) == 1
    true_status, true_body = true_sigs[0]
    false_status, false_body = false_sigs[0]
    differ = true_sigs[0] != false_sigs[0]
    # A real differential is either a status change or a body change too large to be
    # explained by reflecting the (tiny, near-identical) payloads.
    significant = (true_status != false_status) or (
        abs(len(true_body) - len(false_body)) >= _MIN_BOOL_DIFF
    )
    confirmed = stable_true and stable_false and differ and significant
    evidence = {
        "true_status": true_status,
        "false_status": false_status,
        "true_len": len(true_body),
        "false_len": len(false_body),
        "stable": stable_true and stable_false,
        "significant": significant,
        "trials": len(true_sigs),
    }
    return Verdict(
        confirmed=confirmed,
        suspected=differ and significant,
        technique="sqli_boolean",
        evidence=evidence,
    )


async def _verify_error(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
) -> Verdict:
    inj = await send_payload(sender, surface, task.param, payload.values.get("value", "1'"))
    base = await send_payload(sender, surface, task.param, "1")
    inj_err = sig.detect_sql_error(inj.text)
    base_err = sig.detect_sql_error(base.text)
    confirmed = inj_err and not base_err
    return Verdict(
        confirmed=confirmed,
        suspected=inj_err,
        technique="sqli_error",
        evidence={"injected_error": inj_err, "baseline_error": base_err, "status": inj.status_code},
    )


async def _verify_time(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
    *, technique: str,
) -> Verdict:
    from saarthi2.vulnengine.payloads import _fill

    base_sleep = int(payload.values.get("sleep", 5))
    template = payload.values.get("template", "")
    margin_ms = base_sleep * 1000 * 0.6

    base_times = []
    for _ in range(3):
        r = await send_payload(sender, surface, task.param, "1", allow_redirects=True)
        base_times.append(r.elapsed_ms)
    baseline = median(base_times)
    if (max(base_times) - min(base_times)) > base_sleep * 1000 * 0.5:
        return Verdict(suspected=False, technique=technique, reason="noisy baseline")

    val1 = _fill(template, sleep=base_sleep) if template else payload.values.get("value", "")
    t1 = []
    for _ in range(2):
        r = await send_payload(sender, surface, task.param, val1, allow_redirects=True)
        t1.append(r.elapsed_ms)
    reproduces = all(x >= baseline + margin_ms for x in t1)
    suspected = median(t1) >= baseline + margin_ms

    confirmed = False
    scales = False
    inj2 = None
    if suspected and template:
        val2 = _fill(template, sleep=base_sleep * 2)
        r2 = await send_payload(sender, surface, task.param, val2, allow_redirects=True)
        inj2 = r2.elapsed_ms
        scales = inj2 >= median(t1) + margin_ms
        confirmed = reproduces and scales
    return Verdict(
        confirmed=confirmed,
        suspected=suspected,
        technique=technique,
        evidence={
            "baseline_ms": int(baseline),
            "sleep_s": base_sleep,
            "injected_ms": int(median(t1)),
            "injected_2x_ms": int(inj2) if inj2 is not None else None,
            "reproduces": reproduces,
            "scales": scales,
        },
    )


async def _verify_reflect(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
    *, browser: Any,
) -> Verdict:
    value = payload.values.get("value", "")
    marker = payload.values.get("marker", "")
    r = await send_payload(sender, surface, task.param, value, allow_redirects=True)
    reflected = bool(value) and value in r.text
    evidence = {"reflected": reflected, "marker": marker, "status": r.status_code}
    if not reflected:
        return Verdict(
            confirmed=False, suspected=False, technique="reflected_xss", evidence=evidence
        )
    executed = False
    if browser is not None:
        try:
            executed = bool(await browser(surface, task.param, value, marker))
        except Exception as exc:  # a browser failure must not crash the run
            evidence["browser_error"] = str(exc)
            executed = False
    evidence["executed"] = executed
    return Verdict(
        confirmed=executed,
        suspected=reflected,
        technique="reflected_xss",
        evidence=evidence,
        reason="" if browser is not None else "no headless browser — reflection only",
    )


async def _verify_redirect(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
) -> Verdict:
    value = payload.values.get("value", "")
    host = payload.values.get("host", "")
    r = await send_payload(sender, surface, task.param, value, allow_redirects=False)
    location = r.header("location")
    confirmed = 300 <= r.status_code < 400 and _redirect_host_matches(location, host)
    return Verdict(
        confirmed=confirmed,
        suspected=bool(location) and host in location,
        technique="open_redirect",
        evidence={"status": r.status_code, "location": location, "attacker_host": host},
    )


async def _verify_path_read(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
) -> Verdict:
    value = payload.values.get("value", "")
    signature = payload.values.get("signature") or r"root:.*:0:0:"
    r = await send_payload(sender, surface, task.param, value, allow_redirects=True)
    match = re.search(signature, r.text)
    return Verdict(
        confirmed=bool(match),
        suspected=bool(match),
        technique="lfi",
        evidence={
            "signature": signature,
            "match": match.group(0)[:120] if match else "",
            "status": r.status_code,
        },
    )


async def _verify_idor(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
) -> Verdict:
    if task.param is None:
        return Verdict(technique="idor_bola", reason="no id parameter")
    own_val = str(surface.example_values.get(task.param, "1")).strip()
    if not own_val.isdigit():
        return Verdict(technique="idor_bola", reason="non-numeric id")
    own = int(own_val)
    own_r = await send_payload(sender, surface, task.param, str(own), allow_redirects=True)
    if own_r.status_code != 200 or not _looks_data(own_r.text):
        return Verdict(technique="idor_bola", reason="own object not readable")
    own_norm = _normalize(own_r.text, [str(own)])

    # An id far out of range: if it returns the SAME body as a neighbour, the
    # endpoint isn't object-specific (static template / reflection) — not IDOR.
    invalid = await send_payload(
        sender, surface, task.param, str(own + 100000), allow_redirects=True
    )
    invalid_norm = _normalize(invalid.text, [str(own + 100000)])

    for off in payload.values.get("offsets", [1, -1]):
        nid = own + int(off)
        if nid < 0 or nid == own:
            continue
        nr = await send_payload(sender, surface, task.param, str(nid), allow_redirects=True)
        n_norm = _normalize(nr.text, [str(nid)])
        if (
            nr.status_code == 200
            and _looks_data(nr.text)
            and not _looks_denied(nr.text)
            and n_norm != own_norm
            and n_norm != invalid_norm
        ):
            return Verdict(
                confirmed=True,
                suspected=True,
                technique="idor_bola",
                evidence={
                    "own_id": own,
                    "neighbor_id": nid,
                    "own_status": own_r.status_code,
                    "neighbor_status": nr.status_code,
                },
            )
    return Verdict(suspected=False, technique="idor_bola")


async def _verify_oob(
    sender: HttpSender, surface: InputSurface, task: TestTask, payload: PreparedPayload,
    *, oob_check: Any,
) -> Verdict:
    value = payload.values.get("value", "")
    token = payload.values.get("oob", "")
    await send_payload(sender, surface, task.param, value, allow_redirects=True)
    if oob_check is None:
        return Verdict(
            suspected=True, technique="ssrf",
            reason="no OOB collector configured — cannot confirm blind class",
        )
    try:
        arrived = bool(await oob_check(token))
    except Exception:
        arrived = False
    return Verdict(
        confirmed=arrived, suspected=True, technique="ssrf",
        evidence={"oob": token, "callback": arrived},
    )


async def verify(
    task: TestTask,
    surface: InputSurface,
    sender: HttpSender,
    prepared: list[PreparedPayload],
    *,
    browser: Any = None,
    oob_check: Any = None,
) -> Verdict:
    """Run the deterministic verifier(s) for a task; return the strongest verdict.

    Returns the first CONFIRMED verdict; otherwise the best suspected one; else a
    clean not-found verdict. The model is never consulted here.
    """

    best = Verdict(technique=task.vuln_class)
    for payload in prepared:
        technique = payload.technique
        if technique == "boolean" and task.vuln_class == "auth_bypass":
            # A login-success oracle is target-specific; do not auto-confirm.
            verdict = Verdict(suspected=True, technique="auth_bypass",
                              reason="auth-bypass needs a success oracle — not auto-confirmed")
        elif technique == "boolean":
            verdict = await _verify_boolean(sender, surface, task, payload)
        elif technique == "error":
            verdict = await _verify_error(sender, surface, task, payload)
        elif technique == "time":
            verdict = await _verify_time(sender, surface, task, payload, technique="sqli_time")
        elif technique == "cmd_time":
            verdict = await _verify_time(
                sender, surface, task, payload, technique="command_injection"
            )
        elif technique in ("reflect",):
            verdict = await _verify_reflect(sender, surface, task, payload, browser=browser)
        elif technique == "store":
            r = await send_payload(sender, surface, task.param, payload.values.get("value", ""))
            reflected = payload.values.get("value", "") in r.text
            verdict = Verdict(suspected=reflected, technique="stored_xss",
                              reason="stored-xss confirmation needs a rendered view")
        elif technique == "path_read":
            verdict = await _verify_path_read(sender, surface, task, payload)
        elif technique == "redirect":
            verdict = await _verify_redirect(sender, surface, task, payload)
        elif technique == "idor":
            verdict = await _verify_idor(sender, surface, task, payload)
        elif technique == "oob":
            verdict = await _verify_oob(sender, surface, task, payload, oob_check=oob_check)
        else:
            continue

        if verdict.confirmed:
            return verdict
        if verdict.suspected and not best.suspected:
            best = verdict
    return best
