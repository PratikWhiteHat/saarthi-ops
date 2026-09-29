"""COMPREHEND — build a structured App Model from the authenticated crawl.

Grounding is the point: input surfaces and their signals are detected in CODE
(the crawl + light canary probes), never invented. The local 14B is used ONLY to
*classify* against those grounded signals — app type, tech stack, roles, feature
names — via Ollama structured output. If the model is unavailable the model-side
refinement is skipped and the deterministic App Model still stands, so the
pipeline never depends on the LLM to know the surface exists.
"""

from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import urlsplit

from saarthi2.vulnengine import signals as sig
from saarthi2.vulnengine.crawl import CrawlResult, RawSurface
from saarthi2.vulnengine.http import HttpSender
from saarthi2.vulnengine.models import AppModel, InputSurface, SurfaceType

# Structured-output schema for the model's classification-only refinement.
APP_MODEL_REFINE_SCHEMA = {
    "type": "object",
    "properties": {
        "app_type": {"type": "string"},
        "tech_stack": {"type": "array", "items": {"type": "string"}},
        "roles_seen": {"type": "array", "items": {"type": "string"}},
        "key_features": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["app_type"],
}

_ECOMMERCE_RE = re.compile(
    r"\b(add to cart|checkout|shopping cart|add_to_cart|/cart|/checkout|/product|"
    r"price|coupon|basket|payment)\b",
    re.IGNORECASE,
)
_SVG_HTML_RE = re.compile(r"svg|html|image/\*|\*/\*|\.svg|\.html?", re.IGNORECASE)


def _canary() -> str:
    return "sAaR" + secrets.token_hex(4) + "zZ"


def _tech_from_headers(headers: dict[str, str]) -> set[str]:
    tech: set[str] = set()
    for key in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        val = headers.get(key, "")
        if val:
            tech.add(val.split("(", 1)[0].strip())
    return {t for t in tech if t}


def _path_features(url: str) -> list[str]:
    segs = [s for s in urlsplit(url).path.split("/") if s and "." not in s]
    return segs


async def _probe_reflection(
    sender: HttpSender, surface: RawSurface, *, probe_post: bool
) -> tuple[dict[str, set[str]], str]:
    """Send a benign canary per GET param; return per-param signals + a body sample.

    Read-only by default: only GET surfaces are actively probed (a POST probe could
    mutate state, which is off by default per the engine's side-effect policy).
    """

    per_param: dict[str, set[str]] = {}
    if surface.method.upper() == "POST" and not probe_post:
        return per_param, ""

    from saarthi2.vulnengine.probe import strip_query

    base = {k: (v or "1") for k, v in surface.example_values.items()}
    for name in surface.params:
        base.setdefault(name, "1")
    target = strip_query(surface.url)
    sample = ""
    for name in surface.params:
        token = _canary()
        payload = dict(base)
        payload[name] = token
        try:
            if surface.method.upper() == "POST":
                resp = await sender.send("POST", target, data=payload, allow_redirects=True)
            else:
                resp = await sender.send("GET", target, params=payload, allow_redirects=True)
        except Exception:
            continue
        sample = resp.text[:2000] or sample
        found: set[str] = set()
        if sig.detects_reflection(token, resp.text):
            found.add("reflects_input")
        if sig.detect_sql_error(resp.text):
            found.add("sql_error_leak")
        if sig.detect_stack_leak(resp.text):
            found.add("stack_leak")
        if found:
            per_param[name] = found
    return per_param, sample


async def _build_surface(
    sender: HttpSender, raw: RawSurface, *, active_probe: bool, probe_post: bool
) -> tuple[InputSurface, set[str]]:
    """Classify one raw surface into a typed InputSurface + its grounded signals."""

    reflect_map: dict[str, set[str]] = {}
    if active_probe:
        reflect_map, _ = await _probe_reflection(sender, raw, probe_post=probe_post)

    surface_signals: set[str] = set()
    per_param: dict[str, list[str]] = {}
    for name in raw.params:
        value = raw.example_values.get(name, "")
        s = sig.param_signals(name, value)
        s |= reflect_map.get(name, set())
        surface_signals |= s
        if s:
            per_param[name] = sorted(s)

    if raw.accepts and _SVG_HTML_RE.search(" ".join(raw.accepts)):
        surface_signals.add("accepts_svg_html")
    if raw.has_file:
        surface_signals.add("accepts_svg_html")  # unknown accept -> assume risky

    stype = sig.classify_surface(
        params=raw.params,
        signals=surface_signals,
        has_password_field=raw.has_password,
        has_file_field=raw.has_file,
    )
    # Submit-only helper params (e.g. DVWA's Submit) shouldn't be tested as inputs.
    testable = [p for p in raw.params if p.lower() not in ("submit", "login", "csrf", "user_token")]
    surface = InputSurface(
        url=raw.url,
        params=testable or raw.params,
        method=raw.method.upper(),
        type=stype,
        auth_required=True,
        signals=sorted(surface_signals),
        param_signals={k: v for k, v in per_param.items() if k in (testable or raw.params)},
        example_values=dict(raw.example_values),
    )
    return surface, surface_signals


def _guess_app_type(crawl: CrawlResult) -> str:
    blob = " ".join(p.body[:4000] for p in crawl.pages[:10])
    if _ECOMMERCE_RE.search(blob) or _ECOMMERCE_RE.search(crawl.title_hints()):
        return "ecommerce"
    return "web_application"


async def build_app_model(
    crawl: CrawlResult,
    sender: HttpSender,
    *,
    chat: Any = None,
    active_probe: bool = True,
    probe_post: bool = False,
) -> AppModel:
    """Turn a crawl into a structured, grounded App Model."""

    surfaces: list[InputSurface] = []
    all_signals: set[str] = set()
    for raw in crawl.surfaces:
        surface, sset = await _build_surface(
            sender, raw, active_probe=active_probe, probe_post=probe_post
        )
        surfaces.append(surface)
        all_signals |= sset

    tech: set[str] = set()
    features: set[str] = set()
    for page in crawl.pages:
        tech |= _tech_from_headers(page.headers)
        if page.url.lower().endswith(".php") or ".php?" in page.url.lower():
            tech.add("PHP")
        for feat in _path_features(page.url):
            features.add(feat)
    if any(s.type is SurfaceType.AUTH_FIELD for s in surfaces):
        all_signals.add("login_form_present")
    if any(s.type is SurfaceType.FILE_UPLOAD for s in surfaces):
        all_signals.add("file_upload_present")

    model = AppModel(
        app_type=_guess_app_type(crawl),
        tech_stack=sorted(tech),
        roles_seen=["authenticated"],
        key_features=sorted(features),
        input_surfaces=surfaces,
        interesting_signals=sorted(all_signals),
    )

    if chat is not None:
        await _refine_with_model(model, crawl, chat)
    return model


async def _refine_with_model(model: AppModel, crawl: CrawlResult, chat: Any) -> None:
    """Let the 14B classify app_type/tech/roles/features against grounded evidence.

    Never touches ``input_surfaces`` — the model classifies, it does not invent
    endpoints. Any failure leaves the deterministic model untouched.
    """

    digest = crawl.title_hints()[:3000]
    surface_lines = "\n".join(
        f"- {s.method} {s.url} params={s.params} type={s.type} signals={s.signals}"
        for s in model.input_surfaces[:40]
    )
    prompt = (
        "You are classifying an authorized security assessment target. Based ONLY on "
        "the crawled pages and detected input surfaces below, classify the app. Do NOT "
        "invent endpoints or parameters. Return app_type (e.g. ecommerce, cms, api, "
        "banking, web_application), tech_stack, roles_seen, and key_features.\n\n"
        f"Pages:\n{digest}\n\nDetected input surfaces:\n{surface_lines}"
    )
    try:
        data = await chat.structured(
            [{"role": "user", "content": prompt}], APP_MODEL_REFINE_SCHEMA
        )
    except Exception:
        return
    if not isinstance(data, dict):
        return
    if isinstance(data.get("app_type"), str) and data["app_type"].strip():
        model.app_type = data["app_type"].strip()
    for field_name in ("tech_stack", "roles_seen", "key_features"):
        extra = data.get(field_name)
        if isinstance(extra, list):
            merged = {*getattr(model, field_name), *[str(x) for x in extra if str(x).strip()]}
            setattr(model, field_name, sorted(merged))
