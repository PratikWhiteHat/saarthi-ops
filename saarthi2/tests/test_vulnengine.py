"""Vulnerability identification engine — comprehend -> plan -> test -> verify.

Fully offline: a deterministic FakeApp stands in for the target (a DVWA-like
vulnerable app and a hardened clean app) and a fake browser stands in for the
Playwright XSS oracle, so the oracle logic, the hard TEST gate, and the
zero-false-positive guarantee are all proven without a live target or Ollama.
"""

from __future__ import annotations

import asyncio
import html
import re
from urllib.parse import parse_qsl, urlsplit

from saarthi2.state import Store
from saarthi2.vulnengine import signals as sig
from saarthi2.vulnengine.config import load_matrix, load_payloads
from saarthi2.vulnengine.http import SentResponse
from saarthi2.vulnengine.models import (
    AppModel,
    Finding,
    FindingSource,
    FindingStatus,
    InputSurface,
    SurfaceType,
)
from saarthi2.vulnengine.payloads import select_and_mutate
from saarthi2.vulnengine.pipeline import run_pipeline
from saarthi2.vulnengine.planner import plan


# --------------------------------------------------------------------------- #
# Fake target
# --------------------------------------------------------------------------- #
class FakeApp:
    """A deterministic app implementing the HttpSender.send interface."""

    def __init__(self, base: str, kind: str = "vuln") -> None:
        self.base = base
        self.kind = kind

    async def send(
        self, method, url, *, params=None, data=None, headers=None, allow_redirects=False
    ):
        parts = urlsplit(url)
        merged = dict(parse_qsl(parts.query, keep_blank_values=True))
        merged.update(params or {})
        merged.update(data or {})
        path = parts.path
        handler = getattr(self, f"_{self.kind}")
        return handler(path, method.upper(), merged)

    def _resp(self, status, body, elapsed=10, headers=None):
        return SentResponse(
            status_code=status, text=body,
            headers={k.lower(): v for k, v in (headers or {}).items()},
            elapsed_ms=elapsed, url=self.base,
        )

    # ---- vulnerable (DVWA-like) --------------------------------------------
    _INDEX = (
        "<html><body>"
        "<a href='vulnerabilities/sqli/'>SQLi</a>"
        "<a href='vulnerabilities/xss_r/'>XSS</a>"
        "<a href='vulnerabilities/fi/?page=include.php'>FI</a>"
        "<a href='vulnerabilities/exec/'>Exec</a>"
        "<a href='redirect.php?url=/home'>Redirect</a>"
        "<a href='profile.php?id=1'>Profile</a>"
        "</body></html>"
    )
    _SQLI_FORM = (
        "<html><body><form method='GET' action='#'>"
        "<input type='text' name='id'>"
        "<input type='submit' name='Submit' value='Submit'></form>{extra}</body></html>"
    )

    @staticmethod
    def _truthy(low: str):
        if "or '1'='1" in low or "or 1=1" in low:
            return True
        if "and '1'='2" in low or "and 1=2" in low:
            return False
        return None

    def _vuln(self, path, method, m):
        if path in ("/", "") or path.endswith("/index.php"):
            return self._resp(200, self._INDEX)
        if path.endswith("/vulnerabilities/sqli/"):
            return self._sqli(m)
        if path.endswith("/vulnerabilities/xss_r/"):
            name = m.get("name", "")
            return self._resp(200, f"<html><body><p>Hello {name}</p></body></html>")
        if path.endswith("/vulnerabilities/fi/"):
            page = m.get("page", "").replace("\\", "/")
            if "etc/passwd" in page:
                return self._resp(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:")
            return self._resp(200, f"<html><body>File: {m.get('page','')}</body></html>")
        if path.endswith("/vulnerabilities/exec/"):
            ip = m.get("ip", "")
            form = (
                "<html><body><form method='POST' action='#'>"
                "<input type='text' name='ip'>"
                "<input type='submit' name='Submit' value='Submit'></form>{extra}</body></html>"
            )
            if not ip:
                return self._resp(200, form.format(extra=""))
            mt = re.search(r"sleep\s+(\d+)", ip.lower())
            elapsed = 10 + int(mt.group(1)) * 1000 if mt else 10
            return self._resp(200, form.format(extra=f"<pre>PING {ip}</pre>"), elapsed)
        if path.endswith("/redirect.php"):
            return self._resp(302, "", headers={"Location": m.get("url", "")})
        if path.endswith("/profile.php"):
            users = {"1": "Alice Anderson", "2": "Bob Brown", "3": "Carol Clark"}
            uid = m.get("id", "")
            if uid in users:
                return self._resp(
                    200, f"<html>Profile: {users[uid]} uid={uid} mail={uid}@corp</html>"
                )
            return self._resp(200, "<html>No such user</html>")
        return self._resp(404, "<html>not found</html>")

    def _sqli(self, m):
        idv = m.get("id", "")
        form = self._SQLI_FORM.format(extra="")
        if not idv:
            return self._resp(200, form)
        low = idv.lower()
        head = f"<pre>ID: {idv}</pre>"
        mt = re.search(r"sleep\((\d+)\)", low)
        if mt:
            return self._resp(200, form + head, 10 + int(mt.group(1)) * 1000)
        if idv.strip() == "1'":
            return self._resp(200, form + head + "<b>You have an error in your SQL syntax</b>")
        truth = self._truthy(low)
        if truth is True:
            rows = ("First name: admin Surname: admin First name: bob Surname: jones "
                    "First name: carol Surname: white")
            return self._resp(200, form + head + f"<div>{rows}</div>")
        if truth is False:
            return self._resp(200, form + head)
        return self._resp(200, form + head)

    # ---- clean (hardened) ---------------------------------------------------
    _CLEAN_INDEX = (
        "<html><body>"
        "<a href='search.php?q=test'>Search</a>"
        "<a href='profile.php?id=1'>Profile</a>"
        "</body></html>"
    )

    def _clean(self, path, method, m):
        if path in ("/", "") or path.endswith("/index.php"):
            return self._resp(200, self._CLEAN_INDEX)
        if path.endswith("/search.php"):
            q = m.get("q", "")
            return self._resp(200, f"<html><body>Results for {html.escape(q)}</body></html>")
        if path.endswith("/profile.php"):
            return self._resp(200, "<html>Your account page</html>")
        return self._resp(404, "<html>not found</html>")

    # ---- empty (no surfaces) / no-signal (empty plan) -----------------------
    def _empty(self, path, method, m):
        return self._resp(200, "<html><body>welcome, nothing to see</body></html>")

    def _nosignal(self, path, method, m):
        if path in ("/", "") or path.endswith("/index.php"):
            return self._resp(200, "<html><body><a href='misc.php?foo=bar'>x</a></body></html>")
        # A param with no name/value signal, and no reflection of the input.
        return self._resp(200, "<html><body>static content, no echo</body></html>")


async def _fake_browser(app: FakeApp, surface, param, value, marker) -> bool:
    """Stand-in for the Playwright oracle: 'executes' iff the payload reflects raw."""

    base = {p: "1" for p in surface.params}
    base.update(surface.example_values)
    if param is not None:
        base[param] = value
    parts = urlsplit(surface.url)
    r = await app.send("GET", f"{parts.scheme}://{parts.netloc}{parts.path}", params=base)
    return value in r.text


def _browser_for(app: FakeApp):
    async def browser(surface, param, value, marker):
        return await _fake_browser(app, surface, param, value, marker)
    return browser


# --------------------------------------------------------------------------- #
# Signals
# --------------------------------------------------------------------------- #
def test_param_signals() -> None:
    assert "numeric_id" in sig.param_signals("id", "5")
    assert "url_like_value" in sig.param_signals("x", "https://evil.test")
    assert "url_like_value" in sig.param_signals("redirect", "/home")
    assert "file_like_value" in sig.param_signals("page", "include.php")
    assert "command_like" in sig.param_signals("ip", "127.0.0.1")
    assert sig.param_signals("boringname", "plainword") == set()


def test_detectors() -> None:
    assert sig.detect_sql_error("You have an error in your SQL syntax near")
    assert not sig.detect_sql_error("all good")
    assert sig.detects_reflection("abcd1234", "xx abcd1234 yy")
    assert not sig.detects_reflection("ab", "abcdef")  # too short to trust


def test_classify_surface() -> None:
    auth = sig.classify_surface(params=["p"], signals=set(), has_password_field=True)
    upload = sig.classify_surface(params=["f"], signals=set(), has_file_field=True)
    obj = sig.classify_surface(params=["id"], signals={"numeric_id"})
    assert auth is SurfaceType.AUTH_FIELD
    assert upload is SurfaceType.FILE_UPLOAD
    assert obj is SurfaceType.OBJECT_REF


# --------------------------------------------------------------------------- #
# Config
# --------------------------------------------------------------------------- #
def test_bundled_config_loads() -> None:
    matrix = load_matrix()
    assert matrix.get("surface_rules")
    payloads = load_payloads()
    assert "sqli" in payloads and "xss" in payloads


def test_config_seeded_into_dir(tmp_path) -> None:
    cfg = tmp_path / "cfg"
    load_matrix(cfg)
    load_payloads(cfg)
    assert (cfg / "feature_vuln_matrix.yaml").exists()
    assert (cfg / "payloads.yaml").exists()


# --------------------------------------------------------------------------- #
# Payloads
# --------------------------------------------------------------------------- #
def test_select_and_mutate_sqli() -> None:
    prepared = select_and_mutate("sqli")
    techniques = {p.technique for p in prepared}
    assert {"boolean", "error", "time"} <= techniques


def test_oob_skipped_without_collector() -> None:
    assert select_and_mutate("blind_ssrf") == []
    assert select_and_mutate("blind_ssrf", oob_domain="x.oast.test")


def test_xss_marker_filled() -> None:
    prepared = select_and_mutate("xss")
    assert prepared and all("{marker}" not in p.values["value"] for p in prepared)
    assert all(p.values["marker"] in p.values["value"] for p in prepared)


# --------------------------------------------------------------------------- #
# Planner + hard requirement
# --------------------------------------------------------------------------- #
def _reflecting_id_surface() -> InputSurface:
    return InputSurface(
        url="http://t/sqli/", params=["id"], method="GET", type=SurfaceType.OBJECT_REF,
        signals=["numeric_id", "reflects_input"],
        param_signals={"id": ["numeric_id", "reflects_input"]},
        example_values={"id": "1"},
    )


def test_planner_routes_per_signal() -> None:
    model = AppModel(app_type="web_application", input_surfaces=[_reflecting_id_surface()])
    classes = {t.vuln_class for t in plan(model)}
    assert {"sqli", "xss", "idor_bola"} <= classes


def test_planner_orders_by_priority() -> None:
    tasks = plan(AppModel(app_type="web_application", input_surfaces=[_reflecting_id_surface()]))
    assert tasks == sorted(tasks, key=lambda t: -t.priority)


def test_empty_model_not_populated() -> None:
    assert not AppModel().is_populated
    assert plan(AppModel()) == []


def test_plan_empty_when_no_signals() -> None:
    surface = InputSurface(
        url="http://t/misc", params=["foo"], method="GET", type=SurfaceType.GENERIC,
        signals=[], param_signals={}, example_values={"foo": "bar"},
    )
    assert plan(AppModel(app_type="web_application", input_surfaces=[surface])) == []


# --------------------------------------------------------------------------- #
# Full pipeline — DVWA-like target confirms multiple classes
# --------------------------------------------------------------------------- #
def test_pipeline_confirms_multiple_classes() -> None:
    app = FakeApp("http://dvwa.test/", kind="vuln")
    result = asyncio.run(
        run_pipeline("http://dvwa.test/", app, chat=None, browser=_browser_for(app))
    )
    assert result.entered_test
    confirmed = result.confirmed
    classes = {f.vuln_class for f in confirmed}

    assert any(c.startswith("sqli") for c in classes), classes
    assert "reflected_xss" in classes, classes
    assert len(confirmed) >= 3, classes
    # Every confirmed finding is oracle-sourced and carries evidence.
    for f in confirmed:
        assert f.status is FindingStatus.CONFIRMED
        assert f.source is FindingSource.ORACLE
        assert f.evidence


def test_pipeline_confirms_lfi_and_cmd_and_redirect_and_idor() -> None:
    app = FakeApp("http://dvwa.test/", kind="vuln")
    result = asyncio.run(
        run_pipeline("http://dvwa.test/", app, chat=None, browser=_browser_for(app))
    )
    classes = {f.vuln_class for f in result.confirmed}
    # Extension classes the oracle can confirm deterministically on DVWA.
    for expected in ("lfi", "command_injection", "open_redirect", "idor_bola"):
        assert expected in classes, (expected, classes)


# --------------------------------------------------------------------------- #
# Zero false positives on a clean target
# --------------------------------------------------------------------------- #
def test_pipeline_clean_target_zero_confirmed() -> None:
    app = FakeApp("http://clean.test/", kind="clean")
    result = asyncio.run(
        run_pipeline("http://clean.test/", app, chat=None, browser=_browser_for(app))
    )
    assert result.entered_test  # it did have surfaces to test
    assert result.confirmed == []


# --------------------------------------------------------------------------- #
# Hard requirement: no TEST without App Model + non-empty plan
# --------------------------------------------------------------------------- #
def test_refuses_test_without_app_model() -> None:
    app = FakeApp("http://empty.test/", kind="empty")
    result = asyncio.run(run_pipeline("http://empty.test/", app, chat=None))
    assert result.entered_test is False
    assert "App Model" in result.reason
    assert result.findings == []


def test_refuses_test_with_empty_plan() -> None:
    app = FakeApp("http://ns.test/", kind="nosignal")
    result = asyncio.run(run_pipeline("http://ns.test/", app, chat=None))
    assert result.entered_test is False
    assert "Plan is empty" in result.reason


# --------------------------------------------------------------------------- #
# Findings store round-trip with the rich schema
# --------------------------------------------------------------------------- #
def test_store_rich_finding_roundtrip(tmp_path) -> None:
    store = Store(tmp_path / "db.sqlite", tmp_path / "ev", tmp_path / "audit.jsonl")
    finding = Finding(
        id="f-1", vuln_class="sqli_boolean", severity="critical",
        url="http://t/sqli/", param="id", method="GET",
        status=FindingStatus.CONFIRMED, source=FindingSource.ORACLE,
        confidence=0.99, summary="Confirmed boolean SQLi",
        evidence={"true_len": 200, "false_len": 40}, request={"payload": "1' OR '1'='1"},
    )
    store.record_findings("run-1", [finding.to_row()])
    rows = store.list_findings(run_id="run-1")
    store.close()
    assert len(rows) == 1
    row = rows[0]
    assert row["status"] == "confirmed"
    assert row["source"] == "oracle"
    assert row["vuln_class"] == "sqli_boolean"
    assert row["severity"] == "critical"
    assert isinstance(row["evidence"], dict) and row["evidence"]["true_len"] == 200


def test_store_old_shape_still_works(tmp_path) -> None:
    store = Store(tmp_path / "db.sqlite", tmp_path / "ev", tmp_path / "audit.jsonl")
    store.record_findings("run-1", [{"tool": "nuclei", "severity": "high", "message": "x"}])
    rows = store.list_findings(run_id="run-1")
    store.close()
    assert rows[0]["severity"] == "high"
    assert rows[0]["status"] == "confirmed"  # defaulted for scanner findings


# --------------------------------------------------------------------------- #
# vuln_engine step wiring — persists App Model + plan to run-context and findings
# --------------------------------------------------------------------------- #
def test_vuln_engine_step_persists(tmp_path, monkeypatch) -> None:
    import saarthi2.vulnengine.pipeline as pipeline_mod
    from saarthi2.engine.context import RunContext
    from saarthi2.engine.models import Step
    from saarthi2.engine.runner import StepDeps
    from saarthi2.steps.vuln_engine import handle_vuln_engine
    from saarthi2.vulnengine.models import TestTask
    from saarthi2.vulnengine.pipeline import PipelineResult

    async def fake_run_pipeline(base_url, sender, **kwargs):
        model = AppModel(app_type="web_application", input_surfaces=[_reflecting_id_surface()])
        finding = Finding(
            id="f-1", vuln_class="sqli_boolean", severity="critical",
            url=base_url, param="id", method="GET",
            status=FindingStatus.CONFIRMED, source=FindingSource.ORACLE,
            summary="Confirmed", evidence={"x": 1},
        )
        task = TestTask(endpoint=base_url, param="id", vuln_class="sqli")
        return PipelineResult(app_model=model, plan=[task], findings=[finding], entered_test=True)

    monkeypatch.setattr(pipeline_mod, "run_pipeline", fake_run_pipeline)

    store = Store(tmp_path / "db.sqlite", tmp_path / "ev", tmp_path / "audit.jsonl")
    deps = StepDeps(run_command=None, http_request=None, store=store)  # type: ignore[arg-type]
    ctx = RunContext(run_id="run-1", target="http://dvwa.test/")
    step = Step(id="engine", uses="vuln_engine", with_={"base_url": "http://dvwa.test/"})

    result = asyncio.run(handle_vuln_engine(step, ctx, deps))
    rows = store.list_findings(run_id="run-1")
    store.close()

    assert result.status.value == "completed"
    assert result.data["confirmed"] == 1
    assert result.data["entered_test"] is True
    assert ctx.vars["app_model"]["app_type"] == "web_application"
    assert len(ctx.vars["plan"]) == 1
    assert len(rows) == 1 and rows[0]["status"] == "confirmed"


def test_vuln_engine_step_requires_target() -> None:
    from saarthi2.engine.context import RunContext
    from saarthi2.engine.models import Step
    from saarthi2.engine.runner import StepDeps
    from saarthi2.steps.vuln_engine import handle_vuln_engine

    deps = StepDeps(run_command=None, http_request=None)  # type: ignore[arg-type]
    ctx = RunContext(run_id="run-1", target=None)
    step = Step(id="engine", uses="vuln_engine", with_={})
    result = asyncio.run(handle_vuln_engine(step, ctx, deps))
    assert result.status.value == "failed"
