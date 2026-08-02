from saarthi_ai.tui.app import (
    calculate_duration,
    compact_timestamp,
    infer_phase,
    infer_phase_short,
    progress_for_state,
)


def test_phase_inference() -> None:
    assert (
        infer_phase(
            "completed",
            {"crawl_result"},
        )
        == "3D — CRAWLING & URL INTELLIGENCE"
    )
    assert (
        infer_phase(
            "completed",
            {"http_intelligence_result"},
        )
        == "3C — LIVE HOST INTELLIGENCE"
    )
    assert (
        infer_phase(
            "completed",
            {"subdomain_result"},
        )
        == "3B — SUBDOMAIN ENUMERATION"
    )
    assert (
        infer_phase(
            "completed",
            {"dns_result"},
        )
        == "3A — DNS INTELLIGENCE"
    )
    assert infer_phase("completed") == "3B — SUBDOMAIN ENUMERATION"
    assert infer_phase("running") == "ACTIVE WORKFLOW"
    assert infer_phase("planned") == "PLANNING"
    assert infer_phase("failed") == "EXECUTION REVIEW"


def test_active_phase_inference() -> None:
    assert (
        infer_phase(
            "running",
            {"crawl_result"},
        )
        == "3E — JAVASCRIPT INTELLIGENCE"
    )
    assert (
        infer_phase(
            "running",
            {"http_intelligence_result"},
        )
        == "3D — CRAWLING & URL INTELLIGENCE"
    )
    assert (
        infer_phase(
            "running",
            {"subdomain_result"},
        )
        == "3C — LIVE HOST INTELLIGENCE"
    )
    assert (
        infer_phase(
            "analyzing",
            {"dns_result"},
        )
        == "3B — SUBDOMAIN ENUMERATION"
    )


def test_compact_phase_inference() -> None:
    assert (
        infer_phase_short(
            "completed",
            {"crawl_result"},
        )
        == "3D"
    )
    assert (
        infer_phase_short(
            "running",
            {"crawl_result"},
        )
        == "3E"
    )
    assert (
        infer_phase_short(
            "completed",
            {"http_intelligence_result"},
        )
        == "3C"
    )
    assert (
        infer_phase_short(
            "completed",
            {"subdomain_result"},
        )
        == "3B"
    )
    assert infer_phase_short("planned") == "PLAN"
    assert infer_phase_short("failed") == "REVIEW"


def test_progress_mapping() -> None:
    assert progress_for_state("planned") == 20
    assert progress_for_state("running") == 55
    assert progress_for_state("analyzing") == 80
    assert progress_for_state("completed") == 100


def test_duration_calculation() -> None:
    assert (
        calculate_duration(
            "2026-08-01T01:00:00+04:00",
            "2026-08-01T01:02:05+04:00",
        )
        == "00:02:05"
    )


def test_compact_timestamp() -> None:
    assert compact_timestamp("2026-08-01T01:54:00+04:00") == "2026-08-01 01:54:00"
