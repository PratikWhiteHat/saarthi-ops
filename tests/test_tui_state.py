from saarthi_ai.tui.app import (
    calculate_duration,
    compact_timestamp,
    execution_order_sql,
    infer_phase,
    infer_phase_short,
    progress_for_state,
)


def test_phase_inference() -> None:
    assert (
        infer_phase(
            "completed",
            {"javascript_intelligence_result"},
        )
        == "3E — JAVASCRIPT INTELLIGENCE"
    )
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
            {"javascript_intelligence_result"},
        )
        == "4A — DIRECT VULNERABILITY CHECKS"
    )
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
            {"javascript_intelligence_result"},
        )
        == "3E"
    )
    assert (
        infer_phase_short(
            "running",
            {"javascript_intelligence_result"},
        )
        == "4A"
    )
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


def test_execution_order_prefers_latest_activity() -> None:
    assert execution_order_sql(
        "updated_at",
        "completed_at",
        "created_at",
    ) == ('ORDER BY "updated_at" DESC, "completed_at" DESC, "created_at" DESC')


def test_execution_order_handles_legacy_schema() -> None:
    assert execution_order_sql(
        None,
        "finished_at",
        "started_at",
    ) == ('ORDER BY "finished_at" DESC, "started_at" DESC')

    assert execution_order_sql(None, None, None) == ""


def test_completed_direct_check_evidence_maps_to_phase_4a() -> None:
    assert (
        infer_phase(
            "completed",
            {"direct_check_result"},
        )
        == "4A — DIRECT VULNERABILITY CHECKS"
    )


def test_running_direct_check_evidence_maps_to_phase_4a() -> None:
    assert (
        infer_phase(
            "running",
            {"direct_check_result"},
        )
        == "4A — DIRECT VULNERABILITY CHECKS"
    )


def test_direct_check_evidence_maps_to_short_phase_4a() -> None:
    assert (
        infer_phase_short(
            "completed",
            {"direct_check_result"},
        )
        == "4A"
    )


def test_phase_rows_marks_4a_done_and_4b_next() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows("4A — DIRECT VULNERABILITY CHECKS")
    row_map = {row[1]: row for row in rows}

    assert row_map["4A"][0] == "✓"
    assert row_map["4A"][3] == "DONE"
    assert row_map["4B"][0] == "→"
    assert row_map["4B"][3] == "NEXT"


def test_phase_rows_marks_3e_done_and_4a_next() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows("3E — JAVASCRIPT INTELLIGENCE")
    row_map = {row[1]: row for row in rows}

    assert row_map["3E"][3] == "DONE"
    assert row_map["4A"][3] == "NEXT"


def test_phase_rows_keeps_future_phases_planned() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows("4A — DIRECT VULNERABILITY CHECKS")
    row_map = {row[1]: row for row in rows}

    assert row_map["4C"][3] == "PLANNED"
    assert row_map["4D"][3] == "PLANNED"


def test_completed_blind_validation_evidence_maps_to_phase_4b() -> None:
    assert (
        infer_phase(
            "completed",
            {"blind_validation_result"},
        )
        == "4B — BLIND VALIDATION"
    )


def test_running_blind_validation_evidence_maps_to_phase_4b() -> None:
    assert (
        infer_phase(
            "running",
            {"blind_validation_result"},
        )
        == "4B — BLIND VALIDATION"
    )


def test_blind_validation_evidence_maps_to_short_phase_4b() -> None:
    assert (
        infer_phase_short(
            "completed",
            {"blind_validation_result"},
        )
        == "4B"
    )


def test_phase_rows_marks_4b_done_and_4c_next() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows("4B — BLIND VALIDATION")
    row_map = {row[1]: row for row in rows}

    assert row_map["4B"][3] == "DONE"
    assert row_map["4C"][3] == "NEXT"


def test_completed_oast_observation_maps_to_phase_4c() -> None:
    assert (
        infer_phase(
            "completed",
            {"oast_observation"},
        )
        == "4C — OAST MANAGER"
    )


def test_running_oast_observation_maps_to_phase_4c() -> None:
    assert (
        infer_phase(
            "running",
            {"oast_observation"},
        )
        == "4C — OAST MANAGER"
    )


def test_oast_observation_maps_to_short_phase_4c() -> None:
    assert (
        infer_phase_short(
            "completed",
            {"oast_observation"},
        )
        == "4C"
    )


def test_phase_rows_marks_4c_done_and_4d_next() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows("4C — OAST MANAGER")
    row_map = {row[1]: row for row in rows}

    assert row_map["4C"][3] == "DONE"
    assert row_map["4D"][3] == "NEXT"


def test_completed_confirmation_result_maps_to_phase_4d() -> None:
    assert (
        infer_phase(
            "completed",
            {"confirmation_result"},
        )
        == "4D — CONFIRMATION ENGINE"
    )


def test_running_confirmation_result_maps_to_phase_4d() -> None:
    assert (
        infer_phase(
            "running",
            {"confirmation_result"},
        )
        == "4D — CONFIRMATION ENGINE"
    )


def test_confirmation_result_maps_to_short_phase_4d() -> None:
    assert (
        infer_phase_short(
            "completed",
            {"confirmation_result"},
        )
        == "4D"
    )


def test_confirmation_result_takes_precedence_over_oast() -> None:
    assert (
        infer_phase(
            "completed",
            {
                "oast_observation",
                "confirmation_result",
            },
        )
        == "4D — CONFIRMATION ENGINE"
    )


def test_phase_rows_marks_4d_done() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows("4D — CONFIRMATION ENGINE")
    row_map = {row[1]: row for row in rows}

    assert row_map["4C"][3] == "DONE"
    assert row_map["4D"][3] == "DONE"
    assert not any(row[3] == "NEXT" for row in rows)


def test_normalize_phase_code_collapses_phase_4a_children() -> None:
    from saarthi_ai.tui.app import normalize_phase_code

    assert normalize_phase_code("4A-security-headers") == "4A"
    assert normalize_phase_code("4A-cors") == "4A"
    assert normalize_phase_code("3E") == "3E"


def test_phase_rows_uses_completed_orchestration_phases() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows(
        "4A — DIRECT VULNERABILITY CHECKS",
        {
            "3A",
            "3B",
            "3C",
            "3D",
            "3E",
            "4A-security-headers",
            "4A-cors",
        },
    )

    status_by_phase = {
        phase: status
        for _, phase, _, status, _ in rows
    }

    assert status_by_phase["3A"] == "DONE"
    assert status_by_phase["3B"] == "DONE"
    assert status_by_phase["3C"] == "DONE"
    assert status_by_phase["3D"] == "DONE"
    assert status_by_phase["3E"] == "DONE"
    assert status_by_phase["4A"] == "DONE"
    assert status_by_phase["4B"] == "NEXT"
    assert status_by_phase["4C"] == "PLANNED"
    assert status_by_phase["4D"] == "PLANNED"


def test_parse_execution_metadata_rejects_invalid_json() -> None:
    import sqlite3

    from saarthi_ai.tui.app import parse_execution_metadata

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE records (metadata_json TEXT)"
    )
    connection.execute(
        "INSERT INTO records VALUES (?)",
        ("not-json",),
    )

    row = connection.execute(
        "SELECT * FROM records"
    ).fetchone()

    assert parse_execution_metadata(
        row,
        "metadata_json",
    ) == {}


def test_select_dashboard_execution_rows_uses_parent_and_children() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import (
        select_dashboard_execution_rows,
    )

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE executions (
            execution_id TEXT,
            state TEXT,
            metadata_json TEXT
        )
        """
    )

    records = [
        (
            "execution-cors",
            "completed",
            {
                "execution_role": "orchestration_child",
                "orchestration_id": "orchestration-test",
                "phase_code": "4A-cors",
            },
        ),
        (
            "execution-headers",
            "completed",
            {
                "execution_role": "orchestration_child",
                "orchestration_id": "orchestration-test",
                "phase_code": "4A-security-headers",
            },
        ),
        (
            "execution-3e",
            "completed",
            {
                "execution_role": "orchestration_child",
                "orchestration_id": "orchestration-test",
                "phase_code": "3E",
            },
        ),
        (
            "execution-parent",
            "completed",
            {
                "execution_role": "orchestration_parent",
                "orchestration_id": "orchestration-test",
            },
        ),
    ]

    for execution_id, state, metadata in records:
        connection.execute(
            "INSERT INTO executions VALUES (?, ?, ?)",
            (
                execution_id,
                state,
                json.dumps(metadata),
            ),
        )

    rows = connection.execute(
        "SELECT * FROM executions"
    ).fetchall()

    parent, children, completed = (
        select_dashboard_execution_rows(
            list(rows),
            "metadata_json",
        )
    )

    assert parent["execution_id"] == "execution-parent"
    assert len(children) == 3
    assert completed == frozenset(
        {
            "3E",
            "4A-security-headers",
            "4A-cors",
        }
    )


def test_load_orchestration_outcome_reads_partial_summary() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE audit_events (
            execution_id TEXT,
            details_json TEXT,
            created_at TEXT
        )
        """
    )
    connection.execute(
        """
        INSERT INTO audit_events (
            execution_id,
            details_json,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        (
            "execution-parent",
            json.dumps(
                {
                    "orchestration_status": "partial",
                    "outcome_counts": {
                        "completed": 6,
                        "skipped": 0,
                        "failed": 1,
                        "required": 5,
                        "optional": 2,
                    },
                    "phase_outcomes": [
                        {
                            "phase": "4A-cors",
                            "outcome": "failed",
                            "required": False,
                            "reason": None,
                            "error_summary": (
                                "simulated bounded CORS failure"
                            ),
                        }
                    ],
                }
            ),
            "2026-08-04T11:00:00+04:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()

    status, counts, failure = (
        repository._load_orchestration_outcome(
            connection,
            {"audit_events"},
            "execution-parent",
        )
    )

    assert status == "partial"
    assert counts == {
        "completed": 6,
        "skipped": 0,
        "failed": 1,
        "required": 5,
        "optional": 2,
    }
    assert failure == (
        "4A-cors: simulated bounded CORS failure"
    )


def test_load_orchestration_outcome_handles_missing_audit_data() -> None:
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    repository = ReadOnlySaarthiRepository()

    assert repository._load_orchestration_outcome(
        connection,
        set(),
        "execution-parent",
    ) == ("unknown", {}, None)
