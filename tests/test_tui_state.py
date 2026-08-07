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
    assert row_map["4A"][4] == "✓"
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
    assert row_map["5A"][3] == "NEXT"


def test_phase_rows_cover_complete_product_workflow() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows("6C — LOW-RISK ATTACK VALIDATORS")
    row_map = {row[1]: row for row in rows}

    assert len(rows) == 23
    assert row_map["5A"][2] == "Assessment Planner"
    assert row_map["6A"][2] == "Attack Hypothesis Engine"
    assert row_map["6C"][3] == "DONE"
    assert row_map["6D"][3] == "NEXT"
    assert row_map["6G"][2] == "Cleanup & Rollback"
    assert row_map["8A"][2] == "Reporting & Remediation"


def test_orchestration_summary_shows_validator_coverage() -> None:
    from saarthi_ai.tui.app import (
        build_orchestration_summary_lines,
        demo_snapshot,
    )

    rendered = "\n".join(
        build_orchestration_summary_lines(demo_snapshot())
    )

    assert "ORCHESTRATION SUMMARY" in rendered
    assert "Overall Status" in rendered
    assert "Completed Phases" in rendered
    assert "Validator Coverage" in rendered
    assert "81 total" in rendered
    assert "Phase 6C Safe Chain" in rendered
    assert "0/9 complete" in rendered
    assert "Nuclei / SQLmap" in rendered
    assert "APPROVAL REQUIRED" in rendered


def test_activity_text_styles_without_interpreting_markup() -> None:
    from saarthi_ai.tui.app import build_activity_text

    rendered = build_activity_text(
        "2026-08-06 17:40:11 SQLMAP [red]forged[/red]"
    )

    assert rendered.plain == (
        "2026-08-06 17:40:11 SQLMAP [red]forged[/red]"
    )
    assert rendered.spans


def test_normalize_phase_code_collapses_phase_4a_children() -> None:
    from saarthi_ai.tui.app import normalize_phase_code

    assert normalize_phase_code("4A-security-headers") == "4A"
    assert normalize_phase_code("4A-cors") == "4A"
    assert normalize_phase_code("6C-safe-validator") == "6C"
    assert normalize_phase_code("6C-nuclei-preview") == "6C"
    assert normalize_phase_code("6C-sqlmap-preview") == "6C"
    assert normalize_phase_code("3E") == "3E"


def test_phase6_chain_status_tracks_permissions_and_validators() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import (
        PHASE6_SAFE_ACTIONS,
        build_phase6_chain_status,
        phase_execution_label,
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
            "execution-nuclei",
            "planned",
            {
                "phase_code": "6C-nuclei-preview",
                "phase_name": "Nuclei Non-Executed Preview",
            },
        ),
        (
            "execution-browser",
            "completed",
            {
                "phase_code": "6C-safe-validator",
                "phase_name": "browser_attack_surface_validation",
            },
        ),
        (
            "execution-server",
            "completed",
            {
                "phase_code": "6C-safe-validator",
                "phase_name": "server_parser_surface_validation",
            },
        ),
    ]
    for execution_id, state, metadata in records:
        connection.execute(
            "INSERT INTO executions VALUES (?, ?, ?)",
            (execution_id, state, json.dumps(metadata)),
        )

    rows = connection.execute("SELECT * FROM executions").fetchall()
    status = build_phase6_chain_status(
        rows,
        "metadata_json",
        "state",
    )

    assert status["validator_completed"] == "2"
    assert status["validator_total"] == str(
        len(PHASE6_SAFE_ACTIONS)
    )
    assert status["nuclei"] == "PREVIEW READY"
    assert status["sqlmap"] == "APPROVAL REQUIRED"
    assert status["browser_attack_surface_validation"] == "DONE"
    assert status["server_parser_surface_validation"] == "DONE"
    assert status["injection_surface_validation"] == "APPROVAL"
    assert phase_execution_label(
        json.loads(rows[1]["metadata_json"])
    ) == "6C Browser"


def test_phase6_chain_status_shows_active_nuclei_execution() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import (
        build_phase6_chain_status,
        current_phase_for_dashboard,
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
    connection.execute(
        "INSERT INTO executions VALUES (?, ?, ?)",
        (
            "execution-nuclei",
            "running",
            json.dumps(
                {
                    "phase_code": "6C-nuclei",
                    "phase_name": "Controlled Nuclei Execution",
                }
            ),
        ),
    )

    rows = connection.execute("SELECT * FROM executions").fetchall()
    status = build_phase6_chain_status(
        rows,
        "metadata_json",
        "state",
    )

    assert status["nuclei"] == "RUNNING"
    assert current_phase_for_dashboard(
        "completed",
        (),
        {"3A", "6A"},
        status,
    ) == "6C — LOW-RISK ATTACK VALIDATORS"


def test_phase6_is_complete_only_after_every_safe_validator() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import (
        PHASE6_SAFE_ACTIONS,
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
    orchestration_id = "orchestration-phase6"
    connection.execute(
        "INSERT INTO executions VALUES (?, ?, ?)",
        (
            "execution-parent",
            "completed",
            json.dumps(
                {
                    "execution_role": "orchestration_parent",
                    "orchestration_id": orchestration_id,
                }
            ),
        ),
    )
    for index, action in enumerate(PHASE6_SAFE_ACTIONS):
        connection.execute(
            "INSERT INTO executions VALUES (?, ?, ?)",
            (
                f"execution-{index}",
                "completed",
                json.dumps(
                    {
                        "execution_role": "orchestration_child",
                        "orchestration_id": orchestration_id,
                        "phase_code": "6C-safe-validator",
                        "phase_name": action,
                    }
                ),
            ),
        )

    rows = connection.execute("SELECT * FROM executions").fetchall()
    _parent, _children, completed = select_dashboard_execution_rows(
        list(rows),
        "metadata_json",
    )
    assert "6B" in completed
    assert "6C-safe-validator" in completed

    connection.execute(
        "UPDATE executions SET state = 'failed' "
        "WHERE execution_id = 'execution-0'"
    )
    rows = connection.execute("SELECT * FROM executions").fetchall()
    _parent, _children, completed = select_dashboard_execution_rows(
        list(rows),
        "metadata_json",
    )
    assert "6B" not in completed
    assert "6C-safe-validator" not in completed


def test_tui_uses_dynamic_phase6_tool_labels() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import demo_snapshot, tool_rows

    snapshot = replace(
        demo_snapshot(),
        phase6_chain_status={
            "validator_completed": "9",
            "validator_total": "9",
            "nuclei": "PREVIEW READY",
            "sqlmap": "APPROVAL REQUIRED",
            "browser_attack_surface_validation": "DONE",
            "server_parser_surface_validation": "DONE",
        },
    )
    rows = tool_rows(snapshot)

    assert (
        "nuclei",
        "Controlled Preview / Execution",
        "PREVIEW READY",
    ) in rows
    assert (
        "sqlmap",
        "External Result Handoff / Import",
        "APPROVAL REQUIRED",
    ) in rows
    assert (
        "Saarthi 6B",
        "Policy & Approval Gate",
        "DONE",
    ) in rows
    assert (
        "Saarthi 6C.2",
        "Browser Attack Surface Validator",
        "DONE",
    ) in rows
    assert (
        "Saarthi 6C.3",
        "Server/Parser Surface Validator",
        "DONE",
    ) in rows


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


def test_phase_rows_marks_active_phase6_child_in_progress() -> None:
    from saarthi_ai.tui.app import phase_rows

    rows = phase_rows(
        "6C — LOW-RISK ATTACK VALIDATORS",
        {"3A", "3B", "3C", "3D", "3E", "4A", "5A", "5B", "5C", "5D", "6A"},
    )
    status_by_phase = {
        phase: status
        for _, phase, _, status, _ in rows
    }

    assert status_by_phase["6A"] == "DONE"
    assert status_by_phase["6B"] == "NOT RUN"
    assert status_by_phase["6C"] == "IN PROGRESS"
    assert status_by_phase["6D"] == "PLANNED"


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


def test_planned_controlled_validation_evidence_maps_to_phase_6b() -> None:
    assert (
        infer_phase(
            "planned",
            {"controlled_validation_plan"},
        )
        == "6B — CONTROLLED VALIDATION PLAN"
    )


def test_created_controlled_validation_evidence_maps_to_phase_6b() -> None:
    assert (
        infer_phase(
            "created",
            {"controlled_validation_plan"},
        )
        == "6B — CONTROLLED VALIDATION PLAN"
    )


def test_controlled_validation_compact_phase_is_6b() -> None:
    assert (
        infer_phase_short(
            "planned",
            {"controlled_validation_plan"},
        )
        == "6B"
    )


def test_planned_execution_without_phase_6_evidence_remains_generic() -> None:
    assert infer_phase("planned") == "PLANNING"
    assert infer_phase_short("planned") == "PLAN"


def test_completed_controlled_observation_maps_to_phase_6c() -> None:
    assert (
        infer_phase(
            "completed",
            {"controlled_validation_observation"},
        )
        == "6C — LOW-RISK HTTP VALIDATOR"
    )


def test_running_controlled_observation_maps_to_phase_6c() -> None:
    assert (
        infer_phase(
            "running",
            {"controlled_validation_observation"},
        )
        == "6C — LOW-RISK HTTP VALIDATOR"
    )


def test_failed_controlled_observation_maps_to_phase_6c_review() -> None:
    assert (
        infer_phase(
            "failed",
            {"controlled_validation_observation"},
        )
        == "6C — LOW-RISK HTTP VALIDATOR REVIEW"
    )


def test_controlled_observation_compact_phase_is_6c() -> None:
    assert (
        infer_phase_short(
            "completed",
            {"controlled_validation_observation"},
        )
        == "6C"
    )


def test_loads_safe_controlled_observation_summary() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            sha256 TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            sha256,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "evidence-observation",
            "execution-test",
            "controlled_validation_observation",
            "a" * 64,
            json.dumps(
                {
                    "target_url": "https://example.com/account",
                    "action": "clickjacking_header_validation",
                    "method": "HEAD",
                    "status_code": 200,
                    "final_url": "https://example.com/account",
                    "body_bytes_captured": 0,
                    "body_truncated": False,
                    "body_sha256": None,
                    "plan_evidence_id": "evidence-plan",
                    "network_activity": True,
                    "request_attempted": True,
                    "follow_redirects": False,
                    "validator_id": (
                        "6C.2-clickjacking-header-validation"
                    ),
                    "validator_classification": "protected",
                    "validator_reason": (
                        "Restrictive frame policy observed."
                    ),
                    "protection_sources": [
                        "csp_frame_ancestors"
                    ],
                    "header_only": True,
                    "exploit_page_generated": False,
                    "browser_launched": False,
                    "payload_generated": False,
                }
            ),
            "2026-08-04T10:00:00+00:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()

    observation = (
        repository._load_controlled_validation_observation(
            connection,
            {"evidence"},
            "execution-test",
        )
    )

    assert observation is not None
    assert observation["evidence_id"] == "evidence-observation"
    assert observation["target_url"] == "https://example.com/account"
    assert observation["action"] == "clickjacking_header_validation"
    assert observation["method"] == "HEAD"
    assert observation["status_code"] == "200"
    assert observation["body_bytes_captured"] == "0"
    assert observation["body_truncated"] == "false"
    assert observation["network_activity"] == "true"
    assert observation["request_attempted"] == "true"
    assert observation["follow_redirects"] == "false"
    assert observation["plan_evidence_id"] == "evidence-plan"
    assert (
        observation["validator_id"]
        == "6C.2-clickjacking-header-validation"
    )
    assert observation["validator_classification"] == "protected"
    assert observation["protection_sources"] == "csp_frame_ancestors"
    assert observation["header_only"] == "true"
    assert observation["exploit_page_generated"] == "false"
    assert observation["browser_launched"] == "false"
    assert observation["payload_generated"] == "false"


def test_controlled_observation_skips_newest_malformed_metadata() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            sha256 TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.executemany(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            sha256,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            (
                "evidence-valid",
                "execution-test",
                "controlled_validation_observation",
                "a" * 64,
                json.dumps(
                    {
                        "target_url": "https://example.com/valid",
                        "method": "GET",
                        "status_code": 200,
                    }
                ),
                "2026-08-04T10:00:00+00:00",
            ),
            (
                "evidence-malformed",
                "execution-test",
                "controlled_validation_observation",
                "b" * 64,
                "{not-json",
                "2026-08-04T11:00:00+00:00",
            ),
        ],
    )

    repository = ReadOnlySaarthiRepository()
    observation = (
        repository._load_controlled_validation_observation(
            connection,
            {"evidence"},
            "execution-test",
        )
    )

    assert observation is not None
    assert observation["evidence_id"] == "evidence-valid"
    assert observation["target_url"] == "https://example.com/valid"


def test_controlled_observation_missing_fields_use_safe_defaults() -> None:
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        INSERT INTO evidence (
            execution_id,
            evidence_type,
            metadata_json
        )
        VALUES (?, ?, ?)
        """,
        (
            "execution-test",
            "controlled_validation_observation",
            "{}",
        ),
    )

    repository = ReadOnlySaarthiRepository()
    observation = (
        repository._load_controlled_validation_observation(
            connection,
            {"evidence"},
            "execution-test",
        )
    )

    assert observation is not None
    assert observation["evidence_id"] == "—"
    assert observation["evidence_sha256"] == "—"
    assert observation["target_url"] == "—"
    assert observation["status_code"] == "—"
    assert observation["body_bytes_captured"] == "0"
    assert observation["body_truncated"] == "false"
    assert observation["network_activity"] == "false"
    assert observation["request_attempted"] == "false"
    assert observation["follow_redirects"] == "false"


def test_controlled_observation_selects_newest_valid_record() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.executemany(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                "evidence-old",
                "execution-test",
                "controlled_validation_observation",
                json.dumps({"status_code": 200}),
                "2026-08-04T10:00:00+00:00",
            ),
            (
                "evidence-new",
                "execution-test",
                "controlled_validation_observation",
                json.dumps({"status_code": 204}),
                "2026-08-04T11:00:00+00:00",
            ),
        ],
    )

    repository = ReadOnlySaarthiRepository()
    observation = (
        repository._load_controlled_validation_observation(
            connection,
            {"evidence"},
            "execution-test",
        )
    )

    assert observation is not None
    assert observation["evidence_id"] == "evidence-new"
    assert observation["status_code"] == "204"


def test_loads_matching_controlled_observation_reuse_event() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE audit_events (
            execution_id TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.executemany(
        """
        INSERT INTO audit_events (
            execution_id,
            details_json,
            created_at
        )
        VALUES (?, ?, ?)
        """,
        [
            (
                "execution-test",
                json.dumps(
                    {
                        "evidence_id": "different-evidence",
                        "idempotent_reuse": True,
                        "second_request_sent": False,
                    }
                ),
                "2026-08-04T10:00:00+00:00",
            ),
            (
                "execution-test",
                json.dumps(
                    {
                        "evidence_id": "evidence-observation",
                        "idempotent_reuse": True,
                        "second_request_sent": False,
                    }
                ),
                "2026-08-04T11:00:00+00:00",
            ),
        ],
    )

    repository = ReadOnlySaarthiRepository()
    reuse = repository._load_controlled_observation_reuse(
        connection,
        {"audit_events"},
        "execution-test",
        "evidence-observation",
    )

    assert reuse == {
        "reused_existing_evidence": "true",
        "second_request_sent": "false",
    }


def test_controlled_observation_reuse_defaults_without_audit_data() -> None:
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    repository = ReadOnlySaarthiRepository()

    assert repository._load_controlled_observation_reuse(
        connection,
        set(),
        "execution-test",
        "evidence-observation",
    ) == {
        "reused_existing_evidence": "false",
        "second_request_sent": "—",
    }


def test_safe_tui_display_escapes_markup() -> None:
    from saarthi_ai.tui.app import safe_tui_display

    rendered = safe_tui_display(
        "[red]forged alert[/red]"
    )

    assert rendered == (
        r"\[red]forged alert\[/red]"
    )


def test_safe_tui_display_bounds_long_values() -> None:
    from saarthi_ai.tui.app import safe_tui_display

    rendered = safe_tui_display(
        "x" * 200,
        max_length=32,
    )

    assert len(rendered) == 32
    assert rendered.endswith("…")


def test_safe_tui_display_redacts_sensitive_assignment() -> None:
    from saarthi_ai.tui.app import safe_tui_display

    rendered = safe_tui_display(
        "https://example.test/path?token=super-secret&view=1"
    )

    assert "super-secret" not in rendered
    assert "token=[REDACTED]" in rendered
    assert "view=1" in rendered


def test_safe_tui_display_redacts_url_user_information() -> None:
    from saarthi_ai.tui.app import safe_tui_display

    rendered = safe_tui_display(
        "https://operator:password@example.test/account"
    )

    assert "operator" not in rendered
    assert "password" not in rendered
    assert (
        "https://[REDACTED]@example.test/account"
        in rendered
    )


def test_safe_tui_display_flattens_embedded_lines() -> None:
    from saarthi_ai.tui.app import safe_tui_display

    rendered = safe_tui_display(
        "first line\nsecond line\tthird"
    )

    assert rendered == "first line second line third"


def test_safe_tui_display_rejects_complex_values() -> None:
    from saarthi_ai.tui.app import safe_tui_display

    rendered = safe_tui_display(
        {
            "token": "must-not-render",
            "headers": {"Authorization": "secret"},
        }
    )

    assert "must-not-render" not in rendered
    assert "Authorization" not in rendered
    assert rendered == r"\[unsupported value]"


def test_safe_tui_display_rejects_invalid_bound() -> None:
    import pytest

    from saarthi_ai.tui.app import safe_tui_display

    with pytest.raises(
        ValueError,
        match="max_length must be at least 2",
    ):
        safe_tui_display("value", max_length=1)


def test_planned_nuclei_preview_maps_to_phase_6c() -> None:
    assert (
        infer_phase(
            "planned",
            {"controlled_nuclei_preview"},
        )
        == "6C — NUCLEI VALIDATOR PREVIEW"
    )


def test_created_nuclei_preview_maps_to_phase_6c() -> None:
    assert (
        infer_phase(
            "created",
            {"controlled_nuclei_preview"},
        )
        == "6C — NUCLEI VALIDATOR PREVIEW"
    )


def test_nuclei_preview_compact_phase_is_6c() -> None:
    assert (
        infer_phase_short(
            "planned",
            {"controlled_nuclei_preview"},
        )
        == "6C"
    )


def test_loads_safe_controlled_nuclei_preview() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            sha256 TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            sha256,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "evidence-nuclei-preview",
            "execution-test",
            "controlled_nuclei_preview",
            "a" * 64,
            json.dumps(
                {
                    "target_url": "https://example.com/",
                    "arguments": [
                        "-u",
                        "https://example.com/",
                        "-tags",
                        "exposure,misconfig,tech",
                        "-exclude-tags",
                        (
                            "bruteforce,dos,fuzz,headless,"
                            "intrusive,token-spray"
                        ),
                    ],
                    "rate_limit_per_second": 2,
                    "concurrency": 2,
                    "timeout_seconds": 7,
                    "executed": False,
                    "network_activity": False,
                    "subprocess_started": False,
                }
            ),
            "2026-08-05T08:00:00+00:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()
    preview = repository._load_controlled_nuclei_preview(
        connection,
        {"evidence"},
        "execution-test",
    )

    assert preview is not None
    assert preview["evidence_id"] == "evidence-nuclei-preview"
    assert preview["tool_name"] == "nuclei"
    assert preview["target_url"] == "https://example.com/"
    assert preview["rate_limit_per_second"] == "2"
    assert preview["concurrency"] == "2"
    assert preview["timeout_seconds"] == "7"
    assert preview["allowed_tags"] == "exposure,misconfig,tech"
    assert (
        preview["excluded_tags"]
        == "bruteforce,dos,fuzz,headless,intrusive,token-spray"
    )
    assert preview["executed"] == "false"
    assert preview["network_activity"] == "false"
    assert preview["subprocess_started"] == "false"


def test_nuclei_preview_skips_newest_malformed_metadata() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.executemany(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                "evidence-valid-preview",
                "execution-test",
                "controlled_nuclei_preview",
                json.dumps(
                    {
                        "target_url": "https://example.com/",
                        "executed": False,
                    }
                ),
                "2026-08-05T08:00:00+00:00",
            ),
            (
                "evidence-malformed-preview",
                "execution-test",
                "controlled_nuclei_preview",
                "{not-json",
                "2026-08-05T09:00:00+00:00",
            ),
        ],
    )

    repository = ReadOnlySaarthiRepository()
    preview = repository._load_controlled_nuclei_preview(
        connection,
        {"evidence"},
        "execution-test",
    )

    assert preview is not None
    assert preview["evidence_id"] == "evidence-valid-preview"
    assert preview["target_url"] == "https://example.com/"


def test_nuclei_preview_missing_fields_use_safe_defaults() -> None:
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        INSERT INTO evidence (
            execution_id,
            evidence_type,
            metadata_json
        )
        VALUES (?, ?, ?)
        """,
        (
            "execution-test",
            "controlled_nuclei_preview",
            "{}",
        ),
    )

    repository = ReadOnlySaarthiRepository()
    preview = repository._load_controlled_nuclei_preview(
        connection,
        {"evidence"},
        "execution-test",
    )

    assert preview is not None
    assert preview["evidence_id"] == "—"
    assert preview["evidence_sha256"] == "—"
    assert preview["target_url"] == "—"
    assert preview["arguments"] == "—"
    assert preview["executed"] == "false"
    assert preview["network_activity"] == "false"
    assert preview["subprocess_started"] == "false"


def test_loads_matching_nuclei_preview_reuse_event() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE audit_events (
            execution_id TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
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
            "execution-test",
            json.dumps(
                {
                    "tool": "nuclei",
                    "evidence_id": "evidence-nuclei-preview",
                    "idempotent_reuse": True,
                }
            ),
            "2026-08-05T09:00:00+00:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()

    assert repository._load_nuclei_preview_reuse(
        connection,
        {"audit_events"},
        "execution-test",
        "evidence-nuclei-preview",
    ) == {
        "reused_existing_evidence": "true",
    }


def test_scope_lines_render_controlled_nuclei_preview() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        current_phase="6C — NUCLEI VALIDATOR PREVIEW",
        execution_state="planned",
        controlled_nuclei_preview={
            "evidence_id": "evidence-nuclei-preview",
            "evidence_sha256": "a" * 64,
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
            "arguments": (
                "-u https://example.com/ -jsonl -silent "
                "-rate-limit 1 -concurrency 1 -timeout 10"
            ),
            "rate_limit_per_second": "1",
            "concurrency": "1",
            "timeout_seconds": "10",
            "allowed_tags": "exposure,misconfig,tech",
            "excluded_tags": (
                "bruteforce,dos,fuzz,headless,"
                "intrusive,token-spray"
            ),
            "executed": "false",
            "network_activity": "false",
            "subprocess_started": "false",
            "reused_existing_evidence": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "CONTROLLED NUCLEI PREVIEW" in rendered
    assert "evidence-nuclei-preview" in rendered
    assert "nuclei · https://example.com/" in rendered
    assert "1 req/s · 1" in rendered
    assert "10 seconds" in rendered
    assert "exposure,misconfig,tech" in rendered
    assert "Executed           : false" in rendered
    assert "Network Activity   : false" in rendered
    assert "Subprocess Started : false" in rendered
    assert "Evidence Reused    : false" in rendered
    assert "Nuclei was not started" in rendered
    assert "no network request was sent" in rendered


def test_controlled_observation_has_render_priority_over_nuclei() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        controlled_observation={
            "evidence_id": "evidence-observation",
            "target_url": "https://example.com/account",
            "action": "response_differential",
            "method": "HEAD",
            "status_code": "200",
            "body_bytes_captured": "0",
            "body_truncated": "false",
            "body_sha256": "—",
            "plan_evidence_id": "evidence-plan",
            "network_activity": "true",
            "request_attempted": "true",
            "reused_existing_evidence": "false",
            "second_request_sent": "—",
            "follow_redirects": "false",
            "evidence_sha256": "a" * 64,
        },
        controlled_nuclei_preview={
            "evidence_id": "evidence-nuclei-preview",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "CONTROLLED OBSERVATION" in rendered
    assert "evidence-observation" in rendered
    assert "CONTROLLED NUCLEI PREVIEW" not in rendered
    assert "evidence-nuclei-preview" not in rendered


def test_nuclei_preview_rendering_escapes_and_redacts_values() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        controlled_nuclei_preview={
            "evidence_id": "[red]forged[/red]",
            "evidence_sha256": "a" * 64,
            "tool_name": "nuclei",
            "target_url": (
                "https://operator:password@example.test/"
                "?token=super-secret"
            ),
            "arguments": "x" * 500,
            "rate_limit_per_second": "1",
            "concurrency": "1",
            "timeout_seconds": "10",
            "allowed_tags": "exposure",
            "excluded_tags": "dos",
            "executed": "false",
            "network_activity": "false",
            "subprocess_started": "false",
            "reused_existing_evidence": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert r"\[red]forged\[/red]" in rendered
    assert "operator" not in rendered
    assert "password" not in rendered
    assert "super-secret" not in rendered
    assert "[REDACTED]" in rendered
    assert "x" * 121 not in rendered


def test_scope_lines_without_controlled_evidence_remain_normal() -> None:
    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    rendered = "\n".join(build_scope_lines(demo_snapshot()))

    assert "Project Name" in rendered
    assert "CONTROLLED OBSERVATION" not in rendered
    assert "CONTROLLED NUCLEI PREVIEW" not in rendered


def test_nuclei_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    nuclei_rows = [
        row
        for row in TOOLS
        if row[0] == "nuclei"
    ]

    assert nuclei_rows == [
        (
            "nuclei",
            "Controlled Preview / Execution",
            "APPROVAL",
        )
    ]


def test_planned_nuclei_preparation_maps_to_phase_6c() -> None:
    assert (
        infer_phase(
            "planned",
            {"controlled_nuclei_preparation"},
        )
        == "6C — NUCLEI VALIDATOR PREPARATION"
    )


def test_nuclei_preparation_takes_precedence_over_preview() -> None:
    assert (
        infer_phase(
            "planned",
            {
                "controlled_nuclei_preview",
                "controlled_nuclei_preparation",
            },
        )
        == "6C — NUCLEI VALIDATOR PREPARATION"
    )


def test_nuclei_preparation_compact_phase_is_6c() -> None:
    assert (
        infer_phase_short(
            "planned",
            {"controlled_nuclei_preparation"},
        )
        == "6C"
    )


def test_loads_safe_controlled_nuclei_preparation() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            sha256 TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            sha256,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "evidence-nuclei-preparation",
            "execution-test",
            "controlled_nuclei_preparation",
            "b" * 64,
            json.dumps(
                {
                    "preview_evidence_id": (
                        "evidence-nuclei-preview"
                    ),
                    "target_url": "https://example.com/",
                    "arguments": [
                        "-u",
                        "https://example.com/",
                        "-jsonl",
                        "-silent",
                        "-rate-limit",
                        "1",
                        "-concurrency",
                        "1",
                        "-timeout",
                        "7",
                    ],
                    "rate_limit_per_second": 1,
                    "concurrency": 1,
                    "request_timeout_seconds": 7,
                    "process_timeout_seconds": 120,
                    "max_output_bytes": 1_000_000,
                    "executed": False,
                    "network_activity": False,
                    "subprocess_started": False,
                    "runner_invoked": False,
                    "executable_resolved": False,
                }
            ),
            "2026-08-05T10:00:00+00:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()
    preparation = (
        repository._load_controlled_nuclei_preparation(
            connection,
            {"evidence"},
            "execution-test",
        )
    )

    assert preparation is not None
    assert (
        preparation["evidence_id"]
        == "evidence-nuclei-preparation"
    )
    assert (
        preparation["preview_evidence_id"]
        == "evidence-nuclei-preview"
    )
    assert preparation["tool_name"] == "nuclei"
    assert preparation["target_url"] == "https://example.com/"
    assert preparation["rate_limit_per_second"] == "1"
    assert preparation["concurrency"] == "1"
    assert preparation["request_timeout_seconds"] == "7"
    assert preparation["process_timeout_seconds"] == "120"
    assert preparation["max_output_bytes"] == "1000000"
    assert preparation["executed"] == "false"
    assert preparation["network_activity"] == "false"
    assert preparation["subprocess_started"] == "false"
    assert preparation["runner_invoked"] == "false"
    assert preparation["executable_resolved"] == "false"
    assert preparation["reused_existing_evidence"] == "false"


def test_nuclei_preparation_skips_newest_malformed_metadata() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.executemany(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                "evidence-valid-preparation",
                "execution-test",
                "controlled_nuclei_preparation",
                json.dumps(
                    {
                        "target_url": "https://example.com/",
                        "executed": False,
                    }
                ),
                "2026-08-05T10:00:00+00:00",
            ),
            (
                "evidence-malformed-preparation",
                "execution-test",
                "controlled_nuclei_preparation",
                "{not-json",
                "2026-08-05T11:00:00+00:00",
            ),
        ],
    )

    repository = ReadOnlySaarthiRepository()
    preparation = (
        repository._load_controlled_nuclei_preparation(
            connection,
            {"evidence"},
            "execution-test",
        )
    )

    assert preparation is not None
    assert (
        preparation["evidence_id"]
        == "evidence-valid-preparation"
    )
    assert preparation["target_url"] == "https://example.com/"


def test_nuclei_preparation_missing_fields_use_safe_defaults() -> None:
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE evidence (
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            metadata_json TEXT NOT NULL
        )
        """
    )

    connection.execute(
        """
        INSERT INTO evidence (
            execution_id,
            evidence_type,
            metadata_json
        )
        VALUES (?, ?, ?)
        """,
        (
            "execution-test",
            "controlled_nuclei_preparation",
            "{}",
        ),
    )

    repository = ReadOnlySaarthiRepository()
    preparation = (
        repository._load_controlled_nuclei_preparation(
            connection,
            {"evidence"},
            "execution-test",
        )
    )

    assert preparation is not None
    assert preparation["evidence_id"] == "—"
    assert preparation["evidence_sha256"] == "—"
    assert preparation["preview_evidence_id"] == "—"
    assert preparation["target_url"] == "—"
    assert preparation["arguments"] == "—"
    assert preparation["executed"] == "false"
    assert preparation["network_activity"] == "false"
    assert preparation["subprocess_started"] == "false"
    assert preparation["runner_invoked"] == "false"
    assert preparation["executable_resolved"] == "false"


def test_loads_matching_nuclei_preparation_reuse_event() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row

    connection.execute(
        """
        CREATE TABLE audit_events (
            execution_id TEXT NOT NULL,
            details_json TEXT NOT NULL,
            created_at TEXT NOT NULL
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
            "execution-test",
            json.dumps(
                {
                    "phase_code": "6C",
                    "tool": "nuclei",
                    "evidence_id": (
                        "evidence-nuclei-preparation"
                    ),
                    "idempotent_reuse": True,
                }
            ),
            "2026-08-05T11:00:00+00:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()

    assert repository._load_nuclei_preparation_reuse(
        connection,
        {"audit_events"},
        "execution-test",
        "evidence-nuclei-preparation",
    ) == {
        "reused_existing_evidence": "true",
    }


def test_scope_lines_render_controlled_nuclei_preparation() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        current_phase="6C — NUCLEI VALIDATOR PREPARATION",
        execution_state="planned",
        controlled_nuclei_preparation={
            "evidence_id": "evidence-nuclei-preparation",
            "evidence_sha256": "b" * 64,
            "preview_evidence_id": "evidence-nuclei-preview",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
            "arguments": (
                "-u https://example.com/ -jsonl -silent "
                "-rate-limit 1 -concurrency 1 -timeout 7"
            ),
            "rate_limit_per_second": "1",
            "concurrency": "1",
            "request_timeout_seconds": "7",
            "process_timeout_seconds": "120",
            "max_output_bytes": "1000000",
            "executed": "false",
            "network_activity": "false",
            "subprocess_started": "false",
            "runner_invoked": "false",
            "executable_resolved": "false",
            "reused_existing_evidence": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "CONTROLLED NUCLEI PREPARATION" in rendered
    assert "evidence-nuclei-preparation" in rendered
    assert "evidence-nuclei-preview" in rendered
    assert "nuclei · https://example.com/" in rendered
    assert "1 req/s · 1" in rendered
    assert "Request Timeout    : 7 seconds" in rendered
    assert "Process Timeout    : 120 seconds" in rendered
    assert "Output Cap / Stream: 1000000 bytes" in rendered
    assert "Executed           : false" in rendered
    assert "Network Activity   : false" in rendered
    assert "Subprocess Started : false" in rendered
    assert "Runner Invoked     : false" in rendered
    assert "Executable Resolved: false" in rendered
    assert "Evidence Reused    : false" in rendered
    assert "runner was not invoked" in rendered
    assert "no executable was resolved" in rendered
    assert "Nuclei was not started" in rendered
    assert "no network request was sent" in rendered


def test_nuclei_preparation_has_priority_over_preview() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        controlled_nuclei_preparation={
            "evidence_id": "evidence-nuclei-preparation",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
        },
        controlled_nuclei_preview={
            "evidence_id": "evidence-nuclei-preview",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "CONTROLLED NUCLEI PREPARATION" in rendered
    assert "evidence-nuclei-preparation" in rendered
    assert "CONTROLLED NUCLEI PREVIEW" not in rendered
    assert "evidence-nuclei-preview" not in rendered


def test_controlled_observation_has_priority_over_preparation() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        controlled_observation={
            "evidence_id": "evidence-observation",
            "target_url": "https://example.com/account",
            "action": "response_differential",
            "method": "HEAD",
            "status_code": "200",
            "body_bytes_captured": "0",
            "body_truncated": "false",
            "body_sha256": "—",
            "plan_evidence_id": "evidence-plan",
            "network_activity": "true",
            "request_attempted": "true",
            "reused_existing_evidence": "false",
            "second_request_sent": "—",
            "follow_redirects": "false",
            "evidence_sha256": "a" * 64,
        },
        controlled_nuclei_preparation={
            "evidence_id": "evidence-nuclei-preparation",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "CONTROLLED OBSERVATION" in rendered
    assert "evidence-observation" in rendered
    assert "CONTROLLED NUCLEI PREPARATION" not in rendered
    assert "evidence-nuclei-preparation" not in rendered


def test_nuclei_preparation_rendering_escapes_and_redacts() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        controlled_nuclei_preparation={
            "evidence_id": "[red]forged[/red]",
            "evidence_sha256": "b" * 64,
            "preview_evidence_id": "[blue]preview[/blue]",
            "tool_name": "nuclei",
            "target_url": (
                "https://operator:password@example.test/"
                "?token=super-secret"
            ),
            "arguments": "x" * 500,
            "rate_limit_per_second": "1",
            "concurrency": "1",
            "request_timeout_seconds": "7",
            "process_timeout_seconds": "120",
            "max_output_bytes": "1000000",
            "executed": "false",
            "network_activity": "false",
            "subprocess_started": "false",
            "runner_invoked": "false",
            "executable_resolved": "false",
            "reused_existing_evidence": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert r"\[red]forged\[/red]" in rendered
    assert r"\[blue]preview\[/blue]" in rendered
    assert "operator" not in rendered
    assert "password" not in rendered
    assert "super-secret" not in rendered
    assert "[REDACTED]" in rendered
    assert "x" * 121 not in rendered


def test_completed_nuclei_execution_maps_to_official_phase_6c() -> None:
    assert (
        infer_phase(
            "completed",
            {"controlled_nuclei_execution"},
        )
        == "6C — LOW-RISK NUCLEI VALIDATOR"
    )
    assert (
        infer_phase_short(
            "completed",
            {"controlled_nuclei_execution"},
        )
        == "6C"
    )


def test_failed_nuclei_execution_maps_to_phase_6c_review() -> None:
    assert (
        infer_phase(
            "failed",
            {"controlled_nuclei_execution"},
        )
        == "6C — LOW-RISK NUCLEI VALIDATOR REVIEW"
    )


def test_loads_safe_controlled_nuclei_execution() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            sha256 TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            sha256,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "evidence-nuclei-execution",
            "execution-test",
            "controlled_nuclei_execution",
            "c" * 64,
            json.dumps(
                {
                    "phase": "6C",
                    "preparation_evidence_id": (
                        "evidence-nuclei-preparation"
                    ),
                    "target_url": "https://example.com/",
                    "executable": "/opt/homebrew/bin/nuclei",
                    "arguments": [
                        "-u",
                        "https://example.com/",
                        "-retries",
                        "0",
                    ],
                    "exit_code": 0,
                    "timed_out": False,
                    "stdout_bytes": 128,
                    "stderr_bytes": 0,
                    "stdout_truncated": False,
                    "stderr_truncated": False,
                    "started_at": "2026-08-06T08:00:00+00:00",
                    "completed_at": "2026-08-06T08:00:02+00:00",
                    "executed": True,
                    "network_activity": True,
                    "subprocess_started": True,
                    "runner_invoked": True,
                    "executable_resolved": True,
                    "automatic_retry": False,
                }
            ),
            "2026-08-06T08:00:03+00:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()
    execution = repository._load_controlled_nuclei_execution(
        connection,
        {"evidence"},
        "execution-test",
    )

    assert execution is not None
    assert execution["evidence_id"] == "evidence-nuclei-execution"
    assert execution["evidence_sha256"] == "c" * 64
    assert (
        execution["preparation_evidence_id"]
        == "evidence-nuclei-preparation"
    )
    assert execution["tool_name"] == "nuclei"
    assert execution["target_url"] == "https://example.com/"
    assert execution["executable"] == "/opt/homebrew/bin/nuclei"
    assert execution["arguments"].endswith("-retries 0")
    assert execution["exit_code"] == "0"
    assert execution["timed_out"] == "false"
    assert execution["stdout_bytes"] == "128"
    assert execution["stderr_bytes"] == "0"
    assert execution["executed"] == "true"
    assert execution["network_activity"] == "true"
    assert execution["subprocess_started"] == "true"
    assert execution["runner_invoked"] == "true"
    assert execution["executable_resolved"] == "true"
    assert execution["automatic_retry"] == "false"


def test_scope_lines_render_controlled_nuclei_execution() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        current_phase="6C — LOW-RISK NUCLEI VALIDATOR",
        execution_state="completed",
        controlled_nuclei_execution={
            "evidence_id": "evidence-nuclei-execution",
            "evidence_sha256": "c" * 64,
            "preparation_evidence_id": (
                "evidence-nuclei-preparation"
            ),
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
            "executable": "/opt/homebrew/bin/nuclei",
            "arguments": "-u https://example.com/ -retries 0",
            "exit_code": "0",
            "timed_out": "false",
            "stdout_bytes": "128",
            "stderr_bytes": "0",
            "stdout_truncated": "false",
            "stderr_truncated": "false",
            "started_at": "2026-08-06T08:00:00+00:00",
            "completed_at": "2026-08-06T08:00:02+00:00",
            "executed": "true",
            "network_activity": "true",
            "subprocess_started": "true",
            "runner_invoked": "true",
            "executable_resolved": "true",
            "automatic_retry": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "CONTROLLED NUCLEI EXECUTION" in rendered
    assert "evidence-nuclei-execution" in rendered
    assert "evidence-nuclei-preparation" in rendered
    assert "nuclei · https://example.com/" in rendered
    assert "/opt/homebrew/bin/nuclei" in rendered
    assert "Exit / Timed Out   : 0 · false" in rendered
    assert "Output Bytes       : stdout 128 · stderr 0" in rendered
    assert "Executed           : true" in rendered
    assert "Network Activity   : true" in rendered
    assert "Subprocess Started : true" in rendered
    assert "Runner Invoked     : true" in rendered
    assert "Executable Resolved: true" in rendered
    assert "Automatic Retry    : false" in rendered
    assert "Read-only Phase 6C execution evidence" in rendered


def test_nuclei_execution_has_priority_over_preparation() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        controlled_nuclei_execution={
            "evidence_id": "evidence-nuclei-execution",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
        },
        controlled_nuclei_preparation={
            "evidence_id": "evidence-nuclei-preparation",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "CONTROLLED NUCLEI EXECUTION" in rendered
    assert "evidence-nuclei-execution" in rendered
    assert "CONTROLLED NUCLEI PREPARATION" not in rendered
    assert "evidence-nuclei-preparation" not in rendered


def test_attack_hypothesis_set_maps_to_official_phase_6a() -> None:
    assert (
        infer_phase(
            "created",
            {"attack_hypothesis_set"},
        )
        == "6A — ATTACK HYPOTHESIS & PATH GENERATION"
    )
    assert (
        infer_phase_short(
            "created",
            {"attack_hypothesis_set"},
        )
        == "6A"
    )
    assert (
        infer_phase(
            "failed",
            {"attack_hypothesis_set"},
        )
        == "6A — ATTACK HYPOTHESIS REVIEW"
    )


def test_loads_safe_attack_hypothesis_summary() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            sha256 TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            sha256,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "evidence-hypothesis-set",
            "execution-test",
            "attack_hypothesis_set",
            "d" * 64,
            json.dumps(
                {
                    "phase": "6A",
                    "target_url": "https://example.com/",
                    "hypothesis_count": 2,
                    "hypothesis_ids": [
                        "hypothesis-one",
                        "hypothesis-two",
                    ],
                    "families": [
                        "api_business_logic",
                        "injection",
                    ],
                    "considered_evidence_ids": [
                        "evidence-crawl",
                        "evidence-js",
                    ],
                    "rejected_evidence_ids": [],
                    "truncated": False,
                    "executed": False,
                    "network_activity": False,
                    "payload_generated": False,
                    "subprocess_started": False,
                }
            ),
            "2026-08-06T09:00:00+00:00",
        ),
    )

    repository = ReadOnlySaarthiRepository()
    summary = repository._load_attack_hypothesis_set(
        connection,
        {"evidence"},
        "execution-test",
    )

    assert summary is not None
    assert summary["evidence_id"] == "evidence-hypothesis-set"
    assert summary["evidence_sha256"] == "d" * 64
    assert summary["target_url"] == "https://example.com/"
    assert summary["hypothesis_count"] == "2"
    assert summary["families"] == "api_business_logic, injection"
    assert summary["hypothesis_ids"] == (
        "hypothesis-one, hypothesis-two"
    )
    assert summary["considered_evidence_count"] == "2"
    assert summary["rejected_evidence_count"] == "0"
    assert summary["truncated"] == "false"
    assert summary["executed"] == "false"
    assert summary["network_activity"] == "false"
    assert summary["payload_generated"] == "false"
    assert summary["subprocess_started"] == "false"


def test_scope_lines_render_attack_hypothesis_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        current_phase="6A — ATTACK HYPOTHESIS & PATH GENERATION",
        attack_hypothesis_set={
            "evidence_id": "evidence-hypothesis-set",
            "evidence_sha256": "d" * 64,
            "target_url": "https://example.com/",
            "hypothesis_count": "2",
            "families": "api_business_logic, injection",
            "hypothesis_ids": (
                "hypothesis-one, hypothesis-two"
            ),
            "considered_evidence_count": "2",
            "rejected_evidence_count": "0",
            "truncated": "false",
            "executed": "false",
            "network_activity": "false",
            "payload_generated": "false",
            "subprocess_started": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "PHASE 6A — ATTACK HYPOTHESES" in rendered
    assert "evidence-hypothesis-set" in rendered
    assert "Hypothesis Count   : 2" in rendered
    assert "api_business_logic, injection" in rendered
    assert "Evidence Considered: 2" in rendered
    assert "Evidence Rejected  : 0" in rendered
    assert "Executed           : false" in rendered
    assert "Network Activity   : false" in rendered
    assert "Payload Generated  : false" in rendered
    assert "Subprocess Started : false" in rendered
    assert "No validation or security test was executed" in rendered


def test_attack_hypothesis_summary_has_render_priority() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set={
            "evidence_id": "evidence-hypothesis-set",
            "target_url": "https://example.com/",
        },
        controlled_nuclei_execution={
            "evidence_id": "evidence-nuclei-execution",
            "tool_name": "nuclei",
            "target_url": "https://example.com/",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "PHASE 6A — ATTACK HYPOTHESES" in rendered
    assert "evidence-hypothesis-set" in rendered
    assert "CONTROLLED NUCLEI EXECUTION" not in rendered
    assert "evidence-nuclei-execution" not in rendered


def test_attack_hypothesis_tool_row_is_enabled() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6A",
        "Attack Hypothesis Engine",
        "ENABLED",
    ) in TOOLS


def test_loads_linked_phase_6b_plan_summary() -> None:
    import json
    import sqlite3

    from saarthi_ai.tui.app import ReadOnlySaarthiRepository

    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        """
        CREATE TABLE evidence (
            evidence_id TEXT PRIMARY KEY,
            execution_id TEXT NOT NULL,
            evidence_type TEXT NOT NULL,
            sha256 TEXT,
            metadata_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.execute(
        """
        INSERT INTO evidence (
            evidence_id,
            execution_id,
            evidence_type,
            sha256,
            metadata_json,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "evidence-plan",
            "execution-validation",
            "controlled_validation_plan",
            "e" * 64,
            json.dumps(
                {
                    "phase": "6B",
                    "target_url": "https://example.com/",
                    "action": "input_handling_observation",
                    "risk": "low",
                    "policy_decision": "allow",
                    "requested_requests": 2,
                    "source_execution_id": "execution-source",
                    "source_hypothesis_evidence_id": (
                        "evidence-hypotheses"
                    ),
                    "source_hypothesis_id": "hypothesis-test",
                    "executed": False,
                    "network_activity": False,
                }
            ),
            "2026-08-06T10:00:00+00:00",
        ),
    )

    summary = (
        ReadOnlySaarthiRepository()._load_controlled_validation_plan(
            connection,
            {"evidence"},
            "execution-validation",
        )
    )

    assert summary is not None
    assert summary["execution_id"] == "execution-validation"
    assert summary["evidence_id"] == "evidence-plan"
    assert summary["source_execution_id"] == "execution-source"
    assert summary["source_hypothesis_id"] == "hypothesis-test"
    assert summary["action"] == "input_handling_observation"
    assert summary["policy_decision"] == "allow"
    assert summary["executed"] == "false"
    assert summary["network_activity"] == "false"


def test_scope_lines_render_linked_phase_6b_plan() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        current_phase="6B — CONTROLLED VALIDATION PLAN",
        attack_hypothesis_set=None,
        controlled_validation_plan={
            "execution_id": "execution-validation",
            "evidence_id": "evidence-plan",
            "source_execution_id": "execution-source",
            "source_hypothesis_evidence_id": "evidence-hypotheses",
            "source_hypothesis_id": "hypothesis-test",
            "target_url": "https://example.com/",
            "action": "input_handling_observation",
            "risk": "low",
            "policy_decision": "allow",
            "requested_requests": "2",
            "executed": "false",
            "network_activity": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "PHASE 6B — POLICY & APPROVAL GATE" in rendered
    assert "execution-validation" in rendered
    assert "execution-source" in rendered
    assert "hypothesis-test" in rendered
    assert "input_handling_observation / low" in rendered
    assert "Policy Decision     : allow" in rendered
    assert "Executed            : false" in rendered
    assert "Network Activity    : false" in rendered
    assert "No validation request was sent" in rendered


def test_phase_6b_policy_gate_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6B",
        "Policy & Approval Gate",
        "APPROVAL",
    ) in TOOLS


def test_scope_lines_render_clickjacking_validator_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-clickjacking",
            "target_url": "https://example.com/",
            "action": "clickjacking_header_validation",
            "method": "HEAD",
            "status_code": "200",
            "validator_id": (
                "6C.2-clickjacking-header-validation"
            ),
            "validator_classification": "protected",
            "validator_reason": (
                "Restrictive frame policy observed."
            ),
            "protection_sources": "csp_frame_ancestors",
            "header_only": "true",
            "exploit_page_generated": "false",
            "browser_launched": "false",
            "payload_generated": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.2 — CLICKJACKING HEADER VALIDATION" in rendered
    assert "Classification     : protected" in rendered
    assert "csp_frame_ancestors" in rendered
    assert "Header Only        : true" in rendered
    assert "Exploit Page       : false" in rendered
    assert "Browser Launched   : false" in rendered
    assert "Payload Generated  : false" in rendered


def test_clickjacking_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.2",
        "Clickjacking Header Validator",
        "APPROVAL",
    ) in TOOLS


def test_scope_lines_render_parameter_surface_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-parameter-surface",
            "target_url": "https://example.com/?id=1&id=2",
            "action": "http_parameter_surface_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": (
                "6C.3-http-parameter-surface-validation"
            ),
            "validator_classification": (
                "ambiguous_surface_observed"
            ),
            "validator_reason": (
                "Duplicate parameter name observed."
            ),
            "parameter_count": "2",
            "duplicate_parameter_names": "id",
            "variant_parameter_groups": "—",
            "target_unchanged": "true",
            "parameters_mutated": "false",
            "parser_attack_sent": "false",
            "payload_generated": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.3 — HTTP PARAMETER SURFACE VALIDATION" in rendered
    assert "ambiguous_surface_observed" in rendered
    assert "Parameter Count    : 2" in rendered
    assert "Duplicate Names    : id" in rendered
    assert "Target Unchanged   : true" in rendered
    assert "Parameters Mutated : false" in rendered
    assert "Parser Attack Sent : false" in rendered
    assert "Payload Generated  : false" in rendered


def test_parameter_surface_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.3",
        "HTTP Parameter Surface Validator",
        "APPROVAL",
    ) in TOOLS


def test_scope_lines_render_session_cookie_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-session-cookie",
            "target_url": "https://example.com/",
            "action": "session_cookie_attribute_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": (
                "6C.4-session-cookie-attribute-validation"
            ),
            "validator_classification": "review_recommended",
            "validator_reason": (
                "Cookie attributes require manual review."
            ),
            "cookie_count": "2",
            "cookies_with_issues": "1",
            "issue_counts": "missing_http_only=1",
            "cookie_values_discarded": "true",
            "raw_set_cookie_stored": "false",
            "cookie_replayed": "false",
            "credential_header_sent": "false",
            "payload_generated": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.4 — SESSION COOKIE ATTRIBUTE VALIDATION" in rendered
    assert "Classification     : review_recommended" in rendered
    assert "Cookies / Issues   : 2 / 1" in rendered
    assert "missing_http_only=1" in rendered
    assert "Values Discarded   : true" in rendered
    assert "Raw Header Stored  : false" in rendered
    assert "Cookie Replayed    : false" in rendered
    assert "Credential Sent    : false" in rendered
    assert "Payload Generated  : false" in rendered


def test_session_cookie_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.4",
        "Session Cookie Attribute Validator",
        "APPROVAL",
    ) in TOOLS


def test_scope_lines_render_csrf_surface_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-csrf-surface",
            "target_url": "https://example.com/account",
            "action": "csrf_protection_surface_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": (
                "6C.2-csrf-protection-surface-validation"
            ),
            "validator_classification": (
                "protection_signals_observed"
            ),
            "validator_reason": (
                "Anti-CSRF field signal observed."
            ),
            "post_form_count": "1",
            "forms_with_token_signal": "1",
            "forms_without_token_signal": "0",
            "cross_origin_action_count": "0",
            "protection_sources": "anti_csrf_field_name",
            "token_values_discarded": "true",
            "form_submitted": "false",
            "browser_launched": "false",
            "request_body_sent": "false",
            "payload_generated": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.2 — CSRF PROTECTION SURFACE VALIDATION" in rendered
    assert "protection_signals_observed" in rendered
    assert "POST Forms         : 1" in rendered
    assert "With / Without Token: 1 / 0" in rendered
    assert "anti_csrf_field_name" in rendered
    assert "Tokens Discarded   : true" in rendered
    assert "Form Submitted     : false" in rendered
    assert "Browser Launched   : false" in rendered
    assert "Request Body Sent  : false" in rendered


def test_csrf_surface_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.2",
        "CSRF Protection Surface Validator",
        "APPROVAL",
    ) in TOOLS


def test_scope_lines_render_api_exposure_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-api-exposure",
            "target_url": "https://example.com/api/profile",
            "action": "api_data_exposure_surface_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": (
                "6C.7-api-data-exposure-surface-validation"
            ),
            "validator_classification": "review_recommended",
            "validator_reason": "Aggregate field signals observed.",
            "nodes_inspected": "5",
            "sensitive_category_counts": (
                "credential_material=1, personal_contact=1"
            ),
            "json_keys_discarded": "true",
            "json_values_discarded": "true",
            "raw_json_stored": "false",
            "request_body_sent": "false",
            "authentication_used": "false",
            "payload_generated": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.7 — API DATA-EXPOSURE SURFACE VALIDATION" in rendered
    assert "review_recommended" in rendered
    assert "JSON Nodes         : 5" in rendered
    assert "credential_material=1" in rendered
    assert "Keys Discarded     : true" in rendered
    assert "Values Discarded   : true" in rendered
    assert "Raw JSON Stored    : false" in rendered
    assert "Request Body Sent  : false" in rendered
    assert "Authentication Used: false" in rendered


def test_api_exposure_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.7",
        "API Data-Exposure Surface Validator",
        "APPROVAL",
    ) in TOOLS


def test_scope_lines_render_injection_surface_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-injection-surface",
            "target_url": "https://example.com/search?id=1",
            "action": "injection_surface_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": "6C.1-injection-surface-analysis",
            "validator_classification": (
                "injection_surface_observed"
            ),
            "validator_reason": "Input surfaces require review.",
            "injection_types_covered": "13",
            "observed_surfaces": (
                "SQL Injection=1, Host Header Injection=1"
            ),
            "query_parameter_count": "2",
            "form_input_count": "1",
            "parameter_names_discarded": "true",
            "parameter_values_discarded": "true",
            "response_body_discarded": "true",
            "parameters_mutated": "false",
            "payload_generated": "false",
            "exploit_executed": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.1 — INJECTION SURFACE VALIDATION" in rendered
    assert "Injection Coverage : 13 types" in rendered
    assert "SQL Injection=1" in rendered
    assert "Query / Form Inputs: 2 / 1" in rendered
    assert "Names / Values Gone: true / true" in rendered
    assert "Body Discarded     : true" in rendered
    assert "Parameters Mutated : false" in rendered
    assert "Payload / Exploit  : false / false" in rendered


def test_scope_lines_render_browser_surface_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-browser-surface",
            "target_url": "https://example.com/page?redirect=/home",
            "action": "browser_attack_surface_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": "6C.2-browser-attack-surface-analysis",
            "validator_classification": "review_recommended",
            "validator_reason": "Browser surfaces require review.",
            "browser_attack_types_covered": "11",
            "browser_observed_surfaces": (
                "DOM-Based XSS=1, CORS Exploitation=2"
            ),
            "browser_form_count": "1",
            "form_control_count": "2",
            "script_block_count": "1",
            "postmessage_handler_observed": "true",
            "postmessage_origin_check_observed": "true",
            "websocket_usage_observed": "true",
            "websocket_auth_signal_observed": "false",
            "cors_wildcard_origin": "true",
            "cors_credentials_allowed": "false",
            "source_text_discarded": "true",
            "attribute_values_discarded": "true",
            "browser_launched": "false",
            "script_executed": "false",
            "payload_generated": "false",
            "exploit_executed": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.2 — BROWSER ATTACK SURFACE VALIDATION" in rendered
    assert "Browser Coverage   : 11 types" in rendered
    assert "DOM-Based XSS=1" in rendered
    assert "Forms / Inputs / JS: 1 / 2 / 1" in rendered
    assert "postMessage / Origin: true / true" in rendered
    assert "WebSocket / Auth   : true / false" in rendered
    assert "CORS Wildcard / Cred: true / false" in rendered
    assert "Source / Attr Gone : true / true" in rendered
    assert "Browser / Script   : false / false" in rendered
    assert "Payload / Exploit  : false / false" in rendered


def test_scope_lines_render_server_parser_surface_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-server-parser",
            "target_url": "https://example.com/process?url=/resource",
            "action": "server_parser_surface_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": "6C.3-server-parser-surface-analysis",
            "validator_classification": "review_recommended",
            "validator_reason": "Parser surfaces require review.",
            "server_parser_attack_types": "10",
            "server_parser_observed_surfaces": (
                "Blind SSRF=1, Unsafe URL Fetch=1"
            ),
            "server_query_parameter_count": "1",
            "server_form_control_count": "2",
            "absolute_url_value_count": "0",
            "xml_content_type_observed": "false",
            "serialized_content_type_observed": "false",
            "archive_content_type_observed": "false",
            "parser_payload_sent": "false",
            "callback_generated": "false",
            "parameters_mutated": "false",
            "subprocess_started": "false",
            "payload_generated": "false",
            "exploit_executed": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.3 — SERVER/PARSER SURFACE VALIDATION" in rendered
    assert "Attack Coverage    : 10 types" in rendered
    assert "Blind SSRF=1" in rendered
    assert "Query / Form / URLs: 1 / 2 / 0" in rendered
    assert "XML / Serial / Arch: false / false / false" in rendered
    assert "Parser / Callback  : false / false" in rendered
    assert "Mutation / Process : false / false" in rendered
    assert "Payload / Exploit  : false / false" in rendered


def test_scope_lines_render_upload_surface_summary() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import (
        build_scope_lines,
        demo_snapshot,
    )

    snapshot = replace(
        demo_snapshot(),
        attack_hypothesis_set=None,
        controlled_validation_plan=None,
        controlled_observation={
            "evidence_id": "evidence-upload-surface",
            "target_url": "https://example.com/upload",
            "action": "file_upload_surface_validation",
            "method": "GET",
            "status_code": "200",
            "validator_id": (
                "6C.6-file-upload-surface-validation"
            ),
            "validator_classification": (
                "upload_surface_observed"
            ),
            "validator_reason": "A file-input surface was observed.",
            "upload_form_count": "1",
            "file_input_count": "2",
            "post_upload_form_count": "1",
            "multipart_upload_form_count": "1",
            "restricted_accept_input_count": "1",
            "unrestricted_accept_input_count": "1",
            "field_names_discarded": "true",
            "field_values_discarded": "true",
            "form_actions_discarded": "true",
            "file_uploaded": "false",
            "form_submitted": "false",
            "request_body_sent": "false",
            "payload_generated": "false",
        },
    )

    rendered = "\n".join(build_scope_lines(snapshot))

    assert "6C.6 — FILE UPLOAD SURFACE VALIDATION" in rendered
    assert "upload_surface_observed" in rendered
    assert "Upload Forms       : 1" in rendered
    assert "File Inputs        : 2" in rendered
    assert "POST / Multipart   : 1 / 1" in rendered
    assert "Accept Restricted  : 1" in rendered
    assert "Accept Unrestricted: 1" in rendered
    assert "Names / Values Gone: true / true" in rendered
    assert "Actions Discarded  : true" in rendered
    assert "File Uploaded      : false" in rendered
    assert "Form Submitted     : false" in rendered
    assert "Request Body Sent  : false" in rendered


def test_upload_surface_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.6",
        "File Upload Surface Validator",
        "APPROVAL",
    ) in TOOLS


def test_injection_surface_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.1",
        "Injection Surface Validator",
        "APPROVAL",
    ) in TOOLS


def test_browser_surface_validator_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.2",
        "Browser Attack Surface Validator",
        "APPROVAL",
    ) in TOOLS


def test_server_parser_surface_tool_row_requires_approval() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "Saarthi 6C.3",
        "Server/Parser Surface Validator",
        "APPROVAL",
    ) in TOOLS


def test_tui_lists_all_official_validator_families() -> None:
    from saarthi_ai.tui.app import TOOLS

    family_rows = [
        row
        for row in TOOLS
        if row[0]
        in {
            "Saarthi 6C.1",
            "Saarthi 6C.2",
            "Saarthi 6C.3",
            "Saarthi 6C.4",
            "Saarthi 6C.5",
            "Saarthi 6C.6",
            "Saarthi 6C.7",
        }
        and "total)" in row[1]
    ]

    assert len(family_rows) == 7
    assert (
        "Saarthi 6C.5",
        "Authorization & Access Control (0 ready, 0 partial, 9 total)",
        "PLANNED",
    ) in family_rows


def test_sqlmap_tui_row_shows_handoff_and_import() -> None:
    from saarthi_ai.tui.app import TOOLS

    assert (
        "sqlmap",
        "External Result Handoff / Import",
        "6C.1 HANDOFF",
    ) in TOOLS


def test_worker_rows_do_not_claim_sqlmap_automatic_execution() -> None:
    from saarthi_ai.tui.app import demo_snapshot, worker_rows

    snapshot = demo_snapshot()
    rows = {row[0]: row for row in worker_rows(snapshot)}

    assert rows["sqlmap"] == (
        "sqlmap",
        "External handoff + import",
        "TUI approval",
        "NO LAUNCHER",
    )
    assert rows["ffuf"][-1] == "Not configured"
    assert rows["callback"][-1] == "Not configured"


def test_worker_rows_show_approved_sqlmap_handoff_state() -> None:
    from dataclasses import replace

    from saarthi_ai.tui.app import demo_snapshot, worker_rows

    snapshot = replace(
        demo_snapshot(),
        phase6_chain_status={"sqlmap": "AWAITING RESULT"},
    )
    rows = {row[0]: row for row in worker_rows(snapshot)}

    assert rows["sqlmap"] == (
        "sqlmap",
        "External handoff + import",
        "Approved",
        "AWAITING RESULT · EXTERNAL",
    )
