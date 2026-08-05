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


def test_completed_controlled_observation_maps_to_phase_6f() -> None:
    assert (
        infer_phase(
            "completed",
            {"controlled_validation_observation"},
        )
        == "6F — CONTROLLED VALIDATION OBSERVATION"
    )


def test_running_controlled_observation_maps_to_phase_6f() -> None:
    assert (
        infer_phase(
            "running",
            {"controlled_validation_observation"},
        )
        == "6F — CONTROLLED VALIDATION OBSERVATION"
    )


def test_failed_controlled_observation_maps_to_phase_6f_review() -> None:
    assert (
        infer_phase(
            "failed",
            {"controlled_validation_observation"},
        )
        == "6F — CONTROLLED VALIDATION REVIEW"
    )


def test_controlled_observation_compact_phase_is_6f() -> None:
    assert (
        infer_phase_short(
            "completed",
            {"controlled_validation_observation"},
        )
        == "6F"
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
                    "action": "response_differential",
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
    assert observation["action"] == "response_differential"
    assert observation["method"] == "HEAD"
    assert observation["status_code"] == "200"
    assert observation["body_bytes_captured"] == "0"
    assert observation["body_truncated"] == "false"
    assert observation["network_activity"] == "true"
    assert observation["request_attempted"] == "true"
    assert observation["follow_redirects"] == "false"
    assert observation["plan_evidence_id"] == "evidence-plan"


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


def test_planned_nuclei_preview_maps_to_phase_6i() -> None:
    assert (
        infer_phase(
            "planned",
            {"controlled_nuclei_preview"},
        )
        == "6I — CONTROLLED NUCLEI PREVIEW"
    )


def test_created_nuclei_preview_maps_to_phase_6i() -> None:
    assert (
        infer_phase(
            "created",
            {"controlled_nuclei_preview"},
        )
        == "6I — CONTROLLED NUCLEI PREVIEW"
    )


def test_nuclei_preview_compact_phase_is_6i() -> None:
    assert (
        infer_phase_short(
            "planned",
            {"controlled_nuclei_preview"},
        )
        == "6I"
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
        current_phase="6I — CONTROLLED NUCLEI PREVIEW",
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


def test_nuclei_tool_row_is_dry_run_only() -> None:
    from saarthi_ai.tui.app import TOOLS

    nuclei_rows = [
        row
        for row in TOOLS
        if row[0] == "nuclei"
    ]

    assert nuclei_rows == [
        (
            "nuclei",
            "Controlled Invocation Preview",
            "DRY-RUN",
        )
    ]


def test_planned_nuclei_preparation_maps_to_phase_6j() -> None:
    assert (
        infer_phase(
            "planned",
            {"controlled_nuclei_preparation"},
        )
        == "6J — CONTROLLED NUCLEI PREPARATION"
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
        == "6J — CONTROLLED NUCLEI PREPARATION"
    )


def test_nuclei_preparation_compact_phase_is_6j() -> None:
    assert (
        infer_phase_short(
            "planned",
            {"controlled_nuclei_preparation"},
        )
        == "6J"
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
                    "phase_code": "6J.2",
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
        current_phase="6J — CONTROLLED NUCLEI PREPARATION",
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
