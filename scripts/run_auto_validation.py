#!/usr/bin/env python3
"""Run automatic Nuclei and SQLMap validation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from saarthi_ai.automation.auto_validation import (
    AutoValidationConfig,
    AutoValidationError,
    SqlmapCandidate,
    run_automatic_validation,
)


def _load_json(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text(
            encoding="utf-8"
        )
    except OSError as exc:
        raise AutoValidationError(
            f"Unable to read configuration file: {exc}"
        ) from exc

    try:
        payload = json.loads(content)
    except json.JSONDecodeError as exc:
        raise AutoValidationError(
            
                f"Invalid JSON in {path}: "
                f"line {exc.lineno}, column {exc.colno}: "
                f"{exc.msg}"
            
        ) from exc

    if not isinstance(payload, dict):
        raise AutoValidationError(
            "The configuration root must be a JSON object."
        )

    return payload


def _required_boolean(
    payload: dict[str, Any],
    name: str,
) -> bool:
    value = payload.get(name)

    if not isinstance(value, bool):
        raise AutoValidationError(
            f"{name!r} must be true or false."
        )

    return value


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run automatic Nuclei and SQLMap validation "
            "against an explicitly authorized target."
        )
    )

    parser.add_argument(
        "config",
        type=Path,
        help="Path to the reviewed JSON configuration.",
    )

    arguments = parser.parse_args()
    raw_config = _load_json(
        arguments.config
    )

    try:
        sqlmap_candidates = tuple(
            SqlmapCandidate(
                url=str(item["url"]),
                parameter=str(item["parameter"]),
                method=str(
                    item.get(
                        "method",
                        "GET",
                    )
                ),
                data=(
                    str(item["data"])
                    if item.get("data") is not None
                    else None
                ),
                content_type=(
                    str(item["content_type"])
                    if item.get("content_type") is not None
                    else None
                ),
            )
            for item in raw_config.get(
                "sqlmap_candidates",
                [],
            )
        )

        config = AutoValidationConfig(
            target_url=str(
                raw_config["target_url"]
            ),
            allowed_hosts=tuple(
                str(host)
                for host in raw_config[
                    "allowed_hosts"
                ]
            ),
            authorized=_required_boolean(
                raw_config,
                "authorized",
            ),
            active_testing=_required_boolean(
                raw_config,
                "active_testing",
            ),
            intrusive_testing=_required_boolean(
                raw_config,
                "intrusive_testing",
            ),
            approved=_required_boolean(
                raw_config,
                "approved",
            ),
            sqlmap_candidates=sqlmap_candidates,
            evidence_root=Path(
                raw_config.get(
                    "evidence_root",
                    "evidence/automatic-validation",
                )
            ),
            nuclei_templates_path=(
                str(
                    raw_config[
                        "nuclei_templates_path"
                    ]
                )
                if raw_config.get(
                    "nuclei_templates_path"
                )
                else None
            ),
            nuclei_rate_limit=int(
                raw_config.get(
                    "nuclei_rate_limit",
                    5,
                )
            ),
            nuclei_concurrency=int(
                raw_config.get(
                    "nuclei_concurrency",
                    5,
                )
            ),
            nuclei_request_timeout_seconds=int(
                raw_config.get(
                    "nuclei_request_timeout_seconds",
                    10,
                )
            ),
            nuclei_process_timeout_seconds=int(
                raw_config.get(
                    "nuclei_process_timeout_seconds",
                    900,
                )
            ),
            sqlmap_level=int(
                raw_config.get(
                    "sqlmap_level",
                    2,
                )
            ),
            sqlmap_risk=int(
                raw_config.get(
                    "sqlmap_risk",
                    1,
                )
            ),
            sqlmap_threads=int(
                raw_config.get(
                    "sqlmap_threads",
                    1,
                )
            ),
            sqlmap_request_timeout_seconds=int(
                raw_config.get(
                    "sqlmap_request_timeout_seconds",
                    10,
                )
            ),
            sqlmap_process_timeout_seconds=int(
                raw_config.get(
                    "sqlmap_process_timeout_seconds",
                    600,
                )
            ),
            sqlmap_techniques=str(
                raw_config.get(
                    "sqlmap_techniques",
                    "BEUSTQ",
                )
            ),
        )

        result = run_automatic_validation(
            config
        )

    except (
        AutoValidationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        print(
            f"[Saarthi] Automatic validation failed: {exc}",
            file=sys.stderr,
        )
        return 1

    print(
        json.dumps(
            {
                "status": "completed",
                "run_id": result.run_id,
                "evidence_path": result.evidence_path,
                "nuclei_exit_code": result.nuclei[
                    "exit_code"
                ],
                "sqlmap_runs": len(
                    result.sqlmap
                ),
            },
            indent=2,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
