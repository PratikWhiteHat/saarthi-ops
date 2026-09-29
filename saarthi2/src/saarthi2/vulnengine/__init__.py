"""Vulnerability Identification Engine — the deterministic back half of a run.

The recon + auth *on-ramp* (workflow recon + the autonomous agent) reaches live
hosts and an authenticated session. This package is what happens next, so a run
ends in CONFIRMED findings, not a host list:

    comprehend -> plan -> test -> verify -> report

Only ``comprehend`` (App Model) and payload *selection* use the local model;
planning (feature->vuln matrix) and verification (the oracle) are deterministic
code. The oracle NEVER confirms on the model's word — a suspected finding is
promoted to confirmed only by reproducible evidence (differential, timing,
callback, or an actually-fired browser marker).
"""

from __future__ import annotations

from saarthi2.vulnengine.models import (
    AppModel,
    Finding,
    FindingSource,
    FindingStatus,
    InputSurface,
    ResponseSignals,
    SurfaceType,
    TestTask,
)

__all__ = [
    "AppModel",
    "Finding",
    "FindingSource",
    "FindingStatus",
    "InputSurface",
    "ResponseSignals",
    "SurfaceType",
    "TestTask",
]
