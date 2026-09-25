"""Phase 6G models: cleanup artifacts, rollback actions, and the manifest.

A cleanup *item* records one residual artifact an engagement produced — a local
sensitive file, a live auth session, or (rarely) a target-side change — with the
recommended rollback action and whether it can be reversed automatically. The
manifest rolls these up and asserts the overall target-side footprint. All types
are safe to persist: they carry artifact metadata and locations, never the
sensitive contents themselves.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "CleanupArtifactType",
    "CleanupItem",
    "CleanupManifest",
    "FootprintAssertion",
    "Reversibility",
    "RollbackAction",
    "make_cleanup_id",
]


class CleanupArtifactType(StrEnum):
    """What kind of residual artifact a cleanup item represents."""

    LOCAL_SENSITIVE_EVIDENCE = "local_sensitive_evidence"
    EXTERNAL_RESULT_IMPORT = "external_result_import"
    LIVE_AUTH_SESSION = "live_auth_session"
    TARGET_ARTIFACT = "target_artifact"  # created ON the target (rare)
    TARGET_MUTATION = "target_mutation"  # a state change ON the target (rare)


class RollbackAction(StrEnum):
    """The recommended action to reverse/handle a cleanup item."""

    SECURE_DISPOSE = "secure_dispose"  # local: delete/redact per data policy
    INVALIDATE_SESSION = "invalidate_session"  # expire/logout a live session
    DELETE_TARGET_ARTIFACT = "delete_target_artifact"  # remove from target
    MANUAL_REVIEW = "manual_review"  # operator must handle by hand
    RETAIN = "retain"  # keep (audit trail / required evidence)


class Reversibility(StrEnum):
    """Whether the approval-gated executor can reverse an item."""

    AUTO_REVERSIBLE = "auto_reversible"  # executor can act with --approved
    OPERATOR_ACTION = "operator_action"  # needs a human step
    NOT_APPLICABLE = "not_applicable"  # nothing to reverse


class FootprintAssertion(StrEnum):
    """Overall assertion about what the engagement left ON the target."""

    NO_TARGET_FOOTPRINT = "no_target_footprint"
    TARGET_FOOTPRINT_PRESENT = "target_footprint_present"


# Artifact types that represent a change made ON the target (vs. local-only).
_TARGET_SIDE = frozenset(
    {CleanupArtifactType.TARGET_ARTIFACT, CleanupArtifactType.TARGET_MUTATION}
)


def make_cleanup_id(artifact_type: str, location: str) -> str:
    """Stable, deterministic id for a cleanup item across runs."""

    material = "|".join(["6g", artifact_type, location]).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:16]


@dataclass(frozen=True)
class CleanupItem:
    """One residual artifact and how to reverse/handle it."""

    item_id: str
    artifact_type: CleanupArtifactType
    location: str  # local path or target URL/identifier
    reversibility: Reversibility
    action: RollbackAction
    source_evidence_type: str
    detail: str = ""
    target: str | None = None  # target URL for target-side items

    @property
    def is_target_side(self) -> bool:
        return self.artifact_type in _TARGET_SIDE

    def as_dict(self) -> dict:
        return {
            "item_id": self.item_id,
            "artifact_type": self.artifact_type.value,
            "location": self.location,
            "reversibility": self.reversibility.value,
            "action": self.action.value,
            "source_evidence_type": self.source_evidence_type,
            "detail": self.detail,
            "target": self.target,
            "is_target_side": self.is_target_side,
        }


@dataclass(frozen=True)
class CleanupManifest:
    """Aggregated cleanup/rollback plan for one run."""

    target: str
    items: tuple[CleanupItem, ...] = ()

    @property
    def footprint(self) -> FootprintAssertion:
        if any(item.is_target_side for item in self.items):
            return FootprintAssertion.TARGET_FOOTPRINT_PRESENT
        return FootprintAssertion.NO_TARGET_FOOTPRINT

    @property
    def reversible_count(self) -> int:
        return sum(
            1
            for item in self.items
            if item.reversibility is Reversibility.AUTO_REVERSIBLE
        )

    @property
    def operator_action_count(self) -> int:
        return sum(
            1
            for item in self.items
            if item.reversibility is Reversibility.OPERATOR_ACTION
        )

    @property
    def artifact_type_counts(self) -> dict[str, int]:
        counts: Counter[str] = Counter(
            item.artifact_type.value for item in self.items
        )
        return dict(counts)

    @property
    def action_counts(self) -> dict[str, int]:
        counts: Counter[str] = Counter(
            item.action.value for item in self.items
        )
        return dict(counts)

    def as_dict(self) -> dict:
        return {
            "target": self.target,
            "item_count": len(self.items),
            "footprint": self.footprint.value,
            "reversible_count": self.reversible_count,
            "operator_action_count": self.operator_action_count,
            "artifact_type_counts": self.artifact_type_counts,
            "action_counts": self.action_counts,
            "items": [item.as_dict() for item in self.items],
        }
