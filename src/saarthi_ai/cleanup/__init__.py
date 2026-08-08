"""Phase 6G — Cleanup & Rollback.

Accounts for the footprint an authorized engagement leaves behind and plans its
reversal. Saarthi's validators are non-submitting and its exploit/post-exploit
tiers read or simulate only, so the target-side footprint is normally empty —
6G asserts that, enumerates any local sensitive artifacts (extraction proofs,
external-result imports) and live auth sessions for disposal/invalidation, and
classifies each by reversibility.

The auto tier is deterministic and offline: it builds a manifest and executes
nothing. Actual rollback (invalidate a session, delete a self-created target
artifact) is a separate, approval-gated, scope-locked step.
"""
