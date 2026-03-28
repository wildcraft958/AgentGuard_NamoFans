"""Backward-compat re-export: use agentguard.l4.rbac instead."""

from agentguard.l4.rbac import (
    AccessContext,
    L4RBACEngine,
    RBACDecision,
    extract_domain,
    infer_sensitivity,
    infer_verb,
)

__all__ = [
    "AccessContext",
    "L4RBACEngine",
    "RBACDecision",
    "extract_domain",
    "infer_sensitivity",
    "infer_verb",
]
