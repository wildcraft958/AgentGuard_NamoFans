"""
AgentGuard L4a — ABAC policy evaluator (agentguard.l4.rbac).

Evaluates: role × verb × resource_sensitivity × upstream_risk_score
Returns:   ALLOW | DENY | ELEVATE

Design: default-deny. Unknown role → DENY. No exceptions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Literal


class RBACDecision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ELEVATE = "elevate"  # → approval_workflow.py HITL


@dataclass
class AccessContext:
    agent_role: str
    tool_name: str
    task_id: str
    action_verb: Literal["read", "write", "delete", "execute", "network_external"]
    resource_sensitivity: Literal["public", "internal", "confidential"]
    risk_score: float  # 0.0–1.0 composite from upstream L1–L3 results


class L4RBACEngine:
    """ABAC policy evaluator. Reads capability model from AgentGuardConfig."""

    def __init__(self, config):
        self.config = config

    def evaluate(self, ctx: AccessContext) -> RBACDecision:
        """
        Evaluate an access context against the role's capability model.

        Decision order:
          1. Unknown role → DENY (zero-trust)
          2. Hard-blocked verb → DENY
          3. Tool not in allowed_tools → DENY
          4. Verb not allowed for resource sensitivity → DENY
          5. JIT elevation triggers (risk_score > 0.6, or elevate_on condition) → ELEVATE
          6. All checks pass → ALLOW
        """
        capability_model = self.config.rbac_capability_model
        policy = capability_model.get(ctx.agent_role)
        if not policy:
            return RBACDecision.DENY  # unknown role → default deny

        # Hard-blocked verbs — no exceptions
        denied_verbs = policy.get("denied_verbs", [])
        if ctx.action_verb in denied_verbs:
            return RBACDecision.DENY

        # Tool allowlist check (if defined for this role)
        allowed_tools = policy.get("allowed_tools", [])
        if allowed_tools and ctx.tool_name not in allowed_tools:
            return RBACDecision.DENY

        # Verb × resource sensitivity permission matrix
        resource_permissions = policy.get("resource_permissions", {})
        allowed_verbs = resource_permissions.get(ctx.resource_sensitivity, [])
        if ctx.action_verb not in allowed_verbs:
            return RBACDecision.DENY

        # JIT elevation: high upstream risk OR explicit elevate_on condition
        elevate_on = policy.get("elevate_on", [])
        needs_elevation = (
            ctx.risk_score > 0.6
            or ctx.action_verb in ("delete", "execute", "network_external")
            or f"any_{ctx.action_verb}" in elevate_on
        )
        if needs_elevation:
            return RBACDecision.ELEVATE

        return RBACDecision.ALLOW


# ── Inference helpers ─────────────────────────────────────────────────────────
# Maps tool function names → action verbs for automatic classification.
# Falls back to 'read' (conservative) for unknown tools.

_VERB_MAP: dict[str, str] = {
    # Read
    "read_file": "read",
    "fetch_pdf": "read",
    "query_db": "read",
    "search_web": "read",
    "list_files": "read",
    "get_record": "read",
    "read_memory": "read",
    "retrieve": "read",
    "summarize": "read",
    # Write
    "write_file": "write",
    "create_record": "write",
    "update_db": "write",
    "send_email": "write",
    "post_message": "write",
    "append_file": "write",
    "save_result": "write",
    # Delete
    "delete_file": "delete",
    "drop_table": "delete",
    "remove_record": "delete",
    "clear_memory": "delete",
    "db_drop_table": "delete",
    # Execute
    "shell_exec": "execute",
    "run_code": "execute",
    "execute_script": "execute",
    "run_python": "execute",
    "shell_execute": "execute",
    # Network
    "http_request": "network_external",
    "api_call": "network_external",
    "curl": "network_external",
    "wget": "network_external",
    "fetch_url": "network_external",
    "post_webhook": "network_external",
}

_CONFIDENTIAL_HINTS: frozenset[str] = frozenset({
    "/etc/",
    "passwords",
    "credentials",
    "private",
    "secret",
    ".env",
    "api_key",
    "token",
    "ssh",
    "pgp",
    "id_rsa",
})
_INTERNAL_HINTS: frozenset[str] = frozenset({
    "internal",
    "admin",
    "config",
    "database",
    "/db/",
    "system",
    "management",
    ".conf",
})


def infer_verb(tool_name: str) -> str:
    """Map tool name to action verb. Falls back to 'read' (conservative)."""
    return _VERB_MAP.get(tool_name, "read")


def infer_sensitivity(tool_name: str, kwargs: dict) -> str:
    """Infer resource sensitivity from tool name + call arguments."""
    combined = " ".join([
        str(kwargs.get("path", "")),
        str(kwargs.get("query", "")),
        str(kwargs.get("table", "")),
        str(kwargs.get("url", "")),
        tool_name,
    ]).lower()

    if any(h in combined for h in _CONFIDENTIAL_HINTS):
        return "confidential"
    if any(h in combined for h in _INTERNAL_HINTS):
        return "internal"
    return "public"


def extract_domain(url: str) -> str:
    """Extract hostname from a URL string for domain allowlist checking."""
    if not url:
        return ""
    match = re.search(r"https?://([^/?\s]+)", str(url))
    return match.group(1) if match else str(url).split("/")[0]
