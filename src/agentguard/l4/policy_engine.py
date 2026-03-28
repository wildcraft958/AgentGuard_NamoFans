"""
L4a — Policy Decision Point (PBAC engine).

Replaces the static ABAC matrix with YAML-defined, hot-reloadable policies.
Evaluates rules in order — first matching rule wins.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

import yaml


@dataclass
class AccessRequest:
    """Request to evaluate against PBAC policies."""

    agent_id: str
    role: str
    action: str  # read | write | delete | execute
    resource: str
    resource_sensitivity: int  # 0-3: public, internal, confidential, critical
    context: dict = field(default_factory=dict)


class PolicyDecisionPoint:
    """
    YAML-driven Policy Decision Point.

    Evaluates rules in order — first matching rule wins.
    Supports wildcards ("*") for roles and actions.
    Supports condition operators: eq, gte, lte, in, not_in.
    """

    def __init__(self, policy_file: str):
        self._policy_file = policy_file
        self._load()

    def _load(self) -> None:
        with open(self._policy_file) as f:
            data = yaml.safe_load(f)
        self._default_effect: str = data.get("default_effect", "DENY")
        self._rules: list[dict] = data.get("rules", [])

    def reload(self) -> None:
        """Hot-reload policy file without restart."""
        self._load()

    def evaluate(self, req: AccessRequest) -> Literal["ALLOW", "DENY", "ELEVATE"]:
        """Evaluate request against policies. First matching rule wins."""
        for rule in self._rules:
            if self._matches(rule, req):
                return rule["effect"]
        return self._default_effect

    def _matches(self, rule: dict, req: AccessRequest) -> bool:
        roles = rule.get("roles", [])
        if "*" not in roles and req.role not in roles:
            return False

        actions = rule.get("actions", [])
        if "*" not in actions and req.action not in actions:
            return False

        min_sens = rule.get("min_sensitivity", 0)
        if req.resource_sensitivity < min_sens:
            return False

        for cond in rule.get("conditions", []):
            if not self._eval_condition(cond, req):
                return False

        return True

    def _eval_condition(self, cond: dict, req: AccessRequest) -> bool:
        key = cond["key"]
        operator = cond["operator"]
        expected = cond["value"]

        # Resolve actual value: check context dict first, then AccessRequest fields
        if key in req.context:
            actual = req.context[key]
        elif hasattr(req, key):
            actual = getattr(req, key)
        else:
            return False  # unknown key -> condition fails

        if operator == "eq":
            return actual == expected
        elif operator == "gte":
            return actual >= expected
        elif operator == "lte":
            return actual <= expected
        elif operator == "in":
            return actual in expected
        elif operator == "not_in":
            return actual not in expected
        return False
