"""
AgentGuard – Shared Rule Condition Evaluator.

A single composable function for evaluating rule conditions against parameter
values. Supports `not_contains`, `gt`, and `lt` operators in addition to
the standard `equals`, `contains`, `matches`, `startswith`, `endswith`.

Supported operators:
    equals        exact string equality
    contains      case-insensitive substring
    not_contains  negated case-insensitive substring
    matches       regex search (case-insensitive)
    startswith    string prefix
    endswith      string suffix
    in            membership in list
    not_in        non-membership in list
    gt            numeric greater-than
    lt            numeric less-than

Usage:
    from agentguard.tool_firewall.rule_evaluator import eval_condition

    eval_condition("/tmp/secret.env", "endswith", ".env")   # True
    eval_condition("SELECT", "in", ["SELECT", "INSERT"])    # True
    eval_condition(1500, "gt", 1024)                        # True
"""

import re
from typing import Any


def eval_condition(param_val: Any, op: str, value: Any) -> bool:
    """
    Evaluate a single rule condition.

    Args:
        param_val: The actual parameter value from the tool call.
        op:        Operator string (see module docstring for full list).
        value:     The comparison value from the rule definition.

    Returns:
        True if the condition matches (i.e. the rule fires), False otherwise.
        Unknown operators always return False.
    """
    if op == "equals":
        return str(param_val) == str(value)

    if op == "contains":
        return str(value).lower() in str(param_val).lower()

    if op == "not_contains":
        return str(value).lower() not in str(param_val).lower()

    if op == "matches":
        return bool(re.search(str(value), str(param_val), re.IGNORECASE))

    if op == "startswith":
        return str(param_val).startswith(str(value))

    if op == "endswith":
        return str(param_val).endswith(str(value))

    if op == "in":
        allowed = value if isinstance(value, list) else [value]
        return str(param_val) in [str(v) for v in allowed]

    if op == "not_in":
        allowed = value if isinstance(value, list) else [value]
        return str(param_val) not in [str(v) for v in allowed]

    if op == "gt":
        try:
            return float(param_val) > float(value)
        except (TypeError, ValueError):
            return False

    if op == "lt":
        try:
            return float(param_val) < float(value)
        except (TypeError, ValueError):
            return False

    return False
