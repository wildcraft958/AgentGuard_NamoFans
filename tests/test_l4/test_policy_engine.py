"""Tests for PolicyDecisionPoint — L4a PBAC engine."""

import os
import tempfile

import yaml

from agentguard.l4.policy_engine import AccessRequest, PolicyDecisionPoint


POLICIES = {
    "default_effect": "DENY",
    "rules": [
        # Critical rules first (first-match-wins — restrictive before permissive)
        {
            "id": "critical_hitl",
            "roles": ["*"],
            "actions": ["*"],
            "min_sensitivity": 3,
            "conditions": [
                {"key": "hitl_approved", "operator": "eq", "value": True},
            ],
            "effect": "ELEVATE",
        },
        {
            "id": "critical_deny",
            "roles": ["*"],
            "actions": ["*"],
            "min_sensitivity": 3,
            "effect": "DENY",
        },
        # Specific role rules
        {
            "id": "analyst_write_elevate",
            "roles": ["analyst"],
            "actions": ["write"],
            "min_sensitivity": 2,
            "effect": "ELEVATE",
        },
        {
            "id": "reader_public",
            "roles": ["reader"],
            "actions": ["read"],
            "min_sensitivity": 0,
            "effect": "ALLOW",
        },
        # Wildcard fallback
        {
            "id": "wildcard_read",
            "roles": ["*"],
            "actions": ["read"],
            "min_sensitivity": 0,
            "conditions": [
                {"key": "resource_sensitivity", "operator": "lte", "value": 1},
            ],
            "effect": "ALLOW",
        },
    ],
}


def _write_policy_file(policies: dict) -> str:
    """Write policies dict to a temp YAML file, return path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        yaml.dump(policies, f)
    return path


class TestPolicyDecisionPoint:
    def test_allow_reader_public(self):
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)
        req = AccessRequest(
            agent_id="a1",
            role="reader",
            action="read",
            resource="data.txt",
            resource_sensitivity=0,
            context={},
        )
        assert pdp.evaluate(req) == "ALLOW"
        os.unlink(path)

    def test_deny_sensitivity_3_no_hitl(self):
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)
        req = AccessRequest(
            agent_id="a1",
            role="reader",
            action="read",
            resource="secrets.db",
            resource_sensitivity=3,
            context={"hitl_approved": False},
        )
        assert pdp.evaluate(req) == "DENY"
        os.unlink(path)

    def test_elevate_analyst_write_sensitivity_2(self):
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)
        req = AccessRequest(
            agent_id="a1",
            role="analyst",
            action="write",
            resource="report.csv",
            resource_sensitivity=2,
            context={},
        )
        assert pdp.evaluate(req) == "ELEVATE"
        os.unlink(path)

    def test_wildcard_role_match(self):
        """Wildcard '*' role matches any role."""
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)
        req = AccessRequest(
            agent_id="a1",
            role="some_unknown_role",
            action="read",
            resource="public.txt",
            resource_sensitivity=0,
            context={},
        )
        # Matches wildcard_read rule (sensitivity 0 <= 1)
        assert pdp.evaluate(req) == "ALLOW"
        os.unlink(path)

    def test_condition_lte(self):
        """Condition operator 'lte' works correctly."""
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)
        # sensitivity=2 fails the lte=1 condition in wildcard_read
        req = AccessRequest(
            agent_id="a1",
            role="some_role",
            action="read",
            resource="internal.doc",
            resource_sensitivity=2,
            context={},
        )
        # No rule matches -> default DENY
        assert pdp.evaluate(req) == "DENY"
        os.unlink(path)

    def test_condition_eq_hitl(self):
        """HITL approval condition with eq operator."""
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)
        req = AccessRequest(
            agent_id="a1",
            role="executor",
            action="delete",
            resource="critical.db",
            resource_sensitivity=3,
            context={"hitl_approved": True},
        )
        assert pdp.evaluate(req) == "ELEVATE"
        os.unlink(path)

    def test_default_deny_no_match(self):
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)
        req = AccessRequest(
            agent_id="a1",
            role="reader",
            action="delete",
            resource="something",
            resource_sensitivity=1,
            context={},
        )
        assert pdp.evaluate(req) == "DENY"
        os.unlink(path)

    def test_hot_reload(self):
        """Changing YAML and calling reload() applies new policy."""
        path = _write_policy_file(POLICIES)
        pdp = PolicyDecisionPoint(path)

        req = AccessRequest(
            agent_id="a1",
            role="reader",
            action="read",
            resource="data.txt",
            resource_sensitivity=0,
            context={},
        )
        assert pdp.evaluate(req) == "ALLOW"

        # Rewrite to deny-all
        new_policies = {"default_effect": "DENY", "rules": []}
        with open(path, "w") as f:
            yaml.dump(new_policies, f)

        pdp.reload()
        assert pdp.evaluate(req) == "DENY"
        os.unlink(path)
