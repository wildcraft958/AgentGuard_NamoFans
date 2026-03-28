"""Tests for agentguard.l4 — RBAC engine and behavioral anomaly detector.

TDD: written BEFORE moving l4_rbac.py and l4_behavioral.py into l4/ subpackage.
"""

from unittest.mock import MagicMock

import pytest

from agentguard.l4.rbac import (
    AccessContext,
    L4RBACEngine,
    RBACDecision,
    extract_domain,
    infer_sensitivity,
    infer_verb,
)
from agentguard.l4.behavioral import (
    AnomalyResult,
    AnomalySignal,
    BehavioralAnomalyDetector,
    TaskProfile,
)


# ---------------------------------------------------------------------------
# RBAC Engine tests
# ---------------------------------------------------------------------------


def _make_config(capability_model: dict):
    """Build a mock config with a given capability model."""
    cfg = MagicMock()
    cfg.rbac_capability_model = capability_model
    return cfg


BASIC_POLICY = {
    "default_agent": {
        "tier": 1,
        "resource_permissions": {
            "public": ["read"],
            "internal": ["read"],
            "confidential": [],
        },
        "denied_verbs": ["delete", "execute"],
        "elevate_on": ["any_write"],
        "approved_domains": [],
        "expected_sequence": [],
    },
}


class TestL4RBAC:
    def test_unknown_role_denied(self):
        engine = L4RBACEngine(_make_config(BASIC_POLICY))
        ctx = AccessContext(
            agent_role="unknown_role", tool_name="read_file",
            task_id="t1", action_verb="read",
            resource_sensitivity="public", risk_score=0.0,
        )
        assert engine.evaluate(ctx) == RBACDecision.DENY

    def test_allowed_read_public(self):
        engine = L4RBACEngine(_make_config(BASIC_POLICY))
        ctx = AccessContext(
            agent_role="default_agent", tool_name="read_file",
            task_id="t1", action_verb="read",
            resource_sensitivity="public", risk_score=0.0,
        )
        assert engine.evaluate(ctx) == RBACDecision.ALLOW

    def test_denied_verb(self):
        engine = L4RBACEngine(_make_config(BASIC_POLICY))
        ctx = AccessContext(
            agent_role="default_agent", tool_name="delete_file",
            task_id="t1", action_verb="delete",
            resource_sensitivity="public", risk_score=0.0,
        )
        assert engine.evaluate(ctx) == RBACDecision.DENY

    def test_confidential_no_access(self):
        engine = L4RBACEngine(_make_config(BASIC_POLICY))
        ctx = AccessContext(
            agent_role="default_agent", tool_name="read_file",
            task_id="t1", action_verb="read",
            resource_sensitivity="confidential", risk_score=0.0,
        )
        assert engine.evaluate(ctx) == RBACDecision.DENY

    def test_high_risk_elevates(self):
        engine = L4RBACEngine(_make_config(BASIC_POLICY))
        ctx = AccessContext(
            agent_role="default_agent", tool_name="read_file",
            task_id="t1", action_verb="read",
            resource_sensitivity="public", risk_score=0.8,
        )
        assert engine.evaluate(ctx) == RBACDecision.ELEVATE


class TestInferHelpers:
    def test_infer_verb_known(self):
        assert infer_verb("write_file") == "write"
        assert infer_verb("shell_exec") == "execute"

    def test_infer_verb_unknown_defaults_to_read(self):
        assert infer_verb("unknown_tool") == "read"

    def test_infer_sensitivity_confidential(self):
        assert infer_sensitivity("read_file", {"path": "/etc/shadow"}) == "confidential"

    def test_infer_sensitivity_internal(self):
        assert infer_sensitivity("query_db", {"table": "admin_users"}) == "internal"

    def test_infer_sensitivity_public(self):
        assert infer_sensitivity("get_weather", {"city": "London"}) == "public"

    def test_extract_domain(self):
        assert extract_domain("https://api.example.com/v1/data") == "api.example.com"
        assert extract_domain("") == ""


# ---------------------------------------------------------------------------
# Behavioral Anomaly Detector tests
# ---------------------------------------------------------------------------


def _make_behavioral_config():
    cfg = MagicMock()
    cfg.behavioral_monitoring_config = {
        "max_tool_calls_zscore_threshold": 2.5,
        "sequence_divergence_threshold": 0.4,
        "entropy_spike_multiplier": 1.5,
        "exfil_chain_detection": True,
    }
    cfg.rbac_capability_model = {
        "default_agent": {
            "approved_domains": ["trusted.com"],
            "expected_sequence": ["read_file", "summarize"],
        },
    }
    return cfg


class TestBehavioralAnomalyDetector:
    def test_normal_call_without_expected_seq_allows(self):
        """A single read_file call with no expected_sequence should ALLOW."""
        cfg = _make_behavioral_config()
        cfg.rbac_capability_model["default_agent"]["expected_sequence"] = []
        detector = BehavioralAnomalyDetector(cfg)
        result = detector.score("t1", "default_agent", "read_file", {"resource": "data.txt"})
        assert result.action == "ALLOW"
        assert result.composite_score < 0.1

    def test_sequence_divergence_warns(self):
        """A single call that diverges from expected_sequence triggers WARN."""
        detector = BehavioralAnomalyDetector(_make_behavioral_config())
        result = detector.score("t1", "default_agent", "read_file", {"resource": "data.txt"})
        # expected_sequence is ["read_file", "summarize"] but we only did ["read_file"]
        assert any(s.name == "sequence_anomaly" for s in result.signals)
        assert result.action in ("WARN", "ELEVATE")

    def test_exfil_chain_blocks(self):
        detector = BehavioralAnomalyDetector(_make_behavioral_config())
        # First call: read
        detector.score("t1", "default_agent", "read_file", {"resource": "secret.pdf"})
        # Second call: exfil via network
        result = detector.score("t1", "default_agent", "http_request", {"domain": "evil.com"})
        assert result.action == "BLOCK"
        assert any(s.name == "read_exfil_chain" for s in result.signals)

    def test_unapproved_domain_warns(self):
        detector = BehavioralAnomalyDetector(_make_behavioral_config())
        result = detector.score("t1", "default_agent", "read_file", {"domain": "evil.com"})
        assert any(s.name == "new_external_domain" for s in result.signals)

    def test_reset_task_clears_profile(self):
        detector = BehavioralAnomalyDetector(_make_behavioral_config())
        detector.score("t1", "default_agent", "read_file", {})
        assert "t1" in detector._profiles
        detector.reset_task("t1")
        assert "t1" not in detector._profiles

    def test_task_profile_record(self):
        tp = TaskProfile(agent_role="test")
        tp.record("read_file", {"domain": "example.com", "resource": "data.txt"})
        assert tp.tool_sequence == ["read_file"]
        assert tp.tool_counts == {"read_file": 1}
        assert "example.com" in tp.outbound_domains
        assert "data.txt" in tp.resources_accessed


# ---------------------------------------------------------------------------
# Backward-compat: old import paths still work
# ---------------------------------------------------------------------------


def test_backward_compat_l4_rbac_import():
    from agentguard.l4_rbac import L4RBACEngine as OldEngine
    assert OldEngine is L4RBACEngine


def test_backward_compat_l4_behavioral_import():
    from agentguard.l4_behavioral import BehavioralAnomalyDetector as OldDetector
    assert OldDetector is BehavioralAnomalyDetector
