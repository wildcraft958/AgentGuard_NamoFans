"""Tests for L4Orchestrator — fuses L4a policy + L4b behavioral scoring."""

import asyncio
import hashlib
from datetime import datetime, timezone
from unittest.mock import MagicMock

from agentguard.l4.models.telemetry_span import TelemetrySpan
from agentguard.l4.orchestrator import L4Orchestrator
from agentguard.l4.policy_engine import AccessRequest


def _make_request(**overrides):
    defaults = {
        "agent_id": "a1",
        "role": "analyst",
        "action": "read",
        "resource": "data.txt",
        "resource_sensitivity": 0,
        "context": {},
    }
    defaults.update(overrides)
    return AccessRequest(**defaults)


def _make_span(**overrides):
    defaults = {
        "session_id": "sess-1",
        "role": "analyst",
        "tool_name": "file_read",
        "args_hash": hashlib.sha256(b"test").hexdigest(),
        "resource_sensitivity": 0,
        "data_volume_kb": 1.0,
        "timestamp": datetime.now(tz=timezone.utc),
    }
    defaults.update(overrides)
    return TelemetrySpan(**defaults)


def _make_orchestrator(
    policy_decision="ALLOW",
    baseline_score=0.1,
    graph_score=0.1,
    drift_score=0.1,
):
    pdp = MagicMock()
    pdp.evaluate.return_value = policy_decision

    baseline = MagicMock()
    baseline.score.return_value = baseline_score

    graph = MagicMock()
    graph.add_call.return_value = graph_score

    drift = MagicMock()
    drift.record.return_value = drift_score

    return L4Orchestrator(
        pdp=pdp,
        baseline=baseline,
        graph_scorer=graph,
        drift_monitor=drift,
    )


class TestL4Orchestrator:
    def test_deny_from_policy_skips_l4b(self):
        """DENY from L4a propagates immediately without calling L4b scorers."""
        orch = _make_orchestrator(policy_decision="DENY")
        result = asyncio.run(orch.evaluate(_make_request(), _make_span()))
        assert result["decision"] == "DENY"
        assert result["policy"] == "DENY"
        # L4b scorers should NOT have been called
        orch._baseline.score.assert_not_called()
        orch._graph.add_call.assert_not_called()
        orch._drift.record.assert_not_called()

    def test_allow_low_risk(self):
        """Low risk + ALLOW policy -> ALLOW."""
        orch = _make_orchestrator(
            policy_decision="ALLOW",
            baseline_score=0.1,
            graph_score=0.1,
            drift_score=0.1,
        )
        result = asyncio.run(orch.evaluate(_make_request(), _make_span()))
        assert result["decision"] == "ALLOW"
        assert result["risk_score"] < 0.7

    def test_high_risk_overrides_to_elevate(self):
        """risk_score >= 0.70 overrides L4a ALLOW -> ELEVATE."""
        orch = _make_orchestrator(
            policy_decision="ALLOW",
            baseline_score=0.8,
            graph_score=0.9,
            drift_score=0.7,
        )
        result = asyncio.run(orch.evaluate(_make_request(), _make_span()))
        assert result["decision"] == "ELEVATE"
        assert result["risk_score"] >= 0.70

    def test_very_high_risk_overrides_to_deny(self):
        """risk_score >= 0.90 overrides L4a ALLOW -> DENY."""
        orch = _make_orchestrator(
            policy_decision="ALLOW",
            baseline_score=1.0,
            graph_score=1.0,
            drift_score=1.0,
        )
        result = asyncio.run(orch.evaluate(_make_request(), _make_span()))
        assert result["decision"] == "DENY"
        assert result["risk_score"] >= 0.90

    def test_policy_elevate_propagates(self):
        """L4a ELEVATE + low risk -> ELEVATE (policy ELEVATE always propagates)."""
        orch = _make_orchestrator(
            policy_decision="ELEVATE",
            baseline_score=0.1,
            graph_score=0.1,
            drift_score=0.1,
        )
        result = asyncio.run(orch.evaluate(_make_request(), _make_span()))
        assert result["decision"] == "ELEVATE"

    def test_result_contains_all_keys(self):
        """Result dict has all required keys."""
        orch = _make_orchestrator()
        result = asyncio.run(orch.evaluate(_make_request(), _make_span()))
        required_keys = {
            "decision",
            "risk_score",
            "policy",
            "baseline_score",
            "graph_score",
            "drift_score",
            "latency_ms",
        }
        assert required_keys.issubset(result.keys())

    def test_telemetry_span_isolation(self):
        """L4b scorers receive span, never raw args."""
        orch = _make_orchestrator(policy_decision="ALLOW")
        span = _make_span()
        asyncio.run(orch.evaluate(_make_request(), span))
        # Verify the scorers were called with the span's data
        orch._baseline.score.assert_called_once()
        call_args = orch._baseline.score.call_args
        assert call_args[0][0] == span.role  # first arg is role
        # The tool_call dict should have hash, never raw args
        tool_call_dict = call_args[0][1]
        assert "hash" in str(tool_call_dict.get("args", {}))
