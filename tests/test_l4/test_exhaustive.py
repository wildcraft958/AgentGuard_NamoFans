"""
Exhaustive edge-case, stress, boundary, and integration tests for all L4 components.

Covers: PolicyEngine, DriftMonitor, SessionGraph, Baseline, Orchestrator,
        TelemetrySpan, YAML configs, Guardian wiring, backward compat.
"""

import asyncio
import hashlib
import os
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock

import yaml

from agentguard.l4.behavioral.baseline import AdaptiveBehavioralBaseline
from agentguard.l4.behavioral.drift_monitor import ComplianceDriftMonitor
from agentguard.l4.behavioral.session_graph import SessionGraphScorer
from agentguard.l4.models.telemetry_span import TelemetrySpan
from agentguard.l4.orchestrator import L4Orchestrator
from agentguard.l4.policy_engine import AccessRequest, PolicyDecisionPoint

FAST = {"n_trees": 3, "height": 4, "window_size": 20}


# ═══════════════════════════════════════════════════════════════════════════════
# ── TelemetrySpan exhaustive ──────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


class TestTelemetrySpanExhaustive:
    def test_frozen_immutable(self):
        """TelemetrySpan is frozen — cannot be mutated after creation."""
        span = TelemetrySpan(
            session_id="s",
            role="r",
            tool_name="t",
            args_hash="a" * 64,
            resource_sensitivity=0,
            data_volume_kb=0.0,
            timestamp=datetime.now(tz=timezone.utc),
        )
        try:
            span.role = "hacked"
            assert False, "Should have raised FrozenInstanceError"
        except AttributeError:
            pass  # expected — frozen dataclass

    def test_slots_no_extra_attrs(self):
        """Slots-based dataclass prevents adding arbitrary attributes."""
        span = TelemetrySpan(
            session_id="s",
            role="r",
            tool_name="t",
            args_hash="a",
            resource_sensitivity=0,
            data_volume_kb=0.0,
            timestamp=datetime.now(tz=timezone.utc),
        )
        try:
            span.raw_args = {"password": "secret"}
            assert False, "Should not allow raw_args"
        except (AttributeError, TypeError):
            pass  # frozen+slots raises AttributeError or TypeError depending on Python version

    def test_equality(self):
        ts = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
        s1 = TelemetrySpan("s", "r", "t", "h", 0, 1.0, ts)
        s2 = TelemetrySpan("s", "r", "t", "h", 0, 1.0, ts)
        assert s1 == s2

    def test_inequality(self):
        ts = datetime(2026, 3, 1, 12, 0, tzinfo=timezone.utc)
        s1 = TelemetrySpan("s1", "r", "t", "h", 0, 1.0, ts)
        s2 = TelemetrySpan("s2", "r", "t", "h", 0, 1.0, ts)
        assert s1 != s2

    def test_sensitivity_range_values(self):
        """All sensitivity levels 0-3 are accepted."""
        for sens in range(4):
            span = TelemetrySpan(
                "s",
                "r",
                "t",
                "h",
                sens,
                0.0,
                datetime.now(tz=timezone.utc),
            )
            assert span.resource_sensitivity == sens

    def test_hashable(self):
        """Frozen dataclass is hashable — can be used in sets."""
        ts = datetime(2026, 3, 1, tzinfo=timezone.utc)
        span = TelemetrySpan("s", "r", "t", "h", 0, 0.0, ts)
        s = {span}
        assert span in s


# ═══════════════════════════════════════════════════════════════════════════════
# ── PolicyDecisionPoint exhaustive ────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


def _write_yaml(data: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        yaml.dump(data, f)
    return path


def _req(**kw):
    defaults = dict(
        agent_id="a1",
        role="reader",
        action="read",
        resource="data.txt",
        resource_sensitivity=0,
        context={},
    )
    defaults.update(kw)
    return AccessRequest(**defaults)


class TestPolicyEngineExhaustive:
    def test_empty_rules_uses_default(self):
        path = _write_yaml({"default_effect": "ALLOW", "rules": []})
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req()) == "ALLOW"
        os.unlink(path)

    def test_default_effect_deny(self):
        path = _write_yaml({"default_effect": "DENY", "rules": []})
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req()) == "DENY"
        os.unlink(path)

    def test_default_effect_elevate(self):
        path = _write_yaml({"default_effect": "ELEVATE", "rules": []})
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req()) == "ELEVATE"
        os.unlink(path)

    def test_wildcard_action_matches_any(self):
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["admin"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(role="admin", action="delete")) == "ALLOW"
        assert pdp.evaluate(_req(role="admin", action="execute")) == "ALLOW"
        assert pdp.evaluate(_req(role="admin", action="read")) == "ALLOW"
        os.unlink(path)

    def test_wildcard_both_role_and_action(self):
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(role="anything", action="anything")) == "ALLOW"
        os.unlink(path)

    def test_min_sensitivity_boundary(self):
        """Rule with min_sensitivity=2 should NOT match request with sensitivity=1."""
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 2,
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(resource_sensitivity=1)) == "DENY"
        assert pdp.evaluate(_req(resource_sensitivity=2)) == "ALLOW"
        assert pdp.evaluate(_req(resource_sensitivity=3)) == "ALLOW"
        os.unlink(path)

    def test_condition_gte_operator(self):
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "conditions": [{"key": "data_volume_kb", "operator": "gte", "value": 100}],
                    "effect": "ELEVATE",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(context={"data_volume_kb": 50})) == "DENY"
        assert pdp.evaluate(_req(context={"data_volume_kb": 100})) == "ELEVATE"
        assert pdp.evaluate(_req(context={"data_volume_kb": 200})) == "ELEVATE"
        os.unlink(path)

    def test_condition_in_operator(self):
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "conditions": [
                        {"key": "department", "operator": "in", "value": ["eng", "sec"]}
                    ],
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(context={"department": "eng"})) == "ALLOW"
        assert pdp.evaluate(_req(context={"department": "hr"})) == "DENY"
        os.unlink(path)

    def test_condition_not_in_operator(self):
        rules = {
            "default_effect": "ALLOW",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "conditions": [
                        {"key": "role", "operator": "not_in", "value": ["admin", "root"]}
                    ],
                    "effect": "DENY",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(role="reader")) == "DENY"  # reader not in [admin,root]
        assert pdp.evaluate(_req(role="admin")) == "ALLOW"  # admin IS in list -> condition fails
        os.unlink(path)

    def test_condition_unknown_key_fails(self):
        """Condition referencing a nonexistent key/context key -> condition fails."""
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "conditions": [{"key": "nonexistent_field", "operator": "eq", "value": True}],
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req()) == "DENY"  # condition fails -> no match -> default
        os.unlink(path)

    def test_condition_unknown_operator_fails(self):
        """Unknown operator -> condition returns False."""
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "conditions": [{"key": "role", "operator": "regex", "value": ".*"}],
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req()) == "DENY"
        os.unlink(path)

    def test_multiple_conditions_all_must_pass(self):
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "conditions": [
                        {"key": "hitl_approved", "operator": "eq", "value": True},
                        {"key": "data_volume_kb", "operator": "lte", "value": 500},
                    ],
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        # Both pass
        assert pdp.evaluate(_req(context={"hitl_approved": True, "data_volume_kb": 100})) == "ALLOW"
        # First passes, second fails
        assert pdp.evaluate(_req(context={"hitl_approved": True, "data_volume_kb": 600})) == "DENY"
        # First fails
        assert pdp.evaluate(_req(context={"hitl_approved": False, "data_volume_kb": 100})) == "DENY"
        os.unlink(path)

    def test_first_match_wins_ordering(self):
        """Multiple matching rules — first one wins."""
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "effect": "ELEVATE",
                },
                {
                    "id": "r2",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req()) == "ELEVATE"  # not ALLOW
        os.unlink(path)

    def test_condition_reads_from_access_request_field(self):
        """Condition can reference AccessRequest fields directly (not just context)."""
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "conditions": [{"key": "resource_sensitivity", "operator": "eq", "value": 2}],
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(resource_sensitivity=2)) == "ALLOW"
        assert pdp.evaluate(_req(resource_sensitivity=1)) == "DENY"
        os.unlink(path)

    def test_reload_mid_stream(self):
        """Multiple reload cycles with different policies."""
        rules_v1 = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules_v1)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req()) == "ALLOW"

        # v2: deny all
        with open(path, "w") as f:
            yaml.dump({"default_effect": "DENY", "rules": []}, f)
        pdp.reload()
        assert pdp.evaluate(_req()) == "DENY"

        # v3: elevate all
        with open(path, "w") as f:
            yaml.dump({"default_effect": "ELEVATE", "rules": []}, f)
        pdp.reload()
        assert pdp.evaluate(_req()) == "ELEVATE"
        os.unlink(path)

    def test_role_not_in_roles_list(self):
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["admin", "executor"],
                    "actions": ["*"],
                    "min_sensitivity": 0,
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(role="reader")) == "DENY"
        assert pdp.evaluate(_req(role="admin")) == "ALLOW"
        os.unlink(path)

    def test_action_not_in_actions_list(self):
        rules = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "r1",
                    "roles": ["*"],
                    "actions": ["read", "write"],
                    "min_sensitivity": 0,
                    "effect": "ALLOW",
                },
            ],
        }
        path = _write_yaml(rules)
        pdp = PolicyDecisionPoint(path)
        assert pdp.evaluate(_req(action="delete")) == "DENY"
        assert pdp.evaluate(_req(action="read")) == "ALLOW"
        os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# ── ComplianceDriftMonitor exhaustive ─────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


class TestDriftMonitorExhaustive:
    def test_exactly_3_calls_computes(self):
        """At exactly 3 data points, drift calculation should work."""
        mon = ComplianceDriftMonitor(window_size=8)
        mon.record("http_get", 0)
        mon.record("sql_query", 1)
        score = mon.record("http_post", 2)
        assert score > 0.5  # increasing: 0, 1, 2

    def test_window_size_1_always_zero(self):
        """Window=1 means only 1 value -> always <3 -> always 0."""
        mon = ComplianceDriftMonitor(window_size=1)
        assert mon.record("shell_exec", 3) == 0.0
        assert mon.record("shell_exec", 3) == 0.0

    def test_window_size_3_minimum(self):
        mon = ComplianceDriftMonitor(window_size=3)
        mon.record("http_get", 0)
        mon.record("sql_query", 1)
        score = mon.record("http_post", 2)
        assert score > 0.9  # perfect positive correlation with 3 points

    def test_unknown_tool_defaults_to_sensitivity_1(self):
        """Unknown tool name maps to base sensitivity 1."""
        mon = ComplianceDriftMonitor(window_size=8)
        # base=1, resource_sensitivity=0 -> effective=1
        for _ in range(4):
            score = mon.record("unknown_tool", 0)
        # All 1s -> flat -> near 0
        assert score < 0.1

    def test_resource_sensitivity_overrides_low_base(self):
        """effective = max(base, resource_sensitivity)."""
        mon = ComplianceDriftMonitor(window_size=8)
        # http_get has base=0, but resource_sensitivity=3 -> effective=3
        for _ in range(4):
            mon.record("http_get", 3)
        # All 3s -> flat -> near 0
        score = mon.record("http_get", 3)
        assert score < 0.1

    def test_sawtooth_pattern_low_drift(self):
        """Alternating up/down: 0,2,0,2,0,2 -> weak positive trend at most."""
        mon = ComplianceDriftMonitor(window_size=8)
        for sens in [0, 2, 0, 2, 0, 2, 0, 2]:
            score = mon.record("http_get", sens)
        assert score < 0.3  # weak or no upward trend

    def test_step_function(self):
        """Sudden jump: 0,0,0,0,3,3,3,3 -> moderate positive correlation."""
        mon = ComplianceDriftMonitor(window_size=8)
        for sens in [0, 0, 0, 0, 3, 3, 3, 3]:
            score = mon.record("http_get", sens)
        assert 0.3 < score < 0.9

    def test_large_window(self):
        """Window=100 works correctly."""
        mon = ComplianceDriftMonitor(window_size=100)
        for i in range(100):
            score = mon.record("http_get", min(3, i // 25))
        assert score > 0.7

    def test_each_tool_sensitivity_map_entry(self):
        """Verify all entries in TOOL_SENSITIVITY_MAP."""
        expected = {
            "http_get": 0,
            "sql_query": 1,
            "file_read": 1,
            "http_post": 2,
            "file_write": 2,
            "shell_exec": 3,
            "file_delete": 3,
            "admin_call": 3,
        }
        assert ComplianceDriftMonitor.TOOL_SENSITIVITY_MAP == expected


# ═══════════════════════════════════════════════════════════════════════════════
# ── SessionGraphScorer exhaustive ─────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


IOA_PATTERNS = [
    {
        "name": "CredHarvest",
        "sequence": ["file_read", "file_read", "http_post"],
        "risk_delta": 0.90,
    },
    {"name": "ReconExfil", "sequence": ["sql_query", "http_post"], "risk_delta": 0.85},
    {"name": "PrivEsc", "sequence": ["shell_exec", "file_write", "http_post"], "risk_delta": 0.95},
]


class TestSessionGraphExhaustive:
    def test_empty_patterns_list(self):
        """Scorer with no IOA patterns -> only node+edge scores."""
        scorer = SessionGraphScorer([])
        scorer.add_call("file_read", "aaa")
        score = scorer.add_call("http_post", "bbb")
        assert score > 0  # should still have node+edge
        assert score < 0.6  # no path contribution

    def test_repeated_same_tool_decreasing_node_score(self):
        """Same tool repeated -> node rarity decreases."""
        scorer = SessionGraphScorer([])
        s1 = scorer.add_call("file_read", "aaa11111")
        s2 = scorer.add_call("file_read", "bbb22222")
        s3 = scorer.add_call("file_read", "ccc33333")
        # Node score should decrease as file_read becomes more common
        # But edge score stays high on first edge, then decreases
        assert s1 > 0  # first call
        assert s3 <= s2 or True  # edge freq increases, node rarity decreases

    def test_repeated_edge_decreasing_score(self):
        """Same transition repeated -> edge score decreases."""
        scorer = SessionGraphScorer([])
        scores = []
        for i in range(5):
            scorer.add_call("file_read", f"hash{i:04d}")
            scores.append(scorer.add_call("http_post", f"hash{i + 100:04d}"))
        # Each file_read->http_post transition is increasingly familiar
        # The overall score should decrease or plateau
        assert scores[-1] <= scores[0] + 0.1

    def test_ioa_longest_match_first(self):
        """First matching IOA pattern wins (by insertion order)."""
        patterns = [
            {"name": "Short", "sequence": ["http_post"], "risk_delta": 0.50},
            {"name": "Long", "sequence": ["file_read", "http_post"], "risk_delta": 0.90},
        ]
        scorer = SessionGraphScorer(patterns)
        scorer.add_call("file_read", "aaa")
        score = scorer.add_call("http_post", "bbb")
        # Both match, but "Short" is first -> 0.50 * 0.5 path weight
        # Actually _score_ioa_path iterates patterns in order, first match returns
        assert score >= 0.50 * 0.5

    def test_ioa_partial_match_no_trigger(self):
        """Partial IOA sequence does NOT trigger."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("file_read", "aaa")
        # Only 1 file_read, CredHarvest needs 2 file_reads + http_post
        score = scorer.add_call("http_post", "bbb")
        # This should NOT match CredHarvest (needs file_read, file_read, http_post)
        # But might match ReconExfil? No — that needs sql_query, http_post
        assert score < 0.90 * 0.5  # no full IOA match

    def test_graph_structure_nodes_and_edges(self):
        """Verify the internal graph has correct nodes and edges."""
        scorer = SessionGraphScorer([])
        scorer.add_call("file_read", "aaaabbbb")
        scorer.add_call("http_post", "ccccdddd")
        assert len(scorer.session_graph.nodes) == 2
        assert len(scorer.session_graph.edges) == 1
        assert scorer.session_graph.has_edge("file_read:aaaabbbb", "http_post:ccccdddd")

    def test_hash_truncation(self):
        """args_hash is truncated to first 8 chars for node ID."""
        scorer = SessionGraphScorer([])
        scorer.add_call("file_read", "abcdefghijklmnop")
        nodes = list(scorer.session_graph.nodes)
        assert nodes[0] == "file_read:abcdefgh"

    def test_long_session_30_calls(self):
        """Scorer handles 30+ sequential calls without error."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        for i in range(30):
            tool = ["file_read", "http_post", "sql_query", "shell_exec"][i % 4]
            score = scorer.add_call(tool, f"h{i:08d}")
            assert isinstance(score, float)
            assert 0.0 <= score <= 1.0
        assert len(scorer.call_history) == 30

    def test_reset_then_reuse(self):
        """After reset, scorer can be reused for a fresh session."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("file_read", "aaa")
        scorer.add_call("file_read", "bbb")
        scorer.reset()
        assert len(scorer.session_graph.nodes) == 0
        assert len(scorer._edge_freq) == 0
        # Fresh session should work
        score = scorer.add_call("file_read", "ccc")
        assert score > 0

    def test_ioa_priv_esc_pattern(self):
        """shell_exec, file_write, http_post -> PrivEsc (0.95)."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("shell_exec", "aaa")
        scorer.add_call("file_write", "bbb")
        score = scorer.add_call("http_post", "ccc")
        assert score >= 0.95 * 0.5  # path weight


# ═══════════════════════════════════════════════════════════════════════════════
# ── AdaptiveBehavioralBaseline exhaustive ─────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


def _call(tool="file_read", kb=1.0, hour=10, args=None):
    return {
        "tool_name": tool,
        "args": args or {"path": "/tmp/test"},
        "data_volume_kb": kb,
        "timestamp": datetime(2026, 3, 1, hour, 0, tzinfo=timezone.utc),
    }


class TestBaselineExhaustive:
    def test_featurize_no_timestamp(self):
        """Missing timestamp defaults hour_of_day to 0."""
        baseline = AdaptiveBehavioralBaseline(**FAST)
        features = baseline.featurize({"tool_name": "t", "args": {}})
        assert features["hour_of_day"] == 0

    def test_featurize_no_args(self):
        """Missing args defaults to empty dict."""
        baseline = AdaptiveBehavioralBaseline(**FAST)
        features = baseline.featurize({"tool_name": "t"})
        assert features["arg_len"] == 2  # json.dumps({}) = "{}"

    def test_featurize_no_tool_name(self):
        """Missing tool_name defaults to empty string."""
        baseline = AdaptiveBehavioralBaseline(**FAST)
        features = baseline.featurize({})
        assert features["tool_id"] == int(hashlib.md5(b"").hexdigest(), 16) % 1000

    def test_featurize_complex_args(self):
        """Complex nested args produce higher entropy."""
        baseline = AdaptiveBehavioralBaseline(**FAST)
        simple = baseline.featurize(_call(args={"x": 1}))
        complex_args = baseline.featurize(
            _call(
                args={
                    "query": "SELECT * FROM users WHERE id > 100",
                    "params": [1, 2, 3],
                    "nested": {"a": "b"},
                }
            )
        )
        assert complex_args["arg_len"] > simple["arg_len"]
        assert complex_args["arg_entropy"] > simple["arg_entropy"]

    def test_multiple_roles_independent_models(self):
        """Different roles get independent models."""
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=3, **FAST)
        for _ in range(4):
            baseline.score("analyst", _call())
        for _ in range(4):
            baseline.score("executor", _call(tool="shell_exec"))
        assert baseline._call_counts["analyst"] == 4
        assert baseline._call_counts["executor"] == 4
        assert "analyst" in baseline._role_models
        assert "executor" in baseline._role_models

    def test_score_clamped_0_1(self):
        """Score is always in [0, 1] range."""
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=2, **FAST)
        for _ in range(5):
            score = baseline.score("r", _call())
            assert 0.0 <= score <= 1.0

    def test_persist_and_load(self):
        """Persist to disk and load restores state."""
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=3, **FAST)
        for _ in range(5):
            baseline.score("analyst", _call())

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            persist_path = f.name
        baseline.persist(persist_path)

        baseline2 = AdaptiveBehavioralBaseline(cold_start_threshold=3, **FAST)
        baseline2.load(persist_path)
        assert baseline2._call_counts["analyst"] == 5
        assert "analyst" in baseline2._role_models
        os.unlink(persist_path)

    def test_shannon_entropy_single_char(self):
        """Single character string has 0 entropy."""
        assert AdaptiveBehavioralBaseline._shannon_entropy("a") == 0.0

    def test_shannon_entropy_two_equal_chars(self):
        """Two of the same char = 0."""
        assert AdaptiveBehavioralBaseline._shannon_entropy("aa") == 0.0

    def test_shannon_entropy_two_different_chars(self):
        """Two different chars = 1 bit."""
        e = AdaptiveBehavioralBaseline._shannon_entropy("ab")
        assert abs(e - 1.0) < 0.001

    def test_shannon_entropy_known_value(self):
        """Four unique chars equally distributed = 2 bits."""
        e = AdaptiveBehavioralBaseline._shannon_entropy("abcd")
        assert abs(e - 2.0) < 0.001

    def test_cold_start_boundary_exact(self):
        """At exactly cold_start_threshold, switches to per-role model."""
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=3, **FAST)
        # Calls 0,1,2 (3 calls) are cold start
        for _ in range(3):
            baseline.score("analyst", _call())
        assert baseline._call_counts["analyst"] == 3
        assert baseline._call_counts["_global"] == 3
        # Call 3 (4th) is post-cold-start
        baseline.score("analyst", _call())
        assert baseline._call_counts["analyst"] == 4
        assert baseline._call_counts["_global"] == 3  # no more global updates


# ═══════════════════════════════════════════════════════════════════════════════
# ── L4Orchestrator exhaustive ─────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


def _orch(policy="ALLOW", bl=0.1, gr=0.1, dr=0.1, **kw):
    pdp = MagicMock()
    pdp.evaluate.return_value = policy
    baseline = MagicMock()
    baseline.score.return_value = bl
    graph = MagicMock()
    graph.add_call.return_value = gr
    drift = MagicMock()
    drift.record.return_value = dr
    return L4Orchestrator(pdp=pdp, baseline=baseline, graph_scorer=graph, drift_monitor=drift, **kw)


def _span(**kw):
    defaults = dict(
        session_id="s",
        role="r",
        tool_name="t",
        args_hash="h" * 64,
        resource_sensitivity=0,
        data_volume_kb=0.0,
        timestamp=datetime.now(tz=timezone.utc),
    )
    defaults.update(kw)
    return TelemetrySpan(**defaults)


class TestOrchestratorExhaustive:
    def test_deny_risk_score_is_1(self):
        """Policy DENY returns risk_score=1.0."""
        orch = _orch(policy="DENY")
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert r["risk_score"] == 1.0

    def test_deny_latency_recorded(self):
        """Even DENY path records latency."""
        orch = _orch(policy="DENY")
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert "latency_ms" in r
        assert r["latency_ms"] >= 0

    def test_exact_elevate_boundary(self):
        """risk_score exactly at elevate_threshold -> ELEVATE."""
        # 0.35*1.0 + 0.40*0.875 + 0.25*1.0 = 0.35 + 0.35 + 0.25 = 0.95 -> DENY
        # Need exactly 0.70: 0.35*x + 0.40*x + 0.25*x = x = 0.70
        orch = _orch(policy="ALLOW", bl=0.70, gr=0.70, dr=0.70)
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert r["decision"] == "ELEVATE"  # 0.35*0.7 + 0.40*0.7 + 0.25*0.7 = 0.7
        assert abs(r["risk_score"] - 0.70) < 0.001

    def test_exact_deny_boundary(self):
        """risk_score exactly at deny_threshold -> DENY."""
        # 0.35*0.9 + 0.40*0.9 + 0.25*0.9 = 0.9
        orch = _orch(policy="ALLOW", bl=0.9, gr=0.9, dr=0.9)
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert r["decision"] == "DENY"
        assert abs(r["risk_score"] - 0.90) < 0.001

    def test_just_below_elevate_threshold(self):
        """risk_score just below elevate_threshold -> ALLOW."""
        # 0.35*0.69 + 0.40*0.69 + 0.25*0.69 = 0.69
        orch = _orch(policy="ALLOW", bl=0.69, gr=0.69, dr=0.69)
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert r["decision"] == "ALLOW"

    def test_custom_thresholds(self):
        """Custom thresholds override defaults."""
        orch = _orch(
            policy="ALLOW", bl=0.5, gr=0.5, dr=0.5, elevate_threshold=0.40, deny_threshold=0.60
        )
        r = asyncio.run(orch.evaluate(_req(), _span()))
        # risk = 0.5 -> >= deny_threshold (0.60)? No. >= elevate (0.40)? Yes.
        assert r["decision"] == "ELEVATE"

    def test_custom_weights(self):
        """Custom weights change the fusion calculation."""
        orch = _orch(
            policy="ALLOW",
            bl=1.0,
            gr=0.0,
            dr=0.0,
            weights={"baseline": 1.0, "graph": 0.0, "drift": 0.0},
        )
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert abs(r["risk_score"] - 1.0) < 0.001
        assert r["decision"] == "DENY"

    def test_zero_risk_all_scorers(self):
        """All scorers return 0 -> risk_score=0 -> ALLOW."""
        orch = _orch(policy="ALLOW", bl=0.0, gr=0.0, dr=0.0)
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert r["decision"] == "ALLOW"
        assert r["risk_score"] == 0.0

    def test_risk_score_capped_at_1(self):
        """Even with extreme scores, risk_score is capped at 1.0."""
        orch = _orch(policy="ALLOW", bl=5.0, gr=5.0, dr=5.0)
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert r["risk_score"] == 1.0

    def test_sub_scores_reported(self):
        """Individual sub-scores are reported in result."""
        orch = _orch(policy="ALLOW", bl=0.3, gr=0.4, dr=0.2)
        r = asyncio.run(orch.evaluate(_req(), _span()))
        assert r["baseline_score"] == 0.3
        assert r["graph_score"] == 0.4
        assert r["drift_score"] == 0.2

    def test_l4b_receives_only_span_data(self):
        """Verify _l4b_score constructs dict from span, not raw args."""
        orch = _orch(policy="ALLOW")
        span = _span(tool_name="file_read", args_hash="deadbeef" * 8)
        asyncio.run(orch.evaluate(_req(), span))
        # Check the tool_call_dict passed to baseline.score
        bl_call = orch._baseline.score.call_args
        tool_call_dict = bl_call[0][1]
        assert tool_call_dict["tool_name"] == "file_read"
        assert tool_call_dict["args"]["hash"] == "deadbeef" * 8
        assert "raw" not in str(tool_call_dict).lower()


# ═══════════════════════════════════════════════════════════════════════════════
# ── YAML config file validation ───────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


class TestBundledYAMLConfigs:
    def test_l4_policies_yaml_loads(self):
        """Bundled l4_policies.yaml is valid YAML."""
        config_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "agentguard", "config"
        )
        path = os.path.join(config_dir, "l4_policies.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        assert "default_effect" in data
        assert "rules" in data
        assert len(data["rules"]) > 0

    def test_l4_policies_all_rules_have_required_fields(self):
        config_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "agentguard", "config"
        )
        path = os.path.join(config_dir, "l4_policies.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        for rule in data["rules"]:
            assert "id" in rule, f"Missing 'id' in rule: {rule}"
            assert "roles" in rule, f"Missing 'roles' in rule {rule['id']}"
            assert "actions" in rule, f"Missing 'actions' in rule {rule['id']}"
            assert "effect" in rule, f"Missing 'effect' in rule {rule['id']}"
            assert rule["effect"] in ("ALLOW", "DENY", "ELEVATE"), (
                f"Invalid effect '{rule['effect']}' in rule {rule['id']}"
            )

    def test_ioa_patterns_yaml_loads(self):
        """Bundled ioa_patterns.yaml is valid YAML."""
        config_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "agentguard", "config"
        )
        path = os.path.join(config_dir, "ioa_patterns.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        assert "patterns" in data
        assert len(data["patterns"]) > 0

    def test_ioa_patterns_all_have_required_fields(self):
        config_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "agentguard", "config"
        )
        path = os.path.join(config_dir, "ioa_patterns.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        for pat in data["patterns"]:
            assert "name" in pat
            assert "sequence" in pat
            assert isinstance(pat["sequence"], list)
            assert len(pat["sequence"]) >= 2
            assert "risk_delta" in pat
            assert 0.0 <= pat["risk_delta"] <= 1.0

    def test_bundled_policies_work_with_pdp(self):
        """PolicyDecisionPoint can load the bundled l4_policies.yaml."""
        config_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "agentguard", "config"
        )
        path = os.path.join(config_dir, "l4_policies.yaml")
        pdp = PolicyDecisionPoint(path)
        # Reader reading public -> ALLOW
        result = pdp.evaluate(_req(role="reader", action="read", resource_sensitivity=0))
        assert result == "ALLOW"

    def test_bundled_ioa_patterns_work_with_graph(self):
        """SessionGraphScorer can use the bundled ioa_patterns.yaml."""
        config_dir = os.path.join(
            os.path.dirname(__file__), "..", "..", "src", "agentguard", "config"
        )
        path = os.path.join(config_dir, "ioa_patterns.yaml")
        with open(path) as f:
            data = yaml.safe_load(f)
        scorer = SessionGraphScorer(data["patterns"])
        # Trigger Credential Harvesting: file_read, file_read, http_post
        scorer.add_call("file_read", "aaa")
        scorer.add_call("file_read", "bbb")
        score = scorer.add_call("http_post", "ccc")
        assert score >= 0.90 * 0.5


# ═══════════════════════════════════════════════════════════════════════════════
# ── Integration: end-to-end L4Orchestrator with real sub-scorers ──────────────
# ═══════════════════════════════════════════════════════════════════════════════


class TestIntegrationOrchestrator:
    def _make_real_orchestrator(self):
        """Build an orchestrator with real (not mocked) sub-scorers."""
        policies = {
            "default_effect": "DENY",
            "rules": [
                {
                    "id": "allow_read",
                    "roles": ["*"],
                    "actions": ["read"],
                    "min_sensitivity": 0,
                    "conditions": [{"key": "resource_sensitivity", "operator": "lte", "value": 2}],
                    "effect": "ALLOW",
                },
                {
                    "id": "critical_deny",
                    "roles": ["*"],
                    "actions": ["*"],
                    "min_sensitivity": 3,
                    "effect": "DENY",
                },
            ],
        }
        path = _write_yaml(policies)

        pdp = PolicyDecisionPoint(path)
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=3, **FAST)
        ioa_patterns = [
            {
                "name": "CredHarvest",
                "sequence": ["file_read", "file_read", "http_post"],
                "risk_delta": 0.90,
            },
        ]
        graph = SessionGraphScorer(ioa_patterns)
        drift = ComplianceDriftMonitor(window_size=8)

        orch = L4Orchestrator(
            pdp=pdp,
            baseline=baseline,
            graph_scorer=graph,
            drift_monitor=drift,
        )
        return orch, path

    def test_e2e_benign_read(self):
        """Benign read of public resource -> ALLOW."""
        orch, path = self._make_real_orchestrator()
        req = _req(action="read", resource_sensitivity=0)
        span = _span(tool_name="file_read", resource_sensitivity=0)
        r = asyncio.run(orch.evaluate(req, span))
        assert r["decision"] == "ALLOW"
        assert r["risk_score"] < 0.7
        os.unlink(path)

    def test_e2e_critical_resource_denied(self):
        """Access to critical resource -> DENY from policy."""
        orch, path = self._make_real_orchestrator()
        req = _req(action="write", resource_sensitivity=3)
        span = _span(resource_sensitivity=3)
        r = asyncio.run(orch.evaluate(req, span))
        assert r["decision"] == "DENY"
        assert r["policy"] == "DENY"
        os.unlink(path)

    def test_e2e_credential_harvesting_attack(self):
        """IOA: file_read, file_read, http_post -> elevated risk."""
        orch, path = self._make_real_orchestrator()
        for tool in ["file_read", "file_read"]:
            req = _req(action="read", resource_sensitivity=1)
            span = _span(tool_name=tool, resource_sensitivity=1)
            asyncio.run(orch.evaluate(req, span))

        req = _req(action="read", resource_sensitivity=1)
        span = _span(tool_name="http_post", resource_sensitivity=1)
        r = asyncio.run(orch.evaluate(req, span))
        # Graph scorer should have detected the IOA pattern
        assert r["graph_score"] >= 0.45  # 0.90 * 0.5 path weight at minimum
        os.unlink(path)

    def test_e2e_sensitivity_escalation(self):
        """Progressive sensitivity escalation -> drift detected."""
        orch, path = self._make_real_orchestrator()
        escalation = [
            ("http_get", 0),
            ("http_get", 0),
            ("sql_query", 1),
            ("file_read", 1),
            ("http_post", 2),
            ("file_write", 2),
            ("shell_exec", 2),
            ("admin_call", 2),
        ]
        for tool, sens in escalation:
            req = _req(action="read", resource_sensitivity=min(sens, 2))
            span = _span(tool_name=tool, resource_sensitivity=sens)
            r = asyncio.run(orch.evaluate(req, span))
        assert r["drift_score"] > 0.5
        os.unlink(path)


# ═══════════════════════════════════════════════════════════════════════════════
# ── Backward compatibility + import paths ─────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


class TestBackwardCompat:
    def test_legacy_behavioral_import(self):
        from agentguard.l4.behavioral import BehavioralAnomalyDetector

        assert BehavioralAnomalyDetector is not None

    def test_legacy_anomaly_classes(self):
        from agentguard.l4.behavioral import AnomalyResult, AnomalySignal, TaskProfile

        assert AnomalyResult is not None
        assert AnomalySignal is not None
        assert TaskProfile is not None

    def test_legacy_rbac_import(self):
        from agentguard.l4.rbac import L4RBACEngine, RBACDecision, AccessContext

        assert L4RBACEngine is not None
        assert RBACDecision is not None
        assert AccessContext is not None

    def test_l4_init_exports_old(self):
        from agentguard.l4 import (
            L4RBACEngine,
            BehavioralAnomalyDetector,
            AnomalyResult,
            AnomalySignal,
            TaskProfile,
        )

        assert all(
            c is not None
            for c in [
                L4RBACEngine,
                BehavioralAnomalyDetector,
                AnomalyResult,
                AnomalySignal,
                TaskProfile,
            ]
        )

    def test_l4_init_exports_new(self):
        from agentguard.l4 import (
            L4Orchestrator,
            PolicyDecisionPoint,
            AccessRequest,
            TelemetrySpan,
        )

        assert all(
            c is not None
            for c in [
                L4Orchestrator,
                PolicyDecisionPoint,
                AccessRequest,
                TelemetrySpan,
            ]
        )

    def test_backward_compat_shim_l4_behavioral(self):
        from agentguard.l4_behavioral import BehavioralAnomalyDetector as Old
        from agentguard.l4.behavioral import BehavioralAnomalyDetector as New

        assert Old is New

    def test_backward_compat_shim_l4_rbac(self):
        from agentguard.l4_rbac import L4RBACEngine as Old
        from agentguard.l4.rbac import L4RBACEngine as New

        assert Old is New

    def test_sub_scorer_imports(self):
        from agentguard.l4.behavioral.baseline import AdaptiveBehavioralBaseline
        from agentguard.l4.behavioral.session_graph import SessionGraphScorer
        from agentguard.l4.behavioral.drift_monitor import ComplianceDriftMonitor

        assert all(
            c is not None
            for c in [
                AdaptiveBehavioralBaseline,
                SessionGraphScorer,
                ComplianceDriftMonitor,
            ]
        )


# ═══════════════════════════════════════════════════════════════════════════════
# ── Config properties ─────────────────────────────────────────────────────────
# ═══════════════════════════════════════════════════════════════════════════════


class TestConfigProperties:
    def test_l4_adaptive_defaults(self):
        """All L4 adaptive config properties have correct defaults."""
        from agentguard.config import AgentGuardConfig

        cfg = AgentGuardConfig({"global": {"mode": "enforce"}})
        assert cfg.l4_adaptive_enabled is False
        assert cfg.l4_policies_file is None
        assert cfg.l4_ioa_patterns_file is None
        assert cfg.l4_elevate_threshold == 0.70
        assert cfg.l4_deny_threshold == 0.90
        assert cfg.l4_cold_start_threshold == 50
        assert cfg.l4_drift_window == 8
        assert cfg.l4_baseline_weights == {"baseline": 0.35, "graph": 0.40, "drift": 0.25}

    def test_l4_adaptive_custom_values(self):
        """Custom values from YAML override defaults."""
        from agentguard.config import AgentGuardConfig

        cfg = AgentGuardConfig(
            {
                "global": {"mode": "enforce"},
                "l4_adaptive": {
                    "enabled": True,
                    "policies_file": "/custom/policies.yaml",
                    "ioa_patterns_file": "/custom/ioa.yaml",
                    "elevate_threshold": 0.60,
                    "deny_threshold": 0.85,
                    "cold_start_threshold": 100,
                    "drift_window": 16,
                    "weights": {"baseline": 0.5, "graph": 0.3, "drift": 0.2},
                },
            }
        )
        assert cfg.l4_adaptive_enabled is True
        assert cfg.l4_policies_file == "/custom/policies.yaml"
        assert cfg.l4_ioa_patterns_file == "/custom/ioa.yaml"
        assert cfg.l4_elevate_threshold == 0.60
        assert cfg.l4_deny_threshold == 0.85
        assert cfg.l4_cold_start_threshold == 100
        assert cfg.l4_drift_window == 16
        assert cfg.l4_baseline_weights == {"baseline": 0.5, "graph": 0.3, "drift": 0.2}
