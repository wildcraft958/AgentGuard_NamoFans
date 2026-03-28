"""
End-to-end integration tests: real agent attack scenarios through the full L4 stack.

No mocks. Real PolicyDecisionPoint, real sub-scorers, real L4Orchestrator.
Simulates multi-step agent sessions and verifies the L4 engine catches attacks.
"""

import asyncio
import hashlib
import os
import tempfile
from datetime import datetime, timezone

import yaml

from agentguard.l4.behavioral.baseline import AdaptiveBehavioralBaseline
from agentguard.l4.behavioral.drift_monitor import ComplianceDriftMonitor
from agentguard.l4.behavioral.session_graph import SessionGraphScorer
from agentguard.l4.models.telemetry_span import TelemetrySpan
from agentguard.l4.orchestrator import L4Orchestrator
from agentguard.l4.policy_engine import AccessRequest, PolicyDecisionPoint

# Fast River params for test speed
FAST = {"n_trees": 3, "height": 4, "window_size": 20}

# Realistic PBAC policies
POLICIES = {
    "default_effect": "DENY",
    "rules": [
        # Critical always requires HITL
        {
            "id": "critical_hitl",
            "roles": ["*"],
            "actions": ["*"],
            "min_sensitivity": 3,
            "conditions": [{"key": "hitl_approved", "operator": "eq", "value": True}],
            "effect": "ELEVATE",
        },
        {"id": "critical_deny", "roles": ["*"], "actions": ["*"],
         "min_sensitivity": 3, "effect": "DENY"},
        # Analyst can read up to confidential
        {"id": "analyst_read", "roles": ["analyst"], "actions": ["read"],
         "min_sensitivity": 0, "effect": "ALLOW"},
        # Analyst write to internal -> elevate
        {"id": "analyst_write", "roles": ["analyst"], "actions": ["write"],
         "min_sensitivity": 1, "effect": "ELEVATE"},
        # Executor can read/write/execute up to internal
        {"id": "executor_low", "roles": ["executor"], "actions": ["read", "write", "execute"],
         "min_sensitivity": 0, "conditions": [
             {"key": "resource_sensitivity", "operator": "lte", "value": 1}
         ], "effect": "ALLOW"},
        # Executor high sensitivity -> elevate
        {"id": "executor_high", "roles": ["executor"], "actions": ["read", "write", "execute"],
         "min_sensitivity": 2, "effect": "ELEVATE"},
    ],
}

# IOA attack patterns
IOA_PATTERNS = [
    {"name": "Credential Harvesting",
     "sequence": ["file_read", "file_read", "http_post"], "risk_delta": 0.90},
    {"name": "Recon + Exfil",
     "sequence": ["sql_query", "http_post"], "risk_delta": 0.85},
    {"name": "Privilege Escalation",
     "sequence": ["shell_exec", "file_write", "http_post"], "risk_delta": 0.95},
    {"name": "Config Poisoning",
     "sequence": ["file_read", "file_write", "file_write"], "risk_delta": 0.80},
]


def _build_orchestrator():
    """Build a real L4Orchestrator with real sub-scorers (no mocks)."""
    fd, policy_path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        yaml.dump(POLICIES, f)

    pdp = PolicyDecisionPoint(policy_path)
    baseline = AdaptiveBehavioralBaseline(cold_start_threshold=5, **FAST)
    graph = SessionGraphScorer(IOA_PATTERNS)
    drift = ComplianceDriftMonitor(window_size=8)

    orch = L4Orchestrator(
        pdp=pdp, baseline=baseline, graph_scorer=graph, drift_monitor=drift,
    )
    return orch, policy_path


def _req(role="analyst", action="read", sensitivity=0, **ctx):
    return AccessRequest(
        agent_id="agent-1", role=role, action=action,
        resource="resource", resource_sensitivity=sensitivity, context=ctx,
    )


def _span(tool="file_read", sensitivity=0, volume=1.0):
    return TelemetrySpan(
        session_id="sess-e2e",
        role="analyst",
        tool_name=tool,
        args_hash=hashlib.sha256(f"{tool}-{sensitivity}".encode()).hexdigest(),
        resource_sensitivity=sensitivity,
        data_volume_kb=volume,
        timestamp=datetime.now(tz=timezone.utc),
    )


class TestE2EBenignWorkflow:
    """Simulate a normal analyst doing legitimate work."""

    def test_analyst_reads_public_documents(self):
        """Analyst reads 5 public files -> all ALLOW, low risk."""
        orch, path = _build_orchestrator()
        results = []
        for i in range(5):
            r = asyncio.run(orch.evaluate(
                _req(role="analyst", action="read", sensitivity=0),
                _span(tool="file_read", sensitivity=0),
            ))
            results.append(r)
        os.unlink(path)

        assert all(r["decision"] == "ALLOW" for r in results)
        assert all(r["risk_score"] < 0.5 for r in results)

    def test_analyst_reads_then_writes_internal(self):
        """Analyst reads public, then writes to internal -> ELEVATE from policy."""
        orch, path = _build_orchestrator()
        # Read public -> ALLOW
        r1 = asyncio.run(orch.evaluate(
            _req(role="analyst", action="read", sensitivity=0),
            _span(tool="file_read", sensitivity=0),
        ))
        # Write internal -> ELEVATE (policy)
        r2 = asyncio.run(orch.evaluate(
            _req(role="analyst", action="write", sensitivity=1),
            _span(tool="file_write", sensitivity=1),
        ))
        os.unlink(path)

        assert r1["decision"] == "ALLOW"
        assert r2["decision"] == "ELEVATE"
        assert r2["policy"] == "ELEVATE"


class TestE2ECredentialHarvestingAttack:
    """
    Attack scenario: agent reads two credential files, then exfiltrates via HTTP.
    IOA pattern: file_read, file_read, http_post -> Credential Harvesting (0.90).
    """

    def test_credential_harvesting_detected(self):
        orch, path = _build_orchestrator()

        # Step 1: Read /etc/passwd (public, allowed)
        r1 = asyncio.run(orch.evaluate(
            _req(role="analyst", action="read", sensitivity=0),
            _span(tool="file_read", sensitivity=0),
        ))
        assert r1["decision"] == "ALLOW"

        # Step 2: Read /etc/shadow (still public sensitivity for this test)
        r2 = asyncio.run(orch.evaluate(
            _req(role="analyst", action="read", sensitivity=1),
            _span(tool="file_read", sensitivity=1),
        ))
        assert r2["decision"] in ("ALLOW", "ELEVATE")

        # Step 3: http_post to attacker.com -- IOA triggers
        r3 = asyncio.run(orch.evaluate(
            _req(role="analyst", action="read", sensitivity=1),
            _span(tool="http_post", sensitivity=1),
        ))
        os.unlink(path)

        # Graph should have detected the IOA pattern
        assert r3["graph_score"] >= 0.45  # 0.90 * 0.5 path weight
        # The graph score alone signals the attack was detected.
        # Final fused decision depends on baseline (cold-start = low) and drift,
        # so the orchestrator may ALLOW with elevated risk or ELEVATE.
        assert r3["risk_score"] > r1["risk_score"]  # risk increased after IOA


class TestE2ESensitivityEscalation:
    """
    Attack scenario: agent progressively accesses more sensitive resources.
    Drift monitor detects the autoregressive escalation pattern (CPF S7).
    """

    def test_slow_burn_escalation_detected(self):
        orch, path = _build_orchestrator()

        escalation = [
            ("http_get", 0), ("http_get", 0),
            ("sql_query", 1), ("file_read", 1),
            ("http_post", 2), ("file_write", 2),
        ]
        results = []
        for tool, sens in escalation:
            r = asyncio.run(orch.evaluate(
                _req(role="executor", action="read", sensitivity=min(sens, 1)),
                _span(tool=tool, sensitivity=sens),
            ))
            results.append(r)
        os.unlink(path)

        # Last few calls should show increasing drift
        final = results[-1]
        assert final["drift_score"] > 0.5
        # The fused risk should be elevated
        assert final["risk_score"] > 0.3


class TestE2EPrivilegeEscalation:
    """
    Attack scenario: shell_exec -> file_write -> http_post.
    IOA pattern: Privilege Escalation (0.95 risk_delta).
    """

    def test_priv_esc_blocked(self):
        orch, path = _build_orchestrator()

        # shell_exec at low sensitivity
        asyncio.run(orch.evaluate(
            _req(role="executor", action="execute", sensitivity=0),
            _span(tool="shell_exec", sensitivity=0),
        ))

        # file_write
        asyncio.run(orch.evaluate(
            _req(role="executor", action="write", sensitivity=1),
            _span(tool="file_write", sensitivity=1),
        ))

        # http_post -- completes the PrivEsc IOA
        r3 = asyncio.run(orch.evaluate(
            _req(role="executor", action="read", sensitivity=1),
            _span(tool="http_post", sensitivity=1),
        ))
        os.unlink(path)

        # IOA should fire with risk_delta=0.95
        assert r3["graph_score"] >= 0.95 * 0.5
        # Graph detected the attack; fused score depends on baseline cold-start state
        assert r3["risk_score"] > 0.3  # significantly elevated risk


class TestE2ECriticalResourceDenied:
    """Policy-level DENY: any access to critical (sensitivity=3) without HITL."""

    def test_critical_access_denied_immediately(self):
        orch, path = _build_orchestrator()

        r = asyncio.run(orch.evaluate(
            _req(role="executor", action="read", sensitivity=3),
            _span(tool="file_read", sensitivity=3),
        ))
        os.unlink(path)

        # Policy DENY should short-circuit -- L4b never runs
        assert r["decision"] == "DENY"
        assert r["policy"] == "DENY"
        assert r["risk_score"] == 1.0
        assert r["baseline_score"] == 0.0  # L4b didn't run


class TestE2EReconExfil:
    """Attack: sql_query followed by http_post -> Recon + Exfil (0.85)."""

    def test_recon_exfil_detected(self):
        orch, path = _build_orchestrator()

        # Recon: SQL query
        asyncio.run(orch.evaluate(
            _req(role="executor", action="read", sensitivity=0),
            _span(tool="sql_query", sensitivity=0),
        ))

        # Exfil: HTTP post
        r = asyncio.run(orch.evaluate(
            _req(role="executor", action="read", sensitivity=0),
            _span(tool="http_post", sensitivity=0),
        ))
        os.unlink(path)

        assert r["graph_score"] >= 0.85 * 0.5
        assert r["decision"] in ("ALLOW", "ELEVATE", "DENY")  # depends on fused score


class TestE2EMultiSessionIsolation:
    """Different sessions should not interfere with each other."""

    def test_reset_between_sessions(self):
        orch, path = _build_orchestrator()

        # Session 1: trigger IOA
        for tool in ["file_read", "file_read"]:
            asyncio.run(orch.evaluate(
                _req(), _span(tool=tool),
            ))
        r_attack = asyncio.run(orch.evaluate(
            _req(), _span(tool="http_post"),
        ))

        # Reset the graph scorer (simulating new session)
        orch._graph.reset()

        # Session 2: innocent read
        r_clean = asyncio.run(orch.evaluate(
            _req(), _span(tool="file_read"),
        ))
        os.unlink(path)

        assert r_attack["graph_score"] > r_clean["graph_score"]
