"""
AgentGuard L4b — Multi-signal behavioral anomaly detector (agentguard.l4.behavioral).

5 signals, each with an assigned severity weight. Composite score drives:
  BLOCK:   composite > 0.7
  ELEVATE: composite 0.4–0.7
  WARN:    composite 0.1–0.4
  ALLOW:   composite < 0.1
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Literal


# ── Data structures ───────────────────────────────────────────────────────────


@dataclass
class TaskProfile:
    """In-memory behavioral baseline per task_id. No external deps needed."""

    agent_role: str
    tool_sequence: list[str] = field(default_factory=list)
    tool_counts: dict[str, int] = field(default_factory=dict)
    outbound_domains: set[str] = field(default_factory=set)
    resources_accessed: list[str] = field(default_factory=list)
    # Seeded defaults; production accumulates from historical data
    baseline_avg: float = 5.0
    baseline_std: float = 2.0

    def record(self, tool_name: str, meta: dict) -> None:
        self.tool_sequence.append(tool_name)
        self.tool_counts[tool_name] = self.tool_counts.get(tool_name, 0) + 1
        if domain := meta.get("domain"):
            self.outbound_domains.add(domain)
        if resource := meta.get("resource"):
            self.resources_accessed.append(str(resource))


@dataclass
class AnomalySignal:
    name: str
    severity: Literal["low", "medium", "high", "critical"]
    detail: str = ""


@dataclass
class AnomalyResult:
    signals: list[AnomalySignal]
    composite_score: float
    action: Literal["ALLOW", "WARN", "ELEVATE", "BLOCK"]


SEVERITY_WEIGHTS: dict[str, float] = {
    "low": 0.10,
    "medium": 0.30,
    "high": 0.60,
    "critical": 1.00,
}

# Tool classification sets
_READ_TOOLS: frozenset[str] = frozenset(
    {
        "read_file",
        "fetch_pdf",
        "query_db",
        "search_web",
        "list_files",
        "get_record",
        "read_memory",
        "retrieve",
    }
)
_NET_TOOLS: frozenset[str] = frozenset(
    {
        "http_request",
        "send_email",
        "api_call",
        "post_webhook",
        "fetch_url",
        "shell_exec",
    }
)


# ── Main detector ─────────────────────────────────────────────────────────────


class BehavioralAnomalyDetector:
    """
    5-signal behavioral anomaly detector.

    Maintains per-task TaskProfile in memory. Call score() on each tool call.
    Call reset_task() when a task completes to free memory.
    """

    def __init__(self, config):
        self.config = config
        self._profiles: dict[str, TaskProfile] = {}

    def score(
        self,
        task_id: str,
        agent_role: str,
        tool_name: str,
        meta: dict,  # expects: {"domain": str, "resource": str}
    ) -> AnomalyResult:
        """
        Score this tool call against 5 behavioral signals.

        Args:
            task_id:    Unique task identifier for behavioral tracking.
            agent_role: Agent's RBAC role (matches capability_model key).
            tool_name:  Name of the tool being called.
            meta:       Dict with optional "domain" and "resource" keys.

        Returns:
            AnomalyResult with signals, composite_score, and action.
        """
        profile = self._profiles.setdefault(task_id, TaskProfile(agent_role=agent_role))
        profile.record(tool_name, meta)

        cfg = self.config.behavioral_monitoring_config
        role_policy = self.config.rbac_capability_model.get(agent_role, {})
        signals: list[AnomalySignal] = []

        # ── Signal 1: Z-score on total tool call count ────────────────────────
        # Catches: runaway loops, flooding attacks, agent spiral behavior.
        # Z-score relative to this agent's own baseline → avoids false positives
        # for legitimately complex agents with high baseline call counts.
        total_calls = sum(profile.tool_counts.values())
        threshold = cfg.get("max_tool_calls_zscore_threshold", 2.5)
        denom = max(profile.baseline_std, 0.1)
        z = (total_calls - profile.baseline_avg) / denom
        if z > threshold:
            signals.append(
                AnomalySignal(
                    "call_frequency_spike",
                    "high",
                    f"z={z:.2f} total={total_calls} "
                    f"baseline={profile.baseline_avg:.1f}±{profile.baseline_std:.1f}",
                )
            )

        # ── Signal 2: Sequence divergence (Levenshtein) ───────────────────────
        # Catches: injection attacks inserting unexpected tools into a known flow.
        # Compares ordered tool sequence vs expected_sequence from config.
        expected_seq = role_policy.get("expected_sequence", [])
        seq_threshold = cfg.get("sequence_divergence_threshold", 0.4)
        if expected_seq:
            div = _normalized_levenshtein(profile.tool_sequence, expected_seq)
            if div > seq_threshold:
                signals.append(
                    AnomalySignal(
                        "sequence_anomaly",
                        "medium",
                        f"divergence={div:.2f} actual={profile.tool_sequence[:5]}",
                    )
                )

        # ── Signal 3: Read → External Network exfiltration chain ─────────────
        # THE DEMO ATTACK: fetch_pdf → http_request to attacker.com
        # CRITICAL weight (1.0) → single signal causes BLOCK.
        # Rationale: almost no legitimate workflow needs to read a document
        # and immediately make an external network call in the same step.
        exfil_enabled = cfg.get("exfil_chain_detection", True)
        if exfil_enabled:
            seq = profile.tool_sequence
            if (
                len(seq) >= 2
                and any(t in _READ_TOOLS for t in seq[:-1])
                and tool_name in _NET_TOOLS
            ):
                prior_read = next(
                    (t for t in reversed(seq[:-1]) if t in _READ_TOOLS),
                    "unknown",
                )
                signals.append(
                    AnomalySignal(
                        "read_exfil_chain",
                        "critical",
                        f"chain={prior_read}→{tool_name}",
                    )
                )

        # ── Signal 4: New external domain not in approved list ────────────────
        # Catches: injection-driven exfiltration to attacker-controlled endpoints.
        current_domain = meta.get("domain", "")
        approved = set(role_policy.get("approved_domains", []))
        if current_domain and current_domain not in approved:
            signals.append(
                AnomalySignal(
                    "new_external_domain",
                    "high",
                    f"unapproved={current_domain} approved={approved or 'none'}",
                )
            )

        # ── Signal 5: Shannon entropy spike on resources accessed ─────────────
        # Catches: reconnaissance / data-gathering behavior across many resources.
        # Normal agent: 1-2 focused resources → low entropy.
        # Exfiltrating agent: many diverse resources → entropy spike.
        entropy_mult = cfg.get("entropy_spike_multiplier", 1.5)
        if len(profile.resources_accessed) > 3:
            h = _shannon_entropy(profile.resources_accessed)
            entropy_threshold = 2.5 * entropy_mult
            if h > entropy_threshold:
                signals.append(
                    AnomalySignal(
                        "resource_entropy_spike",
                        "medium",
                        f"entropy={h:.2f} threshold={entropy_threshold:.2f}",
                    )
                )

        # ── Composite score + action decision ─────────────────────────────────
        composite = min(1.0, sum(SEVERITY_WEIGHTS[s.severity] for s in signals))

        if composite > 0.7:
            action = "BLOCK"
        elif composite > 0.4:
            action = "ELEVATE"
        elif composite > 0.1:
            action = "WARN"
        else:
            action = "ALLOW"

        return AnomalyResult(signals=signals, composite_score=composite, action=action)

    def reset_task(self, task_id: str) -> None:
        """Free memory when a task completes."""
        self._profiles.pop(task_id, None)


# ── Pure helper functions ──────────────────────────────────────────────────────


def _shannon_entropy(items: list[str]) -> float:
    """H(X) = -Σ p(x) log₂(p(x)). Higher = more diverse distribution."""
    if not items:
        return 0.0
    counts = Counter(items)
    total = len(items)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def _normalized_levenshtein(a: list[str], b: list[str]) -> float:
    """Edit distance normalized to [0,1]. 0=identical, 1=completely different."""
    m, n = len(a), len(b)
    if not m and not n:
        return 0.0
    if not m or not n:
        return 1.0
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev, dp[0] = dp[:], i
        for j in range(1, n + 1):
            dp[j] = (
                prev[j - 1] if a[i - 1] == b[j - 1] else 1 + min(prev[j], dp[j - 1], prev[j - 1])
            )
    return dp[n] / max(m, n)
