"""
L4Orchestrator — fuses L4a (PBAC policy) + L4b (behavioral scoring).

L4a runs in-process synchronously (<2ms).
L4b runs via run_in_executor, isolated from agent context.
TelemetrySpan is the boundary — no raw args cross into L4b (CPF §11.2).
"""

from __future__ import annotations

import asyncio
import time


class L4Orchestrator:
    """
    Two-tier adaptive security engine.

    L4a: PolicyDecisionPoint (sync, in-process)
    L4b: Behavioral scorers (async, isolated context)
    """

    def __init__(
        self,
        pdp,
        baseline,
        graph_scorer,
        drift_monitor,
        elevate_threshold: float = 0.70,
        deny_threshold: float = 0.90,
        weights: dict | None = None,
    ):
        self._pdp = pdp
        self._baseline = baseline
        self._graph = graph_scorer
        self._drift = drift_monitor
        self._elevate_threshold = elevate_threshold
        self._deny_threshold = deny_threshold
        self._weights = weights or {"baseline": 0.35, "graph": 0.40, "drift": 0.25}

    async def evaluate(self, request, span) -> dict:
        """
        Evaluate a tool call through L4a + L4b.

        Args:
            request: AccessRequest for L4a policy evaluation.
            span: TelemetrySpan for L4b behavioral scoring (isolation boundary).

        Returns:
            Dict with decision, risk_score, policy, sub-scores, latency_ms.
        """
        start = time.monotonic()

        # L4a: Fast in-process PBAC (sync)
        policy_decision = self._pdp.evaluate(request)
        if policy_decision == "DENY":
            return {
                "decision": "DENY",
                "risk_score": 1.0,
                "policy": "DENY",
                "baseline_score": 0.0,
                "graph_score": 0.0,
                "drift_score": 0.0,
                "latency_ms": _elapsed_ms(start),
            }

        # L4b: Async behavioral evaluation (isolated, no raw context)
        loop = asyncio.get_event_loop()
        baseline_score, graph_score, drift_score = await loop.run_in_executor(
            None, self._l4b_score, span
        )

        # Fuse scores
        w = self._weights
        risk_score = min(
            1.0,
            w["baseline"] * baseline_score + w["graph"] * graph_score + w["drift"] * drift_score,
        )

        # Final decision
        if risk_score >= self._deny_threshold:
            decision = "DENY"
        elif risk_score >= self._elevate_threshold or policy_decision == "ELEVATE":
            decision = "ELEVATE"
        else:
            decision = "ALLOW"

        return {
            "decision": decision,
            "risk_score": risk_score,
            "policy": policy_decision,
            "baseline_score": baseline_score,
            "graph_score": graph_score,
            "drift_score": drift_score,
            "latency_ms": _elapsed_ms(start),
        }

    def _l4b_score(self, span) -> tuple[float, float, float]:
        """Score using all three sub-scorers. Runs in executor (isolated)."""
        tool_call_dict = {
            "tool_name": span.tool_name,
            "args": {"hash": span.args_hash},
            "data_volume_kb": span.data_volume_kb,
            "timestamp": span.timestamp,
        }
        s_baseline = self._baseline.score(span.role, tool_call_dict)
        s_graph = self._graph.add_call(span.tool_name, span.args_hash)
        s_drift = self._drift.record(span.tool_name, span.resource_sensitivity)
        return s_baseline, s_graph, s_drift


def _elapsed_ms(start: float) -> float:
    return (time.monotonic() - start) * 1000
