"""
AgentGuard L4 — Access control and behavioral anomaly detection (agentguard.l4).

Submodules:
  - rbac:           Attribute-Based Access Control (ABAC) policy evaluator (legacy)
  - behavioral:     Multi-signal behavioral anomaly detector (legacy + new sub-scorers)
  - policy_engine:  Policy Decision Point — PBAC engine (replaces static ABAC)
  - orchestrator:   L4Orchestrator — fuses L4a policy + L4b behavioral scoring
  - models:         TelemetrySpan dataclass (L4b isolation boundary)
"""

# Legacy exports (backward compat)
from agentguard.l4.behavioral import (
    AnomalyResult,
    AnomalySignal,
    BehavioralAnomalyDetector,
    TaskProfile,
)
from agentguard.l4.rbac import (
    AccessContext,
    L4RBACEngine,
    RBACDecision,
    extract_domain,
    infer_sensitivity,
    infer_verb,
)

# New L4 upgrade exports
from agentguard.l4.models.telemetry_span import TelemetrySpan
from agentguard.l4.orchestrator import L4Orchestrator
from agentguard.l4.policy_engine import AccessRequest, PolicyDecisionPoint

__all__ = [
    # Legacy
    "AccessContext",
    "AnomalyResult",
    "AnomalySignal",
    "BehavioralAnomalyDetector",
    "L4RBACEngine",
    "RBACDecision",
    "TaskProfile",
    "extract_domain",
    "infer_sensitivity",
    "infer_verb",
    # New
    "AccessRequest",
    "L4Orchestrator",
    "PolicyDecisionPoint",
    "TelemetrySpan",
]
