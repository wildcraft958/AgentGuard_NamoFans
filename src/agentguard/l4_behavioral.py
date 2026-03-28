"""Backward-compat re-export: use agentguard.l4.behavioral instead."""

from agentguard.l4.behavioral import (
    AnomalyResult,
    AnomalySignal,
    BehavioralAnomalyDetector,
    TaskProfile,
)

__all__ = [
    "AnomalyResult",
    "AnomalySignal",
    "BehavioralAnomalyDetector",
    "TaskProfile",
]
