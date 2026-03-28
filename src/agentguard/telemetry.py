"""Backward-compat re-export: use agentguard.observability.telemetry instead."""

from agentguard.observability.telemetry import get_meter, get_tracer, init_telemetry

__all__ = ["init_telemetry", "get_tracer", "get_meter"]
