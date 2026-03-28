"""
TelemetrySpan — the L4b isolation boundary (CPF §11.2).

This dataclass carries ONLY telemetry metadata to the behavioral scorers.
It must NEVER contain raw tool arguments, LLM messages, or agent context.
This is the architectural boundary that prevents the behavioral monitor
from being compromised by the same adversarial context as the agent.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class TelemetrySpan:
    session_id: str
    role: str
    tool_name: str
    args_hash: str  # SHA256 hex digest of serialized args — NEVER raw args
    resource_sensitivity: int  # 0-3: public, internal, confidential, critical
    data_volume_kb: float
    timestamp: datetime
