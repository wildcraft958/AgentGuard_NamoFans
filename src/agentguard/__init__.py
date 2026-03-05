"""
AgentGuard - A Guardian Agent middleware for AI agent security.

Layer 1 (Input Security): Prompt injection detection, content filtering.
Layer 2 (Output Security): Output toxicity detection, PII detection.
"""

from agentguard.guardian import Guardian
from agentguard.exceptions import AgentGuardError, InputBlockedError, OutputBlockedError, ConfigurationError
from agentguard.decorators import guard, guard_input

__all__ = [
    "Guardian",
    "AgentGuardError",
    "InputBlockedError",
    "OutputBlockedError",
    "ConfigurationError",
    "guard",
    "guard_input",
]
__version__ = "0.2.0"
