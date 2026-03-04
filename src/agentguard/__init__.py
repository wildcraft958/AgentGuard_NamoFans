"""
AgentGuard - A Guardian Agent middleware for AI agent security.

Layer 1 (Input Security): Prompt injection detection, content filtering.
"""

from agentguard.guardian import Guardian
from agentguard.exceptions import AgentGuardError, InputBlockedError, ConfigurationError
from agentguard.decorators import guard_input

__all__ = [
    "Guardian",
    "AgentGuardError",
    "InputBlockedError",
    "ConfigurationError",
    "guard_input",
]
__version__ = "0.1.0"
