"""
AgentGuard - A Guardian Agent middleware for AI agent security.

Layer 1 (Input Security): Prompt injection detection, content filtering.
Layer 2 (Output Security): Output toxicity detection, PII detection.
OWASP Scanner: DeepTeam-powered red-team scan against OWASP Top 10 for LLMs
               and OWASP Top 10 for Agentic Applications.
"""

from agentguard.guardian import Guardian
from agentguard.exceptions import (
    AgentGuardError, InputBlockedError, OutputBlockedError,
    ToolCallBlockedError, ConfigurationError,
)
from agentguard.decorators import guard, guard_input, guard_tool, GuardedToolRegistry
from agentguard.owasp_scanner import scan_agent, OWASPScanResult

__all__ = [
    "Guardian",
    "AgentGuardError",
    "InputBlockedError",
    "OutputBlockedError",
    "ToolCallBlockedError",
    "ConfigurationError",
    "guard",
    "guard_input",
    "guard_tool",
    "GuardedToolRegistry",
    "scan_agent",
    "OWASPScanResult",
]
__version__ = "0.3.0"
