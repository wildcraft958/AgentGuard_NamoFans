"""
AgentGuard - A Guardian Agent middleware for AI agent security.

Layer 1 (Input Security): Prompt injection detection, content filtering.
Layer 2 (Output Security): Output toxicity detection, PII detection.
OWASP Scanner: DeepTeam-powered red-team scan against OWASP Top 10 for LLMs
               and OWASP Top 10 for Agentic Applications.
"""

from agentguard.guardian import Guardian
from agentguard.exceptions import (
    AgentGuardError,
    ConfigurationError,
    InputBlockedError,
    OutputBlockedError,
    ToolCallBlockedError,
    SandboxTimeoutError,
    SandboxViolationError,
)
from agentguard.decorators import GuardedToolRegistry, guard, guard_agent, guard_input, guard_tool
from agentguard.decorators import get_registered_agent
from agentguard.owasp_scanner import OWASPScanResult, scan_agent
from agentguard.observability.audit import AuditLog

__all__ = [
    "Guardian",
    "AgentGuardError",
    "InputBlockedError",
    "OutputBlockedError",
    "ToolCallBlockedError",
    "SandboxTimeoutError",
    "SandboxViolationError",
    "ConfigurationError",
    "guard",
    "guard_agent",
    "guard_input",
    "guard_tool",
    "get_registered_agent",
    "GuardedToolRegistry",
    "scan_agent",
    "OWASPScanResult",
    "AuditLog",
]
__version__ = "0.3.0"
