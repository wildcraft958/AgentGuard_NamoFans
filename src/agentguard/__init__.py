"""
AgentGuard — Multi-layer security middleware for AI agents.

Subpackages:
  - l1_input:      Input security (prompt injection, content filtering)
  - l2_output:     Output security (toxicity, PII, groundedness)
  - l4:            Access control (RBAC) and behavioral anomaly detection
  - tool_firewall: Tool call validation (rule-based, entity, MELON, approval)
  - sandbox:       Subprocess isolation (landlock, seccomp, resource limits)
  - observability: Audit logging (SQLite) and OpenTelemetry tracing/metrics
  - testing:       Red-team utilities (OWASP scanner, Promptfoo bridge)
  - dashboard:     FastAPI dashboard server (optional dependency)
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
from agentguard.testing.owasp_scanner import OWASPScanResult, scan_agent
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
