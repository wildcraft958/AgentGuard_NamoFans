"""
AgentGuard data models and result types.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class GuardMode(Enum):
    """Operating mode for the guardian."""

    ENFORCE = "enforce"
    MONITOR = "monitor"
    DRY_RUN = "dry-run"


class Sensitivity(Enum):
    """Sensitivity levels for detection."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Severity threshold mapping: sensitivity -> max allowed severity score
# Azure Content Safety returns severity 0 (safe) to 6 (severe)
SENSITIVITY_THRESHOLDS = {
    Sensitivity.LOW: 4,  # Only block severity >= 4
    Sensitivity.MEDIUM: 2,  # Block severity >= 2
    Sensitivity.HIGH: 0,  # Block any severity > 0
}


@dataclass
class ValidationResult:
    """Result from a single validation check."""

    is_safe: bool
    layer: str
    blocked_reason: Optional[str] = None
    details: dict = field(default_factory=dict)

    def __repr__(self):
        status = "SAFE" if self.is_safe else "BLOCKED"
        reason = f" - {self.blocked_reason}" if self.blocked_reason else ""
        return f"ValidationResult({status}, layer={self.layer}{reason})"


@dataclass
class InputValidationResult:
    """Aggregated result from all L1 input validation checks."""

    is_safe: bool
    results: list = field(default_factory=list)
    blocked_by: Optional[str] = None
    blocked_reason: Optional[str] = None

    def __repr__(self):
        status = "SAFE" if self.is_safe else f"BLOCKED by {self.blocked_by}"
        return f"InputValidationResult({status}, checks={len(self.results)})"


@dataclass
class OutputValidationResult:
    """Aggregated result from all L2 output validation checks."""

    is_safe: bool
    results: list = field(default_factory=list)
    blocked_by: Optional[str] = None
    blocked_reason: Optional[str] = None
    redacted_text: Optional[str] = None

    def __repr__(self):
        status = "SAFE" if self.is_safe else f"BLOCKED by {self.blocked_by}"
        redacted = " (redacted)" if self.redacted_text else ""
        return f"OutputValidationResult({status}, checks={len(self.results)}{redacted})"


@dataclass
class ToolCallValidationResult:
    """Aggregated result from tool firewall checks."""

    is_safe: bool
    results: list = field(default_factory=list)
    blocked_by: Optional[str] = None
    blocked_reason: Optional[str] = None
    redacted_output: Optional[str] = None
    tool_name: Optional[str] = None

    def __repr__(self):
        status = "SAFE" if self.is_safe else f"BLOCKED by {self.blocked_by}"
        redacted = " (output redacted)" if self.redacted_output else ""
        return f"ToolCallValidationResult({status}, tool={self.tool_name}, checks={len(self.results)}{redacted})"
