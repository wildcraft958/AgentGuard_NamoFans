"""
AgentGuard custom exception hierarchy.
"""


class AgentGuardError(Exception):
    """Base exception for all AgentGuard errors."""

    pass


class InputBlockedError(AgentGuardError):
    """Raised when input is blocked in enforce mode."""

    def __init__(self, reason: str, details: dict = None):
        self.reason = reason
        self.details = details or {}
        super().__init__(f"Input blocked: {reason}")


class OutputBlockedError(AgentGuardError):
    """Raised when output is blocked in enforce mode."""

    def __init__(self, reason: str, details: dict = None):
        self.reason = reason
        self.details = details or {}
        super().__init__(f"Output blocked: {reason}")


class ToolCallBlockedError(AgentGuardError):
    """Raised when a tool call is blocked in enforce mode."""

    def __init__(self, reason: str, details: dict = None):
        self.reason = reason
        self.details = details or {}
        super().__init__(f"Tool call blocked: {reason}")


class ConfigurationError(AgentGuardError):
    """Raised for invalid or missing configuration."""

    pass


class SandboxTimeoutError(AgentGuardError):
    """Raised when a sandboxed tool call exceeds its configured timeout."""

    def __init__(self, reason: str, details: dict = None):
        self.reason = reason
        self.details = details or {}
        super().__init__(f"Sandbox timeout: {reason}")


class SandboxViolationError(AgentGuardError):
    """Raised when a sandboxed tool call violates sandbox policy or exits abnormally."""

    def __init__(self, reason: str, details: dict = None):
        self.reason = reason
        self.details = details or {}
        super().__init__(f"Sandbox violation: {reason}")
