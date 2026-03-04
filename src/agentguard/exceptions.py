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


class ConfigurationError(AgentGuardError):
    """Raised for invalid or missing configuration."""
    pass
