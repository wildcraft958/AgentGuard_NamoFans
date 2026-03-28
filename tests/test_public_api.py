"""Comprehensive public API verification test.

Ensures that all exports from agentguard are the correct types and that
the new subpackage layout matches the target structure.
"""

import pathlib
import types


def test_top_level_exports():
    """Every name in agentguard.__all__ must be the expected type."""
    import agentguard

    expected = {
        "Guardian": type,
        "AgentGuardError": type,
        "InputBlockedError": type,
        "OutputBlockedError": type,
        "ToolCallBlockedError": type,
        "SandboxTimeoutError": type,
        "SandboxViolationError": type,
        "ConfigurationError": type,
        "guard": types.FunctionType,
        "guard_agent": types.FunctionType,
        "guard_input": types.FunctionType,
        "guard_tool": types.FunctionType,
        "get_registered_agent": types.FunctionType,
        "GuardedToolRegistry": type,
        "scan_agent": types.FunctionType,
        "OWASPScanResult": type,
        "AuditLog": type,
    }

    for name, expected_type in expected.items():
        obj = getattr(agentguard, name, None)
        assert obj is not None, f"agentguard.{name} is missing"
        assert isinstance(obj, expected_type), (
            f"agentguard.{name} is {type(obj).__name__}, expected {expected_type.__name__}"
        )


def test_subpackage_structure():
    """Verify the new subpackage layout matches the target."""
    import agentguard

    pkg_root = pathlib.Path(agentguard.__file__).parent

    expected_dirs = [
        "l1_input",
        "l2_output",
        "l4",
        "tool_firewall",
        "sandbox",
        "observability",
        "testing",
        "dashboard",
        "_pipeline",
    ]
    for d in expected_dirs:
        assert (pkg_root / d).is_dir(), f"Subpackage {d}/ missing"
        assert (pkg_root / d / "__init__.py").exists(), f"{d}/__init__.py missing"


def test_subpackage_imports():
    """Verify key imports from each subpackage work."""
    from agentguard.l1_input import PromptShields, ContentFilters  # noqa: F401
    from agentguard.l2_output import OutputToxicity, PIIDetector  # noqa: F401
    from agentguard.l4 import L4RBACEngine, BehavioralAnomalyDetector  # noqa: F401
    from agentguard.l4.rbac import AccessContext, RBACDecision  # noqa: F401
    from agentguard.l4.behavioral import AnomalyResult, AnomalySignal, TaskProfile  # noqa: F401
    from agentguard.observability import AuditLog, init_telemetry  # noqa: F401
    from agentguard.testing import scan_agent, OWASPScanResult  # noqa: F401
    from agentguard.sandbox import SandboxedToolExecutor, SandboxPolicy  # noqa: F401
    from agentguard.tool_firewall import ToolSpecificGuards, ToolInputAnalyzer  # noqa: F401
    from agentguard._pipeline.notifier import Notifier  # noqa: F401
    from agentguard._pipeline.handlers import handle_input_block  # noqa: F401
    from agentguard._pipeline.wave_runner import wave_parallel  # noqa: F401


def test_backward_compat_all_old_paths():
    """All original flat-file import paths must still work via re-export shims."""
    from agentguard.audit_log import AuditLog  # noqa: F401
    from agentguard.telemetry import init_telemetry  # noqa: F401
    from agentguard.l4_rbac import L4RBACEngine  # noqa: F401
    from agentguard.l4_behavioral import BehavioralAnomalyDetector  # noqa: F401
    from agentguard.owasp_scanner import scan_agent  # noqa: F401
    from agentguard.promptfoo_bridge import call_api  # noqa: F401

    # Verify they are the same objects as the new paths
    from agentguard.observability.audit import AuditLog as NewAuditLog
    from agentguard.l4.rbac import L4RBACEngine as NewEngine

    assert AuditLog is NewAuditLog
    assert L4RBACEngine is NewEngine


def test_py_typed_exists():
    import agentguard

    pkg_dir = pathlib.Path(agentguard.__file__).parent
    assert (pkg_dir / "py.typed").exists()


def test_exceptions_hierarchy():
    """All custom exceptions must inherit from AgentGuardError."""
    from agentguard import (
        AgentGuardError,
        InputBlockedError,
        OutputBlockedError,
        ToolCallBlockedError,
        SandboxTimeoutError,
        SandboxViolationError,
        ConfigurationError,
    )

    for exc_cls in [
        InputBlockedError,
        OutputBlockedError,
        ToolCallBlockedError,
        SandboxTimeoutError,
        SandboxViolationError,
        ConfigurationError,
    ]:
        assert issubclass(exc_cls, AgentGuardError), f"{exc_cls.__name__} not subclass of AgentGuardError"
