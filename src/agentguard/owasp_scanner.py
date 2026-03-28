"""Backward-compat re-export: use agentguard.testing.owasp_scanner instead."""

from agentguard.testing.owasp_scanner import *  # noqa: F401, F403
from agentguard.testing.owasp_scanner import (  # noqa: F401 — explicit for patching
    OWASPScanResult,
    _build_callback,
    _check_openai_key,
    _overall_badge,
    _pass_rate_bar,
    _print_framework_results,
    _print_header,
    _severity_label,
    scan_agent,
)
