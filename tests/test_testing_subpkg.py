"""Tests for agentguard.testing subpackage — owasp_scanner + promptfoo_bridge.

TDD: written BEFORE moving owasp_scanner.py and promptfoo_bridge.py into testing/.
Verifies new import paths work and backward-compat re-exports are preserved.
"""


def test_scan_agent_importable_from_testing():
    from agentguard.testing.owasp_scanner import scan_agent

    assert callable(scan_agent)


def test_owasp_scan_result_importable_from_testing():
    from agentguard.testing.owasp_scanner import OWASPScanResult

    assert OWASPScanResult is not None


def test_promptfoo_call_api_importable_from_testing():
    from agentguard.testing.promptfoo_bridge import call_api

    assert callable(call_api)


def test_backward_compat_owasp_scanner_import():
    from agentguard.owasp_scanner import scan_agent as old_scan
    from agentguard.testing.owasp_scanner import scan_agent as new_scan

    assert old_scan is new_scan


def test_backward_compat_promptfoo_bridge_import():
    from agentguard.promptfoo_bridge import call_api as old_call
    from agentguard.testing.promptfoo_bridge import call_api as new_call

    assert old_call is new_call


def test_top_level_scan_agent_still_importable():
    """The top-level agentguard.scan_agent must still work."""
    from agentguard import scan_agent

    assert callable(scan_agent)


def test_top_level_owasp_scan_result_still_importable():
    from agentguard import OWASPScanResult

    assert OWASPScanResult is not None
