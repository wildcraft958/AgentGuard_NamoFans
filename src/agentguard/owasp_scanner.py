"""Backward-compat re-export: use agentguard.testing.owasp_scanner instead."""

from agentguard.testing.owasp_scanner import OWASPScanResult, scan_agent

__all__ = ["OWASPScanResult", "scan_agent"]
