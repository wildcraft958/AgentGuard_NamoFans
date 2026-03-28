"""
AgentGuard – Testing & red-team utilities (agentguard.testing).

Submodules:
  - owasp_scanner:    DeepTeam-powered OWASP Top 10 vulnerability scanner
  - promptfoo_bridge: Promptfoo Python provider bridge for red-team harness
"""

from agentguard.testing.owasp_scanner import OWASPScanResult, scan_agent

__all__ = [
    "OWASPScanResult",
    "scan_agent",
]
