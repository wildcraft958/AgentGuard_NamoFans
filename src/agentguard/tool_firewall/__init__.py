"""AgentGuard – Tool Firewall package.

Components:
  C1: ToolInputAnalyzer  — Azure entity recognition on tool arguments
  C2: MelonDetector       — Contrastive indirect prompt injection detection on tool output
  C3: ToolSpecificGuards  — Rule-based HTTP/SQL/filesystem guards
"""

from agentguard.tool_firewall.tool_specific_guards import ToolSpecificGuards
from agentguard.tool_firewall.tool_input_analyzer import ToolInputAnalyzer
from agentguard.tool_firewall.melon_detector import MelonDetector

__all__ = [
    "ToolSpecificGuards",
    "ToolInputAnalyzer",
    "MelonDetector",
]
