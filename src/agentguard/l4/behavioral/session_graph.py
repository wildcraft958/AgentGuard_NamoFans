"""
SessionGraphScorer — graph-based session anomaly detection.

Models each session as a directed graph of tool call transitions.
Scores anomalies at node, edge, and path (IOA) levels.

References:
  - SentinelAgent (He et al. 2025) — graph-based anomaly detection in MAS
  - CrowdStrike IOA paradigm — behavioral intent vs signature detection
"""

from __future__ import annotations

from collections import defaultdict

import networkx as nx
import numpy as np


class SessionGraphScorer:
    """
    Builds a live DAG for the current session.

    Node  = tool_name:args_hash[:8]
    Edge  = transition (call_i -> call_{i+1})
    Score = 0.2*node + 0.3*edge + 0.5*path
    """

    def __init__(self, ioa_patterns: list[dict]):
        self.ioa_patterns = ioa_patterns
        self.session_graph: nx.DiGraph = nx.DiGraph()
        self.call_history: list[str] = []
        self._tool_history: list[str] = []  # tool names only (for IOA matching)
        self._edge_freq: dict[tuple[str, str], int] = defaultdict(int)

    def add_call(self, tool_name: str, args_hash: str) -> float:
        """Add a tool call to the session graph and return anomaly score."""
        node_id = f"{tool_name}:{args_hash[:8]}"
        self.session_graph.add_node(node_id, tool=tool_name)

        edge_score = 0.0
        if self.call_history:
            prev = self.call_history[-1]
            self.session_graph.add_edge(prev, node_id)
            prev_tool = prev.split(":")[0]
            edge_score = self._score_edge(prev_tool, tool_name)

        self.call_history.append(node_id)
        self._tool_history.append(tool_name)

        node_score = self._score_node(tool_name)
        path_score = self._score_ioa_path()

        return 0.2 * node_score + 0.3 * edge_score + 0.5 * path_score

    def _score_node(self, tool_name: str) -> float:
        """Rarity-based node score. Rare tools score higher."""
        count = sum(1 for n, d in self.session_graph.nodes(data=True) if d.get("tool") == tool_name)
        return 1.0 / (1 + count)

    def _score_edge(self, prev_tool: str, curr_tool: str) -> float:
        """Frequency-based edge score. Unseen transitions score highest."""
        key = (prev_tool, curr_tool)
        self._edge_freq[key] += 1
        count = self._edge_freq[key]
        if count <= 1:
            return 1.0
        return 1.0 / (1 + float(np.log1p(count)))

    def _score_ioa_path(self) -> float:
        """Check recent tool history suffix against IOA patterns."""
        recent = self._tool_history[-5:]
        for pattern in self.ioa_patterns:
            seq = pattern["sequence"]
            if len(recent) >= len(seq):
                if recent[-len(seq) :] == seq:
                    return pattern["risk_delta"]
        return 0.0

    def reset(self) -> None:
        """Clear session state for new session."""
        self.session_graph = nx.DiGraph()
        self.call_history = []
        self._tool_history = []
        self._edge_freq = defaultdict(int)
