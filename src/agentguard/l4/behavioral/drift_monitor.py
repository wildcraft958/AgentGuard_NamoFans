"""
ComplianceDriftMonitor — detects autoregressive sensitivity escalation (CPF §7).

Tracks a sliding window of effective sensitivity values per session.
A monotonically increasing trend indicates the agent is progressively
accessing more sensitive resources — a hallmark of slow-burn attacks.
"""

from __future__ import annotations

from collections import deque

import numpy as np


class ComplianceDriftMonitor:
    """
    Sliding-window Pearson correlation of sensitivity vs time index.

    Returns max(0.0, correlation) as drift score ∈ [0, 1].
    """

    TOOL_SENSITIVITY_MAP: dict[str, int] = {
        "http_get": 0,
        "sql_query": 1,
        "file_read": 1,
        "http_post": 2,
        "file_write": 2,
        "shell_exec": 3,
        "file_delete": 3,
        "admin_call": 3,
    }

    def __init__(self, window_size: int = 8):
        self._window: deque[int] = deque(maxlen=window_size)

    def record(self, tool_name: str, resource_sensitivity: int) -> float:
        """Record a tool call and return the current drift score."""
        base = self.TOOL_SENSITIVITY_MAP.get(tool_name, 1)
        effective = max(base, resource_sensitivity)
        self._window.append(effective)
        return self._drift_score()

    def _drift_score(self) -> float:
        if len(self._window) < 3:
            return 0.0
        arr = np.array(self._window, dtype=np.float64)
        # If all values are identical, std=0 -> correlation is undefined -> 0
        if np.std(arr) == 0:
            return 0.0
        time_idx = np.arange(len(arr), dtype=np.float64)
        corr = np.corrcoef(time_idx, arr)[0, 1]
        if np.isnan(corr):
            return 0.0
        return max(0.0, float(corr))
