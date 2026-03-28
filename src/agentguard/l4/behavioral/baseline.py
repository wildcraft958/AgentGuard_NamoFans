"""
AdaptiveBehavioralBaseline — per-role online anomaly detection using River HalfSpaceTrees.

Solves the cold-start problem by delegating to a shared "_global" model
until a role accumulates enough calls for its own model to be reliable.

Reference: Tan et al. 2011 — Half-Space Trees for streaming anomaly detection.
"""

from __future__ import annotations

import hashlib
import json
import math
import pickle
from collections import Counter, defaultdict
from pathlib import Path

from river import anomaly, compose, preprocessing


class AdaptiveBehavioralBaseline:
    """
    Per-role online anomaly detector.

    Features: tool_id (hash), arg_len, arg_entropy (Shannon),
              data_volume_kb, hour_of_day.
    """

    def __init__(
        self,
        cold_start_threshold: int = 50,
        n_trees: int = 25,
        height: int = 8,
        window_size: int = 250,
    ):
        self._cold_start = cold_start_threshold
        self._n_trees = n_trees
        self._height = height
        self._window_size = window_size
        self._role_models: dict[str, compose.Pipeline] = {}
        self._call_counts: dict[str, int] = defaultdict(int)

    def _make_pipeline(self) -> compose.Pipeline:
        return compose.Pipeline(
            preprocessing.MinMaxScaler(),
            anomaly.HalfSpaceTrees(
                n_trees=self._n_trees,
                height=self._height,
                window_size=self._window_size,
                seed=42,
            ),
        )

    def _get_model(self, role: str) -> compose.Pipeline:
        if role not in self._role_models:
            self._role_models[role] = self._make_pipeline()
        return self._role_models[role]

    def featurize(self, tool_call: dict) -> dict:
        """Extract feature vector from a tool call dict."""
        tool_name = tool_call.get("tool_name", "")
        args = tool_call.get("args", {})
        args_str = json.dumps(args, sort_keys=True)
        timestamp = tool_call.get("timestamp")

        hour = 0
        if timestamp is not None:
            hour = timestamp.hour if hasattr(timestamp, "hour") else 0

        return {
            "tool_id": int(hashlib.md5(tool_name.encode()).hexdigest(), 16) % 1000,
            "arg_len": len(args_str),
            "arg_entropy": self._shannon_entropy(args_str),
            "data_volume_kb": tool_call.get("data_volume_kb", 0),
            "hour_of_day": hour,
        }

    def score(self, role: str, tool_call: dict) -> float:
        """Score a tool call for anomaly. Returns float in [0, 1]."""
        features = self.featurize(tool_call)

        in_cold_start = self._call_counts[role] < self._cold_start

        if in_cold_start:
            # Use global model during cold start
            global_model = self._get_model("_global")
            score_val = global_model.score_one(features)
            global_model.learn_one(features)
            self._call_counts["_global"] += 1

            # Also train the role model in parallel
            role_model = self._get_model(role)
            role_model.learn_one(features)
        else:
            # Use per-role model after cold start
            role_model = self._get_model(role)
            score_val = role_model.score_one(features)
            role_model.learn_one(features)

        self._call_counts[role] += 1
        return min(1.0, max(0.0, float(score_val)))

    def persist(self, path: str) -> None:
        """Save models to disk for warm restart."""
        data = {
            "role_models": self._role_models,
            "call_counts": dict(self._call_counts),
        }
        Path(path).write_bytes(pickle.dumps(data))

    def load(self, path: str) -> None:
        """Load models from disk."""
        data = pickle.loads(Path(path).read_bytes())  # noqa: S301
        self._role_models = data["role_models"]
        self._call_counts = defaultdict(int, data["call_counts"])

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """H(X) = -Σ p(x) log₂(p(x))."""
        if not s:
            return 0.0
        counts = Counter(s)
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())
