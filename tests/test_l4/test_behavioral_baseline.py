"""Tests for AdaptiveBehavioralBaseline — River HalfSpaceTrees online anomaly detector."""

from datetime import datetime, timezone

from agentguard.l4.behavioral.baseline import AdaptiveBehavioralBaseline

# Fast parameters for tests (production uses n_trees=25, height=8)
FAST = {"n_trees": 3, "height": 4, "window_size": 20}


def _make_call(tool_name="file_read", data_volume_kb=1.0, hour=10):
    return {
        "tool_name": tool_name,
        "args": {"path": "/tmp/data.txt"},
        "data_volume_kb": data_volume_kb,
        "timestamp": datetime(2026, 3, 1, hour, 0, tzinfo=timezone.utc),
    }


class TestAdaptiveBehavioralBaseline:
    def test_cold_start_uses_global_model(self):
        """Calls during cold start should use the _global model."""
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=5, **FAST)
        for i in range(4):
            baseline.score("analyst", _make_call())
        assert baseline._call_counts["analyst"] == 4
        assert baseline._call_counts["_global"] == 4

    def test_post_cold_start_uses_role_model(self):
        """After cold_start calls, per-role model is used."""
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=5, **FAST)
        for i in range(6):
            baseline.score("analyst", _make_call())
        assert baseline._call_counts["analyst"] == 6
        assert baseline._call_counts["_global"] == 5

    def test_featurize_keys(self):
        """Featurize returns dict with correct keys."""
        baseline = AdaptiveBehavioralBaseline(**FAST)
        features = baseline.featurize(_make_call())
        assert "tool_id" in features
        assert "arg_len" in features
        assert "arg_entropy" in features
        assert "data_volume_kb" in features
        assert "hour_of_day" in features

    def test_featurize_tool_id_deterministic(self):
        """Same tool name -> same tool_id."""
        baseline = AdaptiveBehavioralBaseline(**FAST)
        f1 = baseline.featurize(_make_call("file_read"))
        f2 = baseline.featurize(_make_call("file_read"))
        assert f1["tool_id"] == f2["tool_id"]

    def test_featurize_different_tools_different_ids(self):
        baseline = AdaptiveBehavioralBaseline(**FAST)
        f1 = baseline.featurize(_make_call("file_read"))
        f2 = baseline.featurize(_make_call("http_post"))
        assert f1["tool_id"] != f2["tool_id"]

    def test_score_returns_float(self):
        baseline = AdaptiveBehavioralBaseline(cold_start_threshold=5, **FAST)
        score = baseline.score("test_role", _make_call())
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_shannon_entropy_empty(self):
        """Empty string should have 0 entropy."""
        assert AdaptiveBehavioralBaseline._shannon_entropy("") == 0.0

    def test_shannon_entropy_uniform(self):
        """String with all unique chars has higher entropy than repeated."""
        uniform = AdaptiveBehavioralBaseline._shannon_entropy("abcdefgh")
        repeated = AdaptiveBehavioralBaseline._shannon_entropy("aaaaaaaa")
        assert uniform > repeated
        assert repeated == 0.0
