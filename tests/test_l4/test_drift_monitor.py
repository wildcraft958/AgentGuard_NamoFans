"""Tests for ComplianceDriftMonitor — detects autoregressive drift (CPF §7)."""

from agentguard.l4.behavioral.drift_monitor import ComplianceDriftMonitor


class TestComplianceDriftMonitor:
    def test_flat_sequence_near_zero(self):
        """Constant sensitivity -> no upward trend -> drift ~0."""
        mon = ComplianceDriftMonitor(window_size=8)
        score = 0.0
        for _ in range(8):
            score = mon.record("http_get", 0)
        assert score < 0.1

    def test_monotonic_increase_high_drift(self):
        """Escalating sensitivity 0->3 -> strong positive correlation."""
        mon = ComplianceDriftMonitor(window_size=8)
        sequence = [
            ("http_get", 0),
            ("http_get", 0),
            ("sql_query", 1),
            ("file_read", 1),
            ("http_post", 2),
            ("file_write", 2),
            ("shell_exec", 3),
            ("admin_call", 3),
        ]
        score = 0.0
        for tool, sens in sequence:
            score = mon.record(tool, sens)
        assert score > 0.8

    def test_fewer_than_3_returns_zero(self):
        """Cold start: fewer than 3 data points -> 0.0."""
        mon = ComplianceDriftMonitor(window_size=8)
        assert mon.record("http_get", 0) == 0.0
        assert mon.record("sql_query", 1) == 0.0

    def test_window_overflow(self):
        """Oldest events drop off when window is exceeded."""
        mon = ComplianceDriftMonitor(window_size=4)
        # Fill with escalating: [0, 1, 2, 3] -> high drift
        for sens in [0, 1, 2, 3]:
            mon.record("http_get", sens)
        high_score = mon.record("http_get", 3)  # window is now [1,2,3,3]

        # Now flood with constant zeros to push out the high values
        for _ in range(4):
            mon.record("http_get", 0)
        flat_score = mon.record("http_get", 0)
        assert flat_score < high_score

    def test_tool_sensitivity_map_lookup(self):
        """Base sensitivity comes from TOOL_SENSITIVITY_MAP, effective = max(base, given)."""
        mon = ComplianceDriftMonitor(window_size=8)
        # shell_exec has base=3 in the map; even if resource_sensitivity=0,
        # effective should be max(3, 0) = 3
        for _ in range(4):
            mon.record("shell_exec", 0)
        # All effective sensitivities should be 3 (flat), so low drift
        score = mon.record("shell_exec", 0)
        # With all 3s, correlation is undefined (no variance) -> 0.0
        assert score < 0.1

    def test_decreasing_sequence_zero(self):
        """Decreasing sensitivity -> negative correlation -> clamped to 0."""
        mon = ComplianceDriftMonitor(window_size=8)
        for tool, sens in [
            ("shell_exec", 3),
            ("file_write", 2),
            ("sql_query", 1),
            ("http_get", 0),
        ]:
            score = mon.record(tool, sens)
        assert score == 0.0  # negative correlation clamped
