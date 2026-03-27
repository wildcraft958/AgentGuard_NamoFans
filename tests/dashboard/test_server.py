"""
Unit tests for agentguard.dashboard.server.

Tests mock both httpx (Jaeger REST API) and AuditLog to keep tests
fully offline and deterministic.
"""

import time
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Fake Jaeger response helpers
# ---------------------------------------------------------------------------

FAKE_JAEGER_TRACE = {
    "traceID": "abc123def456",
    "spans": [
        {
            "traceID": "abc123def456",
            "spanID": "span001",
            "operationName": "agentguard.validate_input",
            "startTime": 1700000000000000,  # microseconds
            "duration": 42000,  # microseconds
            "tags": [
                {"key": "agentguard.is_safe", "value": "true", "type": "string"},
                {"key": "agentguard.layer", "value": "l1_input", "type": "string"},
            ],
            "logs": [],
            "references": [],
            "processID": "p1",
        }
    ],
    "processes": {"p1": {"serviceName": "agentguard", "tags": []}},
}

FAKE_BLOCKED_TRACE = {
    "traceID": "deadbeef1234",
    "spans": [
        {
            "traceID": "deadbeef1234",
            "spanID": "span002",
            "operationName": "agentguard.validate_tool_call",
            "startTime": 1700000010000000,
            "duration": 88000,
            "tags": [
                {"key": "agentguard.is_safe", "value": "false", "type": "string"},
                {"key": "agentguard.blocked_by", "value": "RuleEvaluator", "type": "string"},
            ],
            "logs": [],
            "references": [],
            "processID": "p1",
        }
    ],
    "processes": {"p1": {"serviceName": "agentguard", "tags": []}},
}


def make_jaeger_response(traces: list[dict]) -> MagicMock:
    """Build a mock httpx response that returns the given traces."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = {"data": traces, "total": len(traces), "errors": None}
    return mock_resp


# ---------------------------------------------------------------------------
# Tests: transform_span
# ---------------------------------------------------------------------------


def test_transform_span_safe():
    from agentguard.dashboard.server import transform_span

    raw = FAKE_JAEGER_TRACE["spans"][0]
    result = transform_span(raw)

    assert result["span_id"] == "span001"
    assert result["operation_name"] == "agentguard.validate_input"
    assert result["status"] == "safe"
    assert result["layer"] == "l1_input"
    assert result["blocked_by"] is None
    assert result["duration_ms"] == 42  # 42000 µs → 42 ms


def test_transform_span_blocked():
    from agentguard.dashboard.server import transform_span

    raw = FAKE_BLOCKED_TRACE["spans"][0]
    result = transform_span(raw)

    assert result["span_id"] == "span002"
    assert result["status"] == "blocked"
    assert result["layer"] == "tool_firewall"
    assert result["blocked_by"] == "RuleEvaluator"


def test_transform_span_layer_detection_output():
    from agentguard.dashboard.server import transform_span

    raw = {
        "traceID": "t1",
        "spanID": "s1",
        "operationName": "agentguard.validate_output",
        "startTime": 1700000000000000,
        "duration": 5000,
        "tags": [],
    }
    result = transform_span(raw)
    assert result["layer"] == "l2_output"


# ---------------------------------------------------------------------------
# Tests: /api/spans endpoint
# ---------------------------------------------------------------------------


def test_spans_endpoint_returns_normalized_spans():
    from agentguard.dashboard.server import app

    with patch("agentguard.dashboard.server.httpx.get") as mock_get:
        mock_get.return_value = make_jaeger_response([FAKE_JAEGER_TRACE])

        client = TestClient(app)
        resp = client.get("/api/spans?limit=10")

    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 1
    span = data[0]
    assert span["operation_name"] == "agentguard.validate_input"
    assert span["status"] == "safe"


def test_spans_endpoint_jaeger_error_returns_empty():
    from agentguard.dashboard.server import app

    with patch("agentguard.dashboard.server.httpx.get") as mock_get:
        mock_get.side_effect = Exception("Jaeger unavailable")

        client = TestClient(app)
        resp = client.get("/api/spans")

    assert resp.status_code == 200
    assert resp.json() == []


# ---------------------------------------------------------------------------
# Tests: /api/stats endpoint
# ---------------------------------------------------------------------------


def test_stats_endpoint_shape():
    from agentguard.dashboard.server import app

    mock_audit = MagicMock()
    mock_audit.blocked_count.return_value = 3
    mock_audit.pass_rate.return_value = 0.85

    with (
        patch("agentguard.dashboard.server.httpx.get") as mock_get,
        patch("agentguard.dashboard.server._get_audit_log", return_value=mock_audit),
    ):
        mock_get.return_value = make_jaeger_response(
            [FAKE_JAEGER_TRACE, FAKE_BLOCKED_TRACE]
        )

        client = TestClient(app)
        resp = client.get("/api/stats")

    assert resp.status_code == 200
    stats = resp.json()

    assert "total_spans" in stats
    assert "blocked_spans" in stats
    assert "pass_rate_24h" in stats
    assert "avg_duration_ms" in stats
    assert "layer_breakdown" in stats

    lb = stats["layer_breakdown"]
    assert "l1_input" in lb
    assert "l2_output" in lb
    assert "tool_firewall" in lb


def test_stats_endpoint_counts_correctly():
    from agentguard.dashboard.server import app

    mock_audit = MagicMock()
    mock_audit.blocked_count.return_value = 1
    mock_audit.pass_rate.return_value = 0.5

    with (
        patch("agentguard.dashboard.server.httpx.get") as mock_get,
        patch("agentguard.dashboard.server._get_audit_log", return_value=mock_audit),
    ):
        # one safe (l1_input) + one blocked (tool_firewall)
        mock_get.return_value = make_jaeger_response(
            [FAKE_JAEGER_TRACE, FAKE_BLOCKED_TRACE]
        )

        client = TestClient(app)
        resp = client.get("/api/stats")

    stats = resp.json()
    assert stats["total_spans"] == 2
    assert stats["blocked_spans"] == 1

    lb = stats["layer_breakdown"]
    assert lb["l1_input"]["pass"] == 1
    assert lb["l1_input"]["block"] == 0
    assert lb["tool_firewall"]["block"] == 1


# ---------------------------------------------------------------------------
# Tests: /api/audit endpoint
# ---------------------------------------------------------------------------


def test_audit_endpoint_returns_recent_records():
    from agentguard.dashboard.server import app

    fake_records = [
        {
            "id": 1,
            "ts": "2024-01-01T00:00:00+00:00",
            "action": "validate_input",
            "layer": "l1_input",
            "safe": 1,
            "reason": None,
            "metadata": None,
        }
    ]
    mock_audit = MagicMock()
    mock_audit.recent.return_value = fake_records

    with patch("agentguard.dashboard.server._get_audit_log", return_value=mock_audit):
        client = TestClient(app)
        resp = client.get("/api/audit?limit=10")

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["action"] == "validate_input"
    mock_audit.recent.assert_called_once_with(10)


def test_audit_endpoint_default_limit():
    from agentguard.dashboard.server import app

    mock_audit = MagicMock()
    mock_audit.recent.return_value = []

    with patch("agentguard.dashboard.server._get_audit_log", return_value=mock_audit):
        client = TestClient(app)
        client.get("/api/audit")

    mock_audit.recent.assert_called_once_with(50)


# ---------------------------------------------------------------------------
# Tests: pass_rate_24h computed from Jaeger spans (not audit log)
# ---------------------------------------------------------------------------


def _make_span_raw(span_id, operation, is_safe, start_ms_ago=60_000, layer_tag=None):
    """Build a fake Jaeger raw span with a recent timestamp."""
    now_us = int(time.time() * 1_000_000)
    tags = [{"key": "agentguard.is_safe", "value": str(is_safe).lower(), "type": "string"}]
    if layer_tag:
        tags.append({"key": "agentguard.layer", "value": layer_tag, "type": "string"})
    return {
        "traceID": "t1",
        "spanID": span_id,
        "operationName": operation,
        "startTime": now_us - start_ms_ago * 1000,
        "duration": 50000,
        "tags": tags,
        "logs": [],
        "references": [],
        "processID": "p1",
    }


def _make_trace(spans):
    return {
        "traceID": "t1",
        "spans": spans,
        "processes": {"p1": {"serviceName": "agentguard", "tags": []}},
    }


def test_pass_rate_24h_uses_span_timestamps():
    """pass_rate_24h should equal (safe spans / total spans) within the last 24h."""
    from agentguard.dashboard.server import app

    recent_spans = [
        _make_span_raw("s1", "agentguard.validate_input", True, start_ms_ago=60_000, layer_tag="l1_input"),
        _make_span_raw("s2", "agentguard.validate_input", True, start_ms_ago=60_000, layer_tag="l1_input"),
        _make_span_raw("s3", "agentguard.validate_input", False, start_ms_ago=60_000, layer_tag="l1_input"),
        _make_span_raw("s4", "agentguard.validate_input", True, start_ms_ago=60_000, layer_tag="l1_input"),
    ]
    trace = _make_trace(recent_spans)

    mock_audit = MagicMock()
    mock_audit.blocked_count.return_value = 0

    with (
        patch("agentguard.dashboard.server.httpx.get") as mock_get,
        patch("agentguard.dashboard.server._get_audit_log", return_value=mock_audit),
    ):
        mock_get.return_value = make_jaeger_response([trace])
        client = TestClient(app)
        resp = client.get("/api/stats")

    stats = resp.json()
    # 3 safe out of 4 total → 0.75
    assert stats["pass_rate_24h"] == 0.75


def test_pass_rate_24h_excludes_old_spans():
    """Spans older than 24h should not count toward pass_rate_24h."""
    from agentguard.dashboard.server import app

    # old span (25 hours ago) that is blocked — must NOT affect rate
    old_ms_ago = 25 * 3600 * 1000
    recent_safe = _make_span_raw("s1", "agentguard.validate_input", True, start_ms_ago=60_000, layer_tag="l1_input")
    old_blocked = _make_span_raw("s2", "agentguard.validate_input", False, start_ms_ago=old_ms_ago, layer_tag="l1_input")
    trace = _make_trace([recent_safe, old_blocked])

    mock_audit = MagicMock()
    mock_audit.blocked_count.return_value = 0

    with (
        patch("agentguard.dashboard.server.httpx.get") as mock_get,
        patch("agentguard.dashboard.server._get_audit_log", return_value=mock_audit),
    ):
        mock_get.return_value = make_jaeger_response([trace])
        client = TestClient(app)
        resp = client.get("/api/stats")

    stats = resp.json()
    # only the recent safe span is in the 24h window → 1.0
    assert stats["pass_rate_24h"] == 1.0


def test_pass_rate_24h_no_recent_spans_returns_1():
    """When no spans fall in the 24h window, pass_rate_24h should be 1.0."""
    from agentguard.dashboard.server import app

    mock_audit = MagicMock()
    mock_audit.blocked_count.return_value = 0

    with (
        patch("agentguard.dashboard.server.httpx.get") as mock_get,
        patch("agentguard.dashboard.server._get_audit_log", return_value=mock_audit),
    ):
        mock_get.return_value = make_jaeger_response([])
        client = TestClient(app)
        resp = client.get("/api/stats")

    stats = resp.json()
    assert stats["pass_rate_24h"] == 1.0
