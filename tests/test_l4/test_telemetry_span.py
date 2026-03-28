"""Tests for TelemetrySpan — the L4b isolation boundary (CPF §11.2)."""

import hashlib
from datetime import datetime, timezone

from agentguard.l4.models.telemetry_span import TelemetrySpan


class TestTelemetrySpan:
    def test_fields_present(self):
        span = TelemetrySpan(
            session_id="sess-1",
            role="analyst",
            tool_name="file_read",
            args_hash=hashlib.sha256(b"test").hexdigest(),
            resource_sensitivity=2,
            data_volume_kb=1.5,
            timestamp=datetime.now(tz=timezone.utc),
        )
        assert span.session_id == "sess-1"
        assert span.role == "analyst"
        assert span.tool_name == "file_read"
        assert len(span.args_hash) == 64  # SHA256 hex
        assert span.resource_sensitivity == 2
        assert span.data_volume_kb == 1.5
        assert isinstance(span.timestamp, datetime)

    def test_no_raw_args_field(self):
        """TelemetrySpan must NEVER contain raw tool arguments (CPF §11.2)."""
        span = TelemetrySpan(
            session_id="s",
            role="r",
            tool_name="t",
            args_hash="abc123",
            resource_sensitivity=0,
            data_volume_kb=0.0,
            timestamp=datetime.now(tz=timezone.utc),
        )
        assert not hasattr(span, "raw_args")
        assert not hasattr(span, "llm_context")
        assert not hasattr(span, "messages")

    def test_args_hash_is_string(self):
        h = hashlib.sha256(b'{"path": "/etc/passwd"}').hexdigest()
        span = TelemetrySpan(
            session_id="s",
            role="r",
            tool_name="file_read",
            args_hash=h,
            resource_sensitivity=3,
            data_volume_kb=0.0,
            timestamp=datetime.now(tz=timezone.utc),
        )
        assert isinstance(span.args_hash, str)
        assert span.args_hash == h
