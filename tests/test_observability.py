"""Tests for agentguard.observability — audit log and telemetry."""

import pytest
from opentelemetry import metrics as _otel_metrics, trace as _otel_trace

from agentguard.observability.audit import AuditLog, hash_params
from agentguard.observability.telemetry import init_telemetry, get_tracer, get_meter


# ---------------------------------------------------------------------------
# AuditLog tests
# ---------------------------------------------------------------------------


class TestAuditLog:
    def test_record_and_recent(self, tmp_path):
        log = AuditLog(":memory:")
        row_id = log.record("validate_input", "l1_input", is_safe=True)
        assert isinstance(row_id, int)
        rows = log.recent(10)
        assert len(rows) == 1
        assert rows[0]["action"] == "validate_input"
        assert rows[0]["layer"] == "l1_input"
        assert rows[0]["safe"] == 1

    def test_blocked_count(self, tmp_path):
        log = AuditLog(":memory:")
        log.record("validate_input", "l1_input", is_safe=True)
        log.record("validate_input", "l1_input", is_safe=False, reason="injection")
        log.record("validate_output", "l2_output", is_safe=False, reason="pii")
        assert log.blocked_count() == 2
        assert log.blocked_count(action="validate_input") == 1

    def test_pass_rate(self, tmp_path):
        log = AuditLog(":memory:")
        log.record("validate_input", "l1_input", is_safe=True)
        log.record("validate_input", "l1_input", is_safe=True)
        log.record("validate_input", "l1_input", is_safe=False, reason="blocked")
        rate = log.pass_rate(since_hours=24)
        assert abs(rate - 2 / 3) < 0.01

    def test_pass_rate_empty(self, tmp_path):
        log = AuditLog(":memory:")
        assert log.pass_rate() == 1.0

    def test_l4_columns_recorded(self, tmp_path):
        log = AuditLog(":memory:")
        log.record(
            "validate_tool_call",
            "l4_rbac",
            is_safe=False,
            reason="denied",
            l4_rbac_decision="deny",
            l4_signals='["frequency_spike"]',
            l4_composite=0.85,
            l4_action="BLOCK",
        )
        rows = log.recent(1)
        assert rows[0]["l4_rbac_decision"] == "deny"
        assert rows[0]["l4_composite"] == 0.85

    def test_metadata_json(self, tmp_path):
        import json

        log = AuditLog(":memory:")
        log.record("validate_input", "l1_input", is_safe=True, metadata={"key": "val"})
        rows = log.recent(1)
        meta = json.loads(rows[0]["metadata"])
        assert meta["key"] == "val"

    def test_context_manager(self, tmp_path):
        with AuditLog(":memory:") as log:
            log.record("validate_input", "l1_input", is_safe=True)
            assert len(log.recent()) == 1

    def test_hash_params(self):
        h = hash_params({"a": 1, "b": "test"})
        assert isinstance(h, str)
        assert len(h) == 16
        # Deterministic
        assert hash_params({"a": 1, "b": "test"}) == h


# ---------------------------------------------------------------------------
# Backward-compat: old import path still works
# ---------------------------------------------------------------------------


def test_backward_compat_audit_log_import():
    from agentguard.audit_log import AuditLog as OldAuditLog

    assert OldAuditLog is AuditLog


def test_backward_compat_telemetry_import():
    from agentguard.telemetry import init_telemetry as old_init

    assert old_init is init_telemetry


# ---------------------------------------------------------------------------
# Telemetry tests (no OTLP endpoint — console exporters)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True, scope="function")
def _shutdown_otel_providers():
    """Shut down OTel providers after each telemetry test to stop background threads."""
    yield
    tp = _otel_trace.get_tracer_provider()
    if hasattr(tp, "shutdown"):
        tp.shutdown()
    mp = _otel_metrics.get_meter_provider()
    if hasattr(mp, "shutdown"):
        mp.shutdown()


def test_init_telemetry_returns_tracer_and_meter():
    tracer, meter = init_telemetry(service_name="test-svc")
    assert tracer is not None
    assert meter is not None


def test_get_tracer_returns_tracer():
    t = get_tracer()
    assert t is not None


def test_get_meter_returns_meter():
    m = get_meter()
    assert m is not None
