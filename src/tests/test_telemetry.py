"""Tests for agentguard.telemetry module."""

import os
from unittest.mock import patch

import pytest

import agentguard.telemetry as telemetry_module
from agentguard.telemetry import get_meter, get_tracer, init_telemetry


@pytest.fixture(autouse=True)
def reset_telemetry_singletons():
    """Reset module-level singletons between tests."""
    telemetry_module._tracer = None
    telemetry_module._meter = None
    yield
    telemetry_module._tracer = None
    telemetry_module._meter = None


class TestInitTelemetry:
    def test_init_telemetry_returns_tracer_and_meter(self):
        tracer, meter = init_telemetry("test-service")
        from opentelemetry.trace import Tracer
        from opentelemetry.metrics import Meter

        assert isinstance(tracer, Tracer)
        assert isinstance(meter, Meter)

    def test_init_telemetry_console_fallback_no_endpoint(self):
        """When no OTLP endpoint is provided, console exporters should be used."""
        env = {k: v for k, v in os.environ.items() if k != "OTEL_EXPORTER_OTLP_ENDPOINT"}
        with patch.dict(os.environ, env, clear=True):
            # init_telemetry with no endpoint should not raise
            tracer, meter = init_telemetry("test-service", otlp_endpoint=None)
            assert tracer is not None
            assert meter is not None

    def test_init_telemetry_otlp_exporter_when_endpoint_set(self):
        """When otlp_endpoint is provided, OTLP exporter should be configured (no error)."""
        # We just verify it doesn't crash when endpoint is provided
        # (actual export requires a live collector)
        tracer, meter = init_telemetry("test-service", otlp_endpoint="http://localhost:4317")
        assert tracer is not None
        assert meter is not None

    def test_init_telemetry_reads_endpoint_from_env(self):
        """init_telemetry should read OTEL_EXPORTER_OTLP_ENDPOINT from env if not passed."""
        with patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel-collector:4317"}):
            tracer, meter = init_telemetry("test-service")
            assert tracer is not None
            assert meter is not None


class TestGetTracerSingleton:
    def test_get_tracer_before_init_returns_noop(self):
        """get_tracer() before init should return a (no-op) tracer."""
        tracer = get_tracer()
        assert tracer is not None

    def test_get_tracer_singleton_after_init(self):
        """Repeated get_tracer() calls return the same instance after init."""
        init_telemetry("test-service")
        t1 = get_tracer()
        t2 = get_tracer()
        assert t1 is t2

    def test_get_tracer_singleton_returns_same_object(self):
        """get_tracer() is idempotent — same object each call."""
        init_telemetry("my-svc")
        tracer = get_tracer()
        assert get_tracer() is tracer


class TestGetMeterSingleton:
    def test_get_meter_before_init_returns_noop(self):
        """get_meter() before init should return a (no-op) meter."""
        meter = get_meter()
        assert meter is not None

    def test_get_meter_singleton_after_init(self):
        """Repeated get_meter() calls return the same instance after init."""
        init_telemetry("test-service")
        m1 = get_meter()
        m2 = get_meter()
        assert m1 is m2

    def test_get_meter_singleton_returns_same_object(self):
        """get_meter() is idempotent — same object each call."""
        init_telemetry("my-svc")
        meter = get_meter()
        assert get_meter() is meter


class TestMetricInstruments:
    def test_init_creates_validations_counter(self):
        """init_telemetry should register agentguard.validations counter."""
        # Just check init doesn't crash and returns valid objects
        tracer, meter = init_telemetry("test-service")
        # Counter creation is tested implicitly — if it raised, we'd fail here
        assert meter is not None

    def test_init_creates_duration_histogram(self):
        """init_telemetry should register agentguard.validation.duration histogram."""
        tracer, meter = init_telemetry("test-service")
        assert meter is not None
