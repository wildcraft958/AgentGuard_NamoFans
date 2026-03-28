"""
AgentGuard OTel telemetry setup (agentguard.observability.telemetry).

Call init_telemetry() once at Guardian init time when telemetry is enabled.
Use get_tracer() / get_meter() everywhere else to obtain the singletons.
"""

import os

from opentelemetry import metrics, trace
from opentelemetry.metrics import Meter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import ConsoleMetricExporter, PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Tracer

_SERVICE_NAME = "agentguard"

# Module-level singletons (None until init_telemetry() is called)
_tracer: Tracer | None = None
_meter: Meter | None = None


def init_telemetry(
    service_name: str = _SERVICE_NAME,
    otlp_endpoint: str | None = None,
) -> tuple[Tracer, Meter]:
    """
    Initialize OTel TracerProvider + MeterProvider and return singletons.

    If otlp_endpoint (or OTEL_EXPORTER_OTLP_ENDPOINT env var) is set, uses
    OTLPSpanExporter + OTLPMetricExporter. Otherwise falls back to console exporters.

    Args:
        service_name: OTel resource service.name attribute.
        otlp_endpoint: OTLP gRPC/HTTP collector endpoint. Overrides env var.

    Returns:
        (Tracer, Meter) tuple — both scoped to "agentguard" instrumentation name.
    """
    global _tracer, _meter

    endpoint = otlp_endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    resource = Resource.create({"service.name": service_name})

    # --- Tracing ---
    if endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

        span_exporter = OTLPSpanExporter(endpoint=endpoint)
    else:
        span_exporter = ConsoleSpanExporter()

    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
    trace.set_tracer_provider(tracer_provider)

    # --- Metrics ---
    if endpoint:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter

        metric_exporter = OTLPMetricExporter(endpoint=endpoint)
    else:
        metric_exporter = ConsoleMetricExporter()

    reader = PeriodicExportingMetricReader(metric_exporter)
    meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
    metrics.set_meter_provider(meter_provider)

    _tracer = trace.get_tracer("agentguard")
    _meter = metrics.get_meter("agentguard")

    # Pre-create the two standard instruments so they are registered at startup
    _meter.create_counter(
        name="agentguard.validations",
        description="Number of AgentGuard validation decisions",
        unit="1",
    )
    _meter.create_histogram(
        name="agentguard.validation.duration",
        description="Duration of AgentGuard validation checks",
        unit="ms",
    )

    return _tracer, _meter


def get_tracer() -> Tracer:
    """Return the module-level Tracer singleton (no-op if init not called)."""
    if _tracer is not None:
        return _tracer
    return trace.get_tracer("agentguard")


def get_meter() -> Meter:
    """Return the module-level Meter singleton (no-op if init not called)."""
    if _meter is not None:
        return _meter
    return metrics.get_meter("agentguard")
