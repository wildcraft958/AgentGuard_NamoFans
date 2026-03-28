"""
AgentGuard _pipeline.notifier — Unified OTel + audit notification helpers.

Extracted from Guardian to keep telemetry/audit concerns in one place.
These are mixed into Guardian via composition (self._notifier).
"""

import logging
import time
from contextlib import nullcontext

from opentelemetry.trace import Tracer
from opentelemetry.metrics import Meter

from agentguard.observability.audit import AuditLog

logger = logging.getLogger("agentguard")


class Notifier:
    """Encapsulates OTel span/metric writes and SQLite audit log inserts.

    The Guardian holds a single Notifier instance and delegates all
    observability writes to it, eliminating scattered dual-write patterns.
    """

    def __init__(
        self, tracer: Tracer | None, meter: Meter | None, audit: AuditLog | None, mode: str
    ):
        self._tracer = tracer
        self._meter = meter
        self._audit = audit
        self._mode = mode

    @property
    def audit(self) -> AuditLog | None:
        return self._audit

    def span(self, name: str):
        """Return a context-manager span if tracer available, else a no-op."""
        if self._tracer is not None:
            return self._tracer.start_as_current_span(name)
        return nullcontext(None)

    def set_span_attrs(
        self,
        span,
        is_safe: bool,
        blocked_by: str | None = None,
        blocked_reason: str | None = None,
    ) -> None:
        """Set standard attributes on a span (no-op if span is None)."""
        if span is None:
            return
        try:
            span.set_attribute("agentguard.is_safe", is_safe)
            span.set_attribute("agentguard.mode", self._mode)
            if blocked_by:
                span.set_attribute("agentguard.blocked_by", blocked_by)
            if blocked_reason:
                span.set_attribute("agentguard.blocked_reason", blocked_reason)
        except Exception:
            pass  # Never let telemetry crash the guard

    def record_metrics(self, layer: str, check: str, result: str, start_time: float) -> None:
        """Increment validation counter and record duration histogram."""
        if self._meter is None:
            return
        try:
            elapsed_ms = (time.time() - start_time) * 1000
            attrs = {"layer": layer, "check": check, "result": result}
            self._meter.create_counter(
                "agentguard.validations",
                description="Number of AgentGuard validation decisions",
                unit="1",
            ).add(1, attributes=attrs)
            self._meter.create_histogram(
                "agentguard.validation.duration",
                description="Duration of AgentGuard validation checks",
                unit="ms",
            ).record(elapsed_ms, attributes={"layer": layer, "check": check})
        except Exception:
            pass  # Never let telemetry crash the guard

    def notify(
        self,
        *,
        action: str,
        layer: str,
        blocked_by: str,
        reason: str | None,
        is_safe: bool,
        start_time: float,
        span=None,
        metadata: dict | None = None,
        l4_rbac_decision: str = "",
        l4_signals: str = "[]",
        l4_composite: float = 0.0,
        l4_action: str = "",
    ) -> None:
        """Single notification point for both OTel and SQLite audit log.

        OTel  -> span attributes + metrics histogram.
        Audit -> structured SQLite record.
        """
        self.set_span_attrs(
            span,
            is_safe=is_safe,
            blocked_by=blocked_by if not is_safe else None,
            blocked_reason=reason if not is_safe else None,
        )
        self.record_metrics(layer, blocked_by, "pass" if is_safe else "block", start_time)
        if self._audit:
            self._audit.record(
                action,
                layer,
                is_safe=is_safe,
                reason=reason,
                metadata=metadata,
                l4_rbac_decision=l4_rbac_decision,
                l4_signals=l4_signals,
                l4_composite=l4_composite,
                l4_action=l4_action,
            )
