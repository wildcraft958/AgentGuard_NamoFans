"""
AgentGuard Dashboard — FastAPI server.

Proxies Jaeger REST API traces + merges with SQLite audit log.
Serves static NamoFans HTML and SSE live event stream.

Endpoints:
    GET /                → landing.html
    GET /dashboard       → index.html (OTel live dashboard)
    GET /api/spans       → normalized Jaeger traces, newest first
    GET /api/stats       → aggregate stats (Jaeger + AuditLog)
    GET /api/audit       → recent AuditLog rows
    GET /events          → SSE: polls Jaeger every 2s, pushes span + stats events
"""

import asyncio
import json
import logging
import os
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.responses import FileResponse
from sse_starlette.sse import EventSourceResponse

from agentguard.audit_log import AuditLog
from agentguard.dashboard.demo_router import router as demo_router

logger = logging.getLogger("agentguard.dashboard")

JAEGER_BASE = os.environ.get("JAEGER_QUERY_URL", "http://localhost:16686")
STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="AgentGuard Dashboard")
app.include_router(demo_router)

# ---------------------------------------------------------------------------
# Singleton audit log (lazy-init, one per process)
# ---------------------------------------------------------------------------

_audit_log: AuditLog | None = None


def _get_audit_log() -> AuditLog:
    global _audit_log
    if _audit_log is None:
        _audit_log = AuditLog()
    return _audit_log


# ---------------------------------------------------------------------------
# Jaeger helpers
# ---------------------------------------------------------------------------

_LAYER_MAP = {
    "agentguard.validate_input": "l1_input",
    "agentguard.validate_output": "l2_output",
    "agentguard.validate_tool_call": "tool_firewall",
    "agentguard.validate_tool_output": "tool_firewall",
}


def _detect_layer(operation_name: str) -> str:
    """Map operation name to security layer label."""
    for prefix, layer in _LAYER_MAP.items():
        if operation_name.startswith(prefix):
            return layer
    if "input" in operation_name:
        return "l1_input"
    if "output" in operation_name:
        return "l2_output"
    if "tool" in operation_name:
        return "tool_firewall"
    return "unknown"


def transform_span(raw_span: dict) -> dict:
    """
    Normalize a Jaeger span dict into AgentGuard dashboard format.

    Args:
        raw_span: Single span dict from Jaeger /api/traces response.

    Returns:
        Normalized dict with trace_id, span_id, operation_name, start_ms,
        duration_ms, tags, status, layer, blocked_by.
    """
    tags: dict[str, str] = {}
    for tag in raw_span.get("tags", []):
        tags[tag["key"]] = str(tag.get("value", ""))

    is_safe_val = tags.get("agentguard.is_safe", "true").lower()
    status = "blocked" if is_safe_val == "false" else "safe"

    blocked_by = tags.get("agentguard.blocked_by") or None

    operation_name = raw_span.get("operationName", "")
    layer_tag = tags.get("agentguard.layer") or _detect_layer(operation_name)

    start_us = raw_span.get("startTime", 0)
    duration_us = raw_span.get("duration", 0)

    return {
        "trace_id": raw_span.get("traceID", ""),
        "span_id": raw_span.get("spanID", ""),
        "operation_name": operation_name,
        "start_ms": start_us // 1000,
        "duration_ms": duration_us // 1000,
        "tags": tags,
        "status": status,
        "layer": layer_tag,
        "blocked_by": blocked_by,
    }


def fetch_jaeger_traces(service: str = "agentguard", limit: int = 100) -> list[dict]:
    """
    Query Jaeger REST API for recent traces.

    Args:
        service: Jaeger service name to filter by.
        limit:   Maximum number of traces to retrieve.

    Returns:
        List of normalized span dicts (all spans from all matching traces),
        sorted newest first. Returns [] on any error.
    """
    try:
        url = f"{JAEGER_BASE}/api/traces"
        resp = httpx.get(url, params={"service": service, "limit": limit}, timeout=5.0)
        resp.raise_for_status()
        data = resp.json()
        traces = data.get("data") or []

        spans: list[dict] = []
        for trace in traces:
            for raw_span in trace.get("spans", []):
                spans.append(transform_span(raw_span))

        spans.sort(key=lambda s: s["start_ms"], reverse=True)
        return spans
    except Exception as exc:
        logger.debug("Jaeger fetch failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/favicon.svg")
@app.get("/favicon.ico")
def serve_favicon():
    return FileResponse(str(STATIC_DIR / "favicon.svg"), media_type="image/svg+xml")


@app.get("/")
def serve_landing():
    return FileResponse(str(STATIC_DIR / "landing.html"))


@app.get("/dashboard")
def serve_dashboard():
    return FileResponse(str(STATIC_DIR / "index.html"))


@app.get("/api/spans")
def get_spans(limit: int = 100):
    """Return normalized Jaeger spans, newest first."""
    return fetch_jaeger_traces(limit=limit)


@app.get("/api/stats")
def get_stats():
    """Return aggregate stats from Jaeger traces + AuditLog."""
    import time as _time

    spans = fetch_jaeger_traces(limit=500)
    audit = _get_audit_log()

    total_spans = len(spans)
    blocked_spans = sum(1 for s in spans if s["status"] == "blocked")

    durations = [s["duration_ms"] for s in spans if s["duration_ms"] > 0]
    avg_duration_ms = round(sum(durations) / len(durations), 1) if durations else 0.0

    layer_breakdown: dict[str, dict[str, int]] = {
        "l1_input": {"pass": 0, "block": 0},
        "l2_output": {"pass": 0, "block": 0},
        "tool_firewall": {"pass": 0, "block": 0},
    }
    for span in spans:
        layer = span["layer"]
        if layer in layer_breakdown:
            if span["status"] == "blocked":
                layer_breakdown[layer]["block"] += 1
            else:
                layer_breakdown[layer]["pass"] += 1

    cutoff_ms = int(_time.time() * 1000) - 24 * 3600 * 1000
    recent = [s for s in spans if s["start_ms"] >= cutoff_ms]
    if recent:
        safe_24h = sum(1 for s in recent if s["status"] != "blocked")
        pass_rate_24h = round(safe_24h / len(recent), 4)
    else:
        pass_rate_24h = 1.0

    audit_blocked = audit.blocked_count()

    return {
        "total_spans": total_spans,
        "blocked_spans": blocked_spans if total_spans else audit_blocked,
        "pass_rate_24h": pass_rate_24h,
        "avg_duration_ms": avg_duration_ms,
        "layer_breakdown": layer_breakdown,
    }


@app.get("/api/audit")
def get_audit(limit: int = 50):
    """Return recent AuditLog rows."""
    audit = _get_audit_log()
    return audit.recent(limit)


# ---------------------------------------------------------------------------
# SSE live event stream
# ---------------------------------------------------------------------------


async def _event_generator():
    """
    Async generator that polls Jaeger every 2 seconds and yields SSE events.

    Emits two event types:
      - type="span"  → individual new span dicts
      - type="stats" → current aggregate stats
    """
    seen_span_ids: set[str] = set()

    while True:
        spans = fetch_jaeger_traces(limit=100)
        new_spans = [s for s in spans if s["span_id"] not in seen_span_ids]

        for span in reversed(new_spans):  # oldest first so feed reads chronologically
            seen_span_ids.add(span["span_id"])
            yield {
                "event": "span",
                "data": json.dumps(span),
            }

        if new_spans or not seen_span_ids:
            stats = get_stats()
            yield {
                "event": "stats",
                "data": json.dumps(stats),
            }

        await asyncio.sleep(2)


@app.get("/events")
async def sse_events():
    """SSE endpoint — streams live spans and stats to the browser."""
    return EventSourceResponse(_event_generator())
