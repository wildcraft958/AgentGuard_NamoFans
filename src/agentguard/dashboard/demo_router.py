"""
AgentGuard Demo Router

Provides the /demo page and /api/demo/* endpoints for the interactive
Agent Test Playground. Loads agent modules dynamically and runs them in
background threads so the FastAPI event loop stays unblocked.

Routes:
    GET  /demo                    → serve demo.html
    GET  /api/demo/agents         → sidebar agent list + test cases
    POST /api/demo/run            → submit run → {run_id}
    GET  /api/demo/result/{id}   → poll for completion
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
import time
import uuid
from pathlib import Path
from types import ModuleType

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Path setup — must happen before any test_bots imports
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parents[3]
_src = str(PROJECT_ROOT / "src")
_bots = str(PROJECT_ROOT / "test_bots")
if _src not in sys.path:
    sys.path.insert(0, _src)
if _bots not in sys.path:
    sys.path.insert(0, _bots)

# ---------------------------------------------------------------------------
# Local imports (after path setup)
# ---------------------------------------------------------------------------

from agentguard.dashboard.agent_registry import get_agent, public_registry  # noqa: E402
from agentguard.exceptions import InputBlockedError, OutputBlockedError  # noqa: E402

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

_run_results: dict[str, dict] = {}
_module_cache: dict[str, ModuleType] = {}

STATIC_DIR = Path(__file__).parent / "static"
router = APIRouter()


# ---------------------------------------------------------------------------
# Module loading
# ---------------------------------------------------------------------------


def _load_module(rel_path: str) -> ModuleType:
    """Load a module by path relative to PROJECT_ROOT. Cached by abs path."""
    abs_path = PROJECT_ROOT / rel_path
    key = str(abs_path)
    if key in _module_cache:
        return _module_cache[key]
    spec = importlib.util.spec_from_file_location(abs_path.stem, abs_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    _module_cache[key] = mod
    return mod


# ---------------------------------------------------------------------------
# Agent invocation
# ---------------------------------------------------------------------------


def _invoke_agent(agent_id: str, mode: str, message: str, documents: list | None) -> str:
    """
    Invoke the specified agent in guarded or unguarded mode.

    Returns the plain-text response string.
    Raises InputBlockedError / OutputBlockedError if guarded mode blocks.
    """
    cfg = get_agent(agent_id)
    if cfg is None:
        raise ValueError(f"Unknown agent: {agent_id!r}")

    if mode == "guarded":
        mod = _load_module(cfg["guarded_module"])
        fn = getattr(mod, cfg["guarded_fn"])
        result = fn(user_message=message, documents=documents)
        if isinstance(result, dict):
            return result.get("response", str(result))
        return str(result)
    else:
        mod = _load_module(cfg["unguarded_module"])
        cls = getattr(mod, cfg["unguarded_class"])
        return cls().run(message, documents=documents)


# ---------------------------------------------------------------------------
# Background execution
# ---------------------------------------------------------------------------


def _execute_run(run_id: str, agent_id: str, mode: str, message: str, documents: list | None) -> None:
    """Run the agent synchronously (called from a thread). Writes result to _run_results."""
    start = time.time()
    result: dict = {"status": "complete"}
    try:
        response = _invoke_agent(agent_id, mode, message, documents)
        result["blocked"] = False
        result["response"] = response
    except (InputBlockedError, OutputBlockedError) as e:
        result["blocked"] = True
        result["blocked_reason"] = e.reason
        result["blocked_by"] = e.details.get("blocked_by") if hasattr(e, "details") else None
        result["layer"] = None  # layer not stored on exception; visible in OTel spans
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"{type(e).__name__}: {e}"
    finally:
        result["duration_ms"] = round((time.time() - start) * 1000)
        _run_results[run_id] = result


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------


class RunRequest(BaseModel):
    agent_id: str
    mode: str = "guarded"
    message: str
    documents: list[str] | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/demo")
def serve_demo():
    """Serve the demo UI HTML page."""
    demo_html = STATIC_DIR / "demo.html"
    return FileResponse(str(demo_html))


@router.get("/api/demo/agents")
def get_agents():
    """Return the agent list with test cases (internal module paths stripped)."""
    return public_registry()


@router.post("/api/demo/run")
async def post_run(body: RunRequest):
    """Submit an agent run. Returns immediately with a run_id."""
    run_id = str(uuid.uuid4())
    _run_results[run_id] = {"status": "pending"}
    asyncio.create_task(
        asyncio.to_thread(
            _execute_run, run_id, body.agent_id, body.mode, body.message, body.documents
        )
    )
    return {"run_id": run_id}


@router.get("/api/demo/result/{run_id}")
def get_result(run_id: str):
    """Poll for the result of a run. Returns 404 if run_id is unknown."""
    result = _run_results.get(run_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return result
