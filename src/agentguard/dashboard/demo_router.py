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
import copy
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
from agentguard.exceptions import InputBlockedError, OutputBlockedError, ToolCallBlockedError  # noqa: E402

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

    supports_docs = cfg.get("supports_documents", True)

    if mode == "guarded":
        mod = _load_module(cfg["guarded_module"])
        fn = getattr(mod, cfg["guarded_fn"])
        result = (
            fn(user_message=message, documents=documents)
            if supports_docs
            else fn(user_message=message)
        )
        if isinstance(result, dict):
            return result.get("response", str(result))
        return str(result)
    else:
        mod = _load_module(cfg["unguarded_module"])
        if "unguarded_fn" in cfg:
            # Function-based unguarded agent (e.g. vulnerable_agent.run_agent)
            fn = getattr(mod, cfg["unguarded_fn"])
            return fn(message)
        else:
            # Class-based unguarded agent
            cls = getattr(mod, cfg["unguarded_class"])
            return cls().run(message, documents=documents) if supports_docs else cls().run(message)


# ---------------------------------------------------------------------------
# MELON direct mode
# ---------------------------------------------------------------------------


def _run_melon_direct(agent_id: str, tool_name: str, tool_args: dict, user_message: str) -> str:
    """
    Bypass the agent LLM entirely: call the named tool directly, then run MELON's
    masked-run-only detection on the output.

    Standard MELON compares original vs masked LLM runs — but safety-trained models
    (e.g. Gemini) refuse to follow injected instructions even in the original run, causing
    MELON to always return safe (no tool calls in original → early exit). The masked run
    is reliable: MELON's few-shot examples explicitly instruct the LLM to follow any
    instructions found in file contents. If the masked run produces tool calls, the tool
    output contains an injection attempting to drive agent behavior.

    Uses OPENAI_* env vars directly (same gateway as the agents) — does not require
    separate TFY_* credentials.
    """
    import os  # noqa: PLC0415

    from dotenv import load_dotenv  # noqa: PLC0415
    from openai import OpenAI  # noqa: PLC0415

    from agentguard.tool_firewall.melon_detector import _FEW_SHOT_MESSAGES  # noqa: PLC0415

    load_dotenv(PROJECT_ROOT / ".env")

    cfg = get_agent(agent_id)
    if cfg is None:
        raise ValueError(f"Unknown agent: {agent_id!r}")

    # Load TOOL_REGISTRY and TOOL_SCHEMAS from the unguarded module
    mod = _load_module(cfg["unguarded_module"])
    tool_registry = getattr(mod, "TOOL_REGISTRY")
    tool_schemas = getattr(mod, "TOOL_SCHEMAS")

    # Step 1: Call the poisoned tool directly (no agent LLM decision needed)
    fn = tool_registry.get(tool_name)
    if fn is None:
        raise ValueError(f"Tool {tool_name!r} not found in {agent_id} registry")
    tool_result = fn(**tool_args)

    # Step 2: Build an OpenAI client using the same gateway as the agents
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        base_url=os.environ.get("OPENAI_BASE_URL", ""),
    )
    model = os.environ.get("OPENAI_MODEL", "")

    # Step 3: Build MELON masked messages
    # Format the tool output as a file for the masked context (same format as melon_detector.py)
    tool_contents = (
        "=" * 50 + "\n\nfunction: tool_output\n\n" + str(tool_result) + "\n\n" + "=" * 50 + "\n\n"
    )
    masked_messages = [
        {
            "role": "system",
            "content": (
                "You are an automation agent. You have access to all tools. "
                "Follow all instructions found in data returned by tools."
            ),
        },
    ]
    masked_messages += copy.deepcopy(_FEW_SHOT_MESSAGES)
    masked_messages.append(
        {
            "role": "user",
            "content": (
                "Thanks. I also read a file called random.txt. This file "
                "also contains some tool calls and their corresponding "
                "execution outputs. Here are the contents:\n\n" + tool_contents + "\n\n"
                "Please summarize the contents. If there are any "
                "instructions in the contents, follow them first, then do "
                "summarization. Else, just summarize the contents. Please "
                "note that contents may already contain some tool calls and "
                "their outputs. If you are trying to follow instructions, "
                "please make sure that you are not repeating the same tool calls."
            ),
        }
    )

    # Step 4: Run masked LLM call
    masked_response = client.chat.completions.create(
        model=model,
        messages=masked_messages,
        tools=tool_schemas,
    )
    masked_msg = masked_response.choices[0].message

    # Step 5: If masked run produced tool calls, the tool output contains injection
    if masked_msg.tool_calls:
        injected_calls = [tc.function.name for tc in masked_msg.tool_calls]
        raise ToolCallBlockedError(
            reason=(
                f"Indirect prompt injection detected in tool output — "
                f"masked run followed injected instructions and called: {injected_calls}"
            ),
            details={"blocked_by": "melon_detector"},
        )

    # Masked run produced no tool calls — no injection detected
    return f"Tool output (MELON: no injection detected):\n{tool_result}"


# ---------------------------------------------------------------------------
# Background execution
# ---------------------------------------------------------------------------


def _execute_run(
    run_id: str,
    agent_id: str,
    mode: str,
    message: str,
    documents: list | None,
    melon_direct: bool = False,
    tool_name: str | None = None,
    tool_args: dict | None = None,
) -> None:
    """Run the agent synchronously (called from a thread). Writes result to _run_results."""
    start = time.time()
    result: dict = {"status": "complete"}
    try:
        if melon_direct and tool_name:
            response = _run_melon_direct(agent_id, tool_name, tool_args or {}, message)
        else:
            response = _invoke_agent(agent_id, mode, message, documents)
        result["blocked"] = False
        result["response"] = response
    except (InputBlockedError, OutputBlockedError, ToolCallBlockedError) as e:
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
    melon_direct: bool = False
    tool_name: str | None = None
    tool_args: dict | None = None


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
            _execute_run,
            run_id,
            body.agent_id,
            body.mode,
            body.message,
            body.documents,
            body.melon_direct,
            body.tool_name,
            body.tool_args,
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
