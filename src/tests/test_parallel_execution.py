"""Tests for parallel execution mode (guard decorator + guard_tool)."""

import asyncio
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentguard.parallel import ParallelContext, get_parallel_context, set_parallel_context
from agentguard.exceptions import InputBlockedError, ToolCallBlockedError
from agentguard.models import InputValidationResult, ToolCallValidationResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_guardian(parallel=True, l1_safe=True, c3_safe=True, c1_safe=True):
    """Build a mock Guardian with configurable behaviour."""
    mock = MagicMock()
    mock.config.parallel_execution_enabled = parallel
    mock.config.mode.value = "enforce"

    if l1_safe:
        mock.validate_input.return_value = InputValidationResult(is_safe=True, results=[])
        mock.avalidate_input = AsyncMock(
            return_value=InputValidationResult(is_safe=True, results=[])
        )
    else:
        mock.validate_input.side_effect = InputBlockedError("injection detected")
        mock.avalidate_input = AsyncMock(side_effect=InputBlockedError("injection detected"))

    # _run_c3/_run_c1/_run_c4 return None on pass (raise ToolCallBlockedError on failure)
    mock._run_c3.return_value = None
    mock._run_c1.return_value = None
    mock._run_c4.return_value = None

    if not c3_safe:
        mock._run_c3.side_effect = ToolCallBlockedError("rule violation")
    if not c1_safe:
        mock._run_c1.side_effect = ToolCallBlockedError("entity detected")

    mock.validate_tool_output.return_value = ToolCallValidationResult(is_safe=True, tool_name="t")
    return mock


# ---------------------------------------------------------------------------
# ParallelContext unit tests
# ---------------------------------------------------------------------------


class TestParallelContext:
    def test_gate_starts_unset(self):
        ctx = ParallelContext(gate=threading.Event())
        assert not ctx.gate.is_set()
        assert not ctx.cancelled
        assert ctx.block_reason is None
        assert ctx.executed_tools == []

    def test_set_and_get_context(self):
        ctx = ParallelContext(gate=threading.Event())
        set_parallel_context(ctx)
        assert get_parallel_context() is ctx

    def test_clear_context(self):
        ctx = ParallelContext(gate=threading.Event())
        set_parallel_context(ctx)
        set_parallel_context(None)
        assert get_parallel_context() is None

    def test_contextvar_isolation(self):
        """Each coroutine/thread gets its own view."""
        results = {}

        async def task_a():
            ctx = ParallelContext(gate=threading.Event())
            set_parallel_context(ctx)
            await asyncio.sleep(0)
            results["a"] = get_parallel_context()

        async def task_b():
            set_parallel_context(None)
            await asyncio.sleep(0)
            results["b"] = get_parallel_context()

        async def run():
            await asyncio.gather(task_a(), task_b())

        asyncio.run(run())
        # Each task saw its own context value
        assert results["a"] is not None
        assert results["b"] is None


# ---------------------------------------------------------------------------
# guard decorator — parallel L1 + agent
# ---------------------------------------------------------------------------


class TestGuardParallelL1:
    @pytest.mark.asyncio
    async def test_l1_safe_agent_runs_and_returns_result(self):
        """When L1 passes, agent result is returned normally."""
        from agentguard.decorators import guard, _guardian_cache

        _guardian_cache.clear()

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=True, l1_safe=True)

            @guard(param="msg", output_field=None)
            async def agent(msg: str) -> dict:
                return {"response": f"ok: {msg}"}

            result = await agent(msg="hello")
            assert result == {"response": "ok: hello"}

    @pytest.mark.asyncio
    async def test_l1_blocks_raises_input_blocked_error(self):
        """When L1 blocks, InputBlockedError is raised and agent is cancelled."""
        from agentguard.decorators import guard, _guardian_cache

        _guardian_cache.clear()

        agent_started = threading.Event()

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=True, l1_safe=False)

            @guard(param="msg", output_field=None)
            async def agent(msg: str) -> dict:
                agent_started.set()
                await asyncio.sleep(10)  # long-running; should be cancelled
                return {"response": "should not reach"}

            with pytest.raises(InputBlockedError):
                await agent(msg="inject me")

    @pytest.mark.asyncio
    async def test_l1_block_logs_speculatively_executed_tools(self, caplog):
        """Speculatively executed tools are logged when L1 blocks."""
        import logging
        from agentguard.decorators import guard, _guardian_cache

        _guardian_cache.clear()

        guardian = _make_guardian(parallel=True, l1_safe=False)

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = guardian

            @guard(param="msg", output_field=None)
            async def agent(msg: str) -> dict:
                # Simulate a tool that ran before L1 finished
                ctx = get_parallel_context()
                if ctx:
                    ctx.executed_tools.append("read_db")
                return {"response": "done"}

            with caplog.at_level(logging.WARNING, logger="agentguard.decorators"):
                with pytest.raises(InputBlockedError):
                    await agent(msg="bad input")

            assert any("read_db" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_sequential_mode_unchanged(self):
        """When parallel_execution_enabled=False, no ParallelContext is created."""
        from agentguard.decorators import guard, _guardian_cache

        _guardian_cache.clear()

        seen_ctx = []

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=False, l1_safe=True)

            @guard(param="msg", output_field=None)
            async def agent(msg: str) -> dict:
                seen_ctx.append(get_parallel_context())
                return {"response": "ok"}

            result = await agent(msg="hello")
            assert result == {"response": "ok"}
            assert seen_ctx[0] is None  # no context in sequential mode


# ---------------------------------------------------------------------------
# Gate mechanism — GuardedToolRegistry
# ---------------------------------------------------------------------------


class TestParallelGate:
    def test_gate_blocks_tool_until_set(self):
        """Tool execution waits on the gate and proceeds when L1 passes."""
        from agentguard.decorators import GuardedToolRegistry

        executed = []

        def my_tool(**kwargs):
            executed.append("ran")
            return "result"

        registry = GuardedToolRegistry({"my_tool": my_tool}, config="dummy.yaml")

        ctx = ParallelContext(gate=threading.Event())
        set_parallel_context(ctx)

        # Release gate after a short delay (simulating L1 passing)
        def release():
            time.sleep(0.05)
            ctx.gate.set()

        t = threading.Thread(target=release)
        t.start()

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=True)
            fn = registry.get("my_tool")
            result = fn()

        t.join()
        set_parallel_context(None)

        assert result == "result"
        assert executed == ["ran"]

    def test_cancelled_gate_prevents_tool_execution(self):
        """When gate is set but cancelled=True, tool raises ToolCallBlockedError."""
        from agentguard.decorators import GuardedToolRegistry

        executed = []

        def my_tool(**kwargs):
            executed.append("ran")
            return "result"

        registry = GuardedToolRegistry({"my_tool": my_tool}, config="dummy.yaml")

        ctx = ParallelContext(gate=threading.Event())
        ctx.cancelled = True
        ctx.block_reason = "injection detected"
        ctx.gate.set()  # gate is set (unblocked) but cancelled
        set_parallel_context(ctx)

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=True)
            fn = registry.get("my_tool")
            with pytest.raises(ToolCallBlockedError, match="injection detected"):
                fn()

        set_parallel_context(None)
        assert executed == []  # tool never ran


# ---------------------------------------------------------------------------
# guard_tool — parallel C1 + tool execution
# ---------------------------------------------------------------------------


class TestGuardToolParallel:
    def test_c3_blocks_before_tool_runs(self):
        """C3 failure prevents tool from running (C3 is always sequential)."""
        from agentguard.decorators import guard_tool

        tool_ran = []

        def my_tool(**kwargs):
            tool_ran.append(True)
            return "result"

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=True, c3_safe=False)
            with pytest.raises(ToolCallBlockedError):
                guard_tool("my_tool", {}, my_tool, config="dummy.yaml")

        assert tool_ran == []

    def test_c1_fails_tool_result_discarded(self):
        """When C1 blocks in parallel path, tool result is discarded and error raised."""
        from agentguard.decorators import guard_tool

        tool_ran = []

        def my_tool(**kwargs):
            tool_ran.append(True)
            return "sensitive result"

        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=True, c3_safe=True, c1_safe=False)
            with pytest.raises(ToolCallBlockedError, match="entity detected"):
                guard_tool("my_tool", {}, my_tool, config="dummy.yaml")

    def test_rollback_fn_called_on_c1_failure(self):
        """Optional rollback_fn is called when C1 blocks after tool executed."""
        from agentguard.decorators import GuardedToolRegistry

        rolled_back = []

        def my_tool(**kwargs):
            return "wrote to db"

        def undo_my_tool(**kwargs):
            rolled_back.append(kwargs)

        registry = GuardedToolRegistry(
            {"my_tool": my_tool},
            rollback_fns={"my_tool": undo_my_tool},
            config="dummy.yaml",
        )

        # No parallel gate — test rollback_fn path in guard_tool directly
        with patch("agentguard.decorators._get_guardian") as mock_get:
            mock_get.return_value = _make_guardian(parallel=True, c3_safe=True, c1_safe=False)
            fn = registry.get("my_tool")
            with pytest.raises(ToolCallBlockedError):
                fn(arg="val")

        assert rolled_back == [{"arg": "val"}]
