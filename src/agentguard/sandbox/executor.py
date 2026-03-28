"""
AgentGuard Sandbox — SandboxedToolExecutor.

Runs tool functions in an isolated subprocess with four layered defenses
inspired by NemoClaw's architecture:

    Layer 1 — Resource limits   (RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE)
    Layer 2 — Filesystem        (Linux Landlock LSM — kernel-enforced)
    Layer 3 — Syscall filter    (seccomp BPF via libseccomp — kernel-enforced)
    Layer 4 — Network policy    (socket monkey-patch — application-layer)

Integration with guard_tool():
    guard_tool()
        → validate_tool_call()        (existing AgentGuard checks)
        → SandboxedToolExecutor.execute(fn, fn_args)
            → multiprocessing fork → child process
                → apply_resource_limits()
                → apply_landlock()
                → apply_seccomp()
                → apply_network_guard()
                → fn(**fn_args)
            ← IPC Queue result
        → validate_tool_output()      (existing AgentGuard checks)

All four layers are self-restrictions applied inside the child process — no
root privileges are required.
"""

import asyncio
import logging
import multiprocessing
import os
import signal
import time
from typing import Any, Callable

logger = logging.getLogger("agentguard.sandbox.executor")


# ── Subprocess worker ─────────────────────────────────────────────────────────


def _sandbox_worker(
    fn: Callable,
    fn_args: dict,
    result_q: multiprocessing.Queue,
    error_q: multiprocessing.Queue,
    policy,
) -> None:
    """
    Runs inside the forked child process.

    Applies all sandbox layers in order then executes the tool.
    Communicates outcome back to the parent via Queues.
    """
    try:
        # ── Create own process group so timeout can kill all children ──
        # Without this, forked children become orphans adopted by init.
        os.setpgrp()

        # ── Pre-import all sandbox modules BEFORE Landlock restricts filesystem ──
        # Landlock is applied below and will block access to the project source
        # tree AND /etc/ld.so.cache (needed by ctypes.util.find_library).
        # All Python modules AND native library handles must be fully initialized
        # now, while the full filesystem is still accessible.
        from agentguard.sandbox.resource_limits import apply_resource_limits
        from agentguard.sandbox.landlock import apply_landlock
        from agentguard.sandbox.seccomp_guard import apply_seccomp, _get_libseccomp
        from agentguard.sandbox.network_guard import apply_network_guard

        # Pre-load libseccomp.so NOW (reads /etc/ld.so.cache) — must happen
        # before Landlock blocks /etc. The handle is module-level cached so
        # apply_seccomp() will reuse it after Landlock is active.
        _get_libseccomp()

        # ── Layer 1: Resource limits (set first so we stay within memory budget) ──
        if policy.resources.enabled:
            apply_resource_limits(policy.resources)

        # ── Layer 2: Landlock filesystem isolation ────────────────────────────────
        if policy.filesystem.enabled:
            apply_landlock(policy.filesystem)

        # ── Layer 3: Seccomp syscall filter ───────────────────────────────────────
        if policy.syscalls.enabled:
            apply_seccomp(policy.syscalls)

        # ── Layer 4: Network policy ───────────────────────────────────────────────
        if policy.network.enabled:
            apply_network_guard(policy.network)

        # ── Execute tool ──────────────────────────────────────────────────────────
        if asyncio.iscoroutinefunction(fn):
            # Create a fresh event loop in the child — never reuse the parent's.
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(fn(**fn_args))
            finally:
                loop.close()
        else:
            result = fn(**fn_args)

        result_q.put(result)

    except Exception as exc:  # noqa: BLE001
        error_q.put((type(exc).__name__, str(exc)))


# ── Executor ──────────────────────────────────────────────────────────────────


class SandboxedToolExecutor:
    """
    Executes tool functions in a sandboxed subprocess.

    Usage (handled automatically by guard_tool when sandbox is enabled):

        executor = SandboxedToolExecutor(policy)
        result = executor.execute(my_tool_fn, {"arg1": "value"})
    """

    def __init__(self, policy):
        self.policy = policy
        # Fork is the correct context on Linux: zero-copy init, preserves
        # all Python imports in the child without re-pickling the function.
        self._mp_ctx = multiprocessing.get_context("fork")

    def execute(self, fn: Callable, fn_args: dict) -> Any:
        """
        Execute fn(**fn_args) inside a sandboxed subprocess.

        Args:
            fn:      Tool callable.
            fn_args: Arguments dict for fn.

        Returns:
            The tool's return value (passed back via IPC Queue).

        Raises:
            SandboxTimeoutError:   Tool exceeded timeout_seconds.
            SandboxViolationError: Tool raised an exception inside the sandbox,
                                   or the subprocess exited abnormally (e.g.
                                   killed by RLIMIT_CPU SIGXCPU / RLIMIT_AS OOM).
        """
        if not self.policy.enabled or self.policy.mode == "disabled":
            return self._run_direct(fn, fn_args)

        result_q = self._mp_ctx.Queue()
        error_q = self._mp_ctx.Queue()

        proc = self._mp_ctx.Process(
            target=_sandbox_worker,
            args=(fn, fn_args, result_q, error_q, self.policy),
            daemon=True,
        )

        t0 = time.monotonic()
        proc.start()
        fn_name = getattr(fn, "__name__", "<tool>")
        logger.info(
            "Sandbox subprocess started (pid=%d tool=%s timeout=%ds)",
            proc.pid,
            fn_name,
            self.policy.timeout_seconds,
        )

        proc.join(timeout=self.policy.timeout_seconds)
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)

        # ── Timeout ───────────────────────────────────────────────────────────
        if proc.is_alive():
            # Kill entire process group (catches zombie children from fork bombs)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                proc.kill()  # Fallback: kill just the parent
            proc.join(timeout=3)
            from agentguard.exceptions import SandboxTimeoutError

            raise SandboxTimeoutError(
                f"Tool '{fn_name}' timed out after {self.policy.timeout_seconds}s in sandbox",
                details={"elapsed_ms": elapsed_ms, "pid": proc.pid},
            )

        # ── Worker error ──────────────────────────────────────────────────────
        if not error_q.empty():
            exc_type, exc_msg = error_q.get_nowait()

            if self.policy.mode == "monitor":
                logger.warning(
                    "Sandbox violation (monitor — not blocking): %s: %s",
                    exc_type,
                    exc_msg,
                )
                return self._run_direct(fn, fn_args)

            from agentguard.exceptions import SandboxViolationError

            raise SandboxViolationError(
                f"Tool '{fn_name}' raised {exc_type} inside sandbox: {exc_msg}",
                details={
                    "exc_type": exc_type,
                    "elapsed_ms": elapsed_ms,
                    "exit_code": proc.exitcode,
                },
            )

        # ── Normal result ─────────────────────────────────────────────────────
        if not result_q.empty():
            result = result_q.get_nowait()
            logger.info(
                "Sandbox execution completed (tool=%s %.1fms)",
                fn_name,
                elapsed_ms,
            )
            return result

        # Subprocess exited cleanly but produced no result — likely killed by
        # a resource limit signal (SIGXCPU from RLIMIT_CPU, or SIGKILL from OOM).
        from agentguard.exceptions import SandboxViolationError

        raise SandboxViolationError(
            f"Sandbox subprocess for '{fn_name}' exited (code={proc.exitcode}) "
            f"without result — probable resource limit violation",
            details={"exit_code": proc.exitcode, "elapsed_ms": elapsed_ms},
        )

    def _run_direct(self, fn: Callable, fn_args: dict) -> Any:
        """Fallback: run fn in-process (used when sandbox is disabled or monitor mode)."""
        if asyncio.iscoroutinefunction(fn):
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            return loop.run_until_complete(fn(**fn_args))
        return fn(**fn_args)
