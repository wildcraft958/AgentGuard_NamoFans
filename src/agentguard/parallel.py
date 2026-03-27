"""
AgentGuard -- Parallel execution context.

Holds shared state for one request when parallel_execution is enabled:
  - gate: threading.Event that tools wait on until L1 validation finishes
  - cancelled: True when L1 blocked; tools check this after the gate opens
  - block_reason: the L1 block message, forwarded to waiting tools
  - executed_tools: names of tools that ran speculatively before L1 finished
"""

import threading
from contextvars import ContextVar
from dataclasses import dataclass, field


@dataclass
class ParallelContext:
    gate: threading.Event = field(default_factory=threading.Event)
    cancelled: bool = False
    block_reason: str | None = None
    executed_tools: list[str] = field(default_factory=list)


_ctx: ContextVar[ParallelContext | None] = ContextVar("agentguard_parallel", default=None)


def get_parallel_context() -> ParallelContext | None:
    return _ctx.get()


def set_parallel_context(ctx: ParallelContext | None) -> None:
    _ctx.set(ctx)
