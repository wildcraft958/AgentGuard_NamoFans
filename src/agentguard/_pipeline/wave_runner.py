"""
AgentGuard _pipeline.wave_runner — Async parallel check execution.

Runs coroutines in parallel with first-to-fail cancellation. When any check
returns is_safe=False, all remaining in-flight tasks are cancelled.
"""

import asyncio

from agentguard.models import ValidationResult


async def wave_parallel(
    checks: list[tuple[str, object]],
) -> tuple[list[tuple[str, ValidationResult]], tuple[str, ValidationResult] | None]:
    """
    Run check coroutines in parallel with first-to-fail cancellation.

    Args:
        checks: List of (check_name, coroutine) pairs.

    Returns:
        (all_completed_results, first_block_or_none)
    """
    tasks = {asyncio.create_task(coro, name=name) for name, coro in checks}
    results = []
    block_result = None
    pending = set(tasks)

    while pending:
        done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            name = task.get_name()
            result = task.result()
            results.append((name, result))
            if not result.is_safe and block_result is None:
                block_result = (name, result)
                for p in pending:
                    p.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)
                pending = set()
                break

    return results, block_result
