"""
AgentGuard _pipeline.handlers — Mode-aware block handlers.

Extracted from Guardian. Each handler decides whether to block (enforce)
or log-and-allow (monitor) based on the current guard mode.
"""

import logging
import time

from agentguard._pipeline.notifier import Notifier
from agentguard.exceptions import InputBlockedError, OutputBlockedError, ToolCallBlockedError
from agentguard.models import (
    GuardMode,
    InputValidationResult,
    OutputValidationResult,
    ToolCallValidationResult,
    ValidationResult,
)

logger = logging.getLogger("agentguard")


def handle_input_block(
    mode: GuardMode,
    notifier: Notifier,
    results: list,
    blocking_result: ValidationResult,
    blocked_by: str,
    start_time: float,
    span=None,
) -> InputValidationResult:
    """Handle a blocked input — single notify call covers OTel + audit."""
    elapsed_ms = (time.time() - start_time) * 1000

    if mode == GuardMode.MONITOR:
        logger.warning(
            "MONITOR mode: would block (%s: %s) but allowing through (%.1fms)",
            blocked_by,
            blocking_result.blocked_reason,
            elapsed_ms,
        )
        notifier.notify(
            action="validate_input",
            layer="l1_input",
            blocked_by=blocked_by,
            reason=f"MONITOR: would block via {blocked_by}",
            is_safe=True,
            start_time=start_time,
            span=span,
            metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
        )
        return InputValidationResult(
            is_safe=True, results=results, blocked_by=None, blocked_reason=None
        )

    # ENFORCE mode
    logger.warning(
        "ENFORCE mode: BLOCKING input (%s: %s) (%.1fms)",
        blocked_by,
        blocking_result.blocked_reason,
        elapsed_ms,
    )
    notifier.notify(
        action="validate_input",
        layer="l1_input",
        blocked_by=blocked_by,
        reason=blocking_result.blocked_reason,
        is_safe=False,
        start_time=start_time,
        span=span,
        metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
    )
    result = InputValidationResult(
        is_safe=False,
        results=results,
        blocked_by=blocked_by,
        blocked_reason=blocking_result.blocked_reason,
    )
    raise InputBlockedError(
        reason=blocking_result.blocked_reason,
        details={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms, "validation_result": result},
    )


def handle_tool_block(
    mode: GuardMode,
    notifier: Notifier,
    results: list,
    blocking_result: ValidationResult,
    blocked_by: str,
    start_time: float,
    tool_name: str,
    span=None,
    layer: str = "tool_firewall",
    **l4_kwargs,
) -> ToolCallValidationResult:
    """Handle a blocked tool call — single notify call covers OTel + audit."""
    elapsed_ms = (time.time() - start_time) * 1000

    if mode == GuardMode.MONITOR:
        logger.warning(
            "MONITOR mode: would block tool call (%s: %s) but allowing (%.1fms)",
            blocked_by,
            blocking_result.blocked_reason,
            elapsed_ms,
        )
        notifier.notify(
            action="validate_tool_call",
            layer=layer,
            blocked_by=blocked_by,
            reason=f"MONITOR: would block via {blocked_by}",
            is_safe=True,
            start_time=start_time,
            span=span,
            metadata={"blocked_by": blocked_by, "tool_name": tool_name, "elapsed_ms": elapsed_ms},
            **l4_kwargs,
        )
        return ToolCallValidationResult(is_safe=True, results=results, tool_name=tool_name)

    # ENFORCE mode
    logger.warning(
        "ENFORCE mode: BLOCKING tool call (%s: %s) (%.1fms)",
        blocked_by,
        blocking_result.blocked_reason,
        elapsed_ms,
    )
    notifier.notify(
        action="validate_tool_call",
        layer=layer,
        blocked_by=blocked_by,
        reason=blocking_result.blocked_reason,
        is_safe=False,
        start_time=start_time,
        span=span,
        metadata={"blocked_by": blocked_by, "tool_name": tool_name, "elapsed_ms": elapsed_ms},
        **l4_kwargs,
    )
    result = ToolCallValidationResult(
        is_safe=False,
        results=results,
        blocked_by=blocked_by,
        blocked_reason=blocking_result.blocked_reason,
        tool_name=tool_name,
    )
    raise ToolCallBlockedError(
        reason=blocking_result.blocked_reason,
        details={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms, "validation_result": result},
    )


def handle_output_block(
    mode: GuardMode,
    notifier: Notifier,
    results: list,
    blocking_result: ValidationResult,
    blocked_by: str,
    start_time: float,
    redacted_text: str = None,
    span=None,
) -> OutputValidationResult:
    """Handle a blocked output — single notify call covers OTel + audit."""
    elapsed_ms = (time.time() - start_time) * 1000

    if mode == GuardMode.MONITOR:
        logger.warning(
            "MONITOR mode: would block output (%s: %s) but allowing through (%.1fms)",
            blocked_by,
            blocking_result.blocked_reason,
            elapsed_ms,
        )
        notifier.notify(
            action="validate_output",
            layer="l2_output",
            blocked_by=blocked_by,
            reason=f"MONITOR: would block via {blocked_by}",
            is_safe=True,
            start_time=start_time,
            span=span,
            metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
        )
        return OutputValidationResult(is_safe=True, results=results, redacted_text=redacted_text)

    # ENFORCE mode
    logger.warning(
        "ENFORCE mode: BLOCKING output (%s: %s) (%.1fms)",
        blocked_by,
        blocking_result.blocked_reason,
        elapsed_ms,
    )
    notifier.notify(
        action="validate_output",
        layer="l2_output",
        blocked_by=blocked_by,
        reason=blocking_result.blocked_reason,
        is_safe=False,
        start_time=start_time,
        span=span,
        metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
    )
    result = OutputValidationResult(
        is_safe=False,
        results=results,
        blocked_by=blocked_by,
        blocked_reason=blocking_result.blocked_reason,
        redacted_text=redacted_text,
    )
    raise OutputBlockedError(
        reason=blocking_result.blocked_reason,
        details={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms, "validation_result": result},
    )
