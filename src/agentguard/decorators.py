"""
AgentGuard -- Decorator API.

Provides the @guard decorator for unified L1 (input) + L2 (output) security,
and @guard_input as a backward-compatible alias for L1-only checks.

Usage:
    from agentguard import guard

    @guard(param="message", output_field="response")
    def chat(message: str):
        return {"response": llm.complete(message)}

    # L1-only (backward compat):
    from agentguard import guard_input

    @guard_input(param="message")
    def chat(message: str):
        return llm.complete(message)
"""

import asyncio
import functools
import inspect
import logging
import threading

from agentguard.guardian import Guardian
from agentguard.parallel import ParallelContext, get_parallel_context, set_parallel_context

logger = logging.getLogger("agentguard.decorators")

# Cache Guardian instances per config path to avoid re-init overhead
_guardian_cache: dict[str, Guardian] = {}

_DEFAULT_CONFIG = "agentguard.yaml"

# Registry for @guard_agent decorated functions
# Maps agent_name -> (guarded_func, config_path, param_name, output_field)
_AGENT_REGISTRY: dict[str, tuple] = {}


def get_registered_agent(agent_name: str) -> tuple | None:
    """Return the registry entry for agent_name, or None if not found."""
    return _AGENT_REGISTRY.get(agent_name)


async def _parallel_guard(guardian, func, args, kwargs, user_text, documents, images, output_field):
    """
    Run L1 validation and agent concurrently.

    L1 validates user_text in a thread. The agent runs immediately in parallel.
    A threading.Event gate holds tool calls until L1 finishes. If L1 blocks,
    the agent task is cancelled via TaskGroup, and any tools that ran
    speculatively are logged for rollback awareness.
    """
    from agentguard.exceptions import InputBlockedError

    par_ctx = ParallelContext(gate=threading.Event())
    set_parallel_context(par_ctx)

    async def l1_coro():
        try:
            logger.debug("guard[parallel]: starting L1 validation")
            await asyncio.to_thread(
                guardian.validate_input, user_text, documents=documents, images=images
            )
            par_ctx.gate.set()
            logger.debug("guard[parallel]: L1 passed, gate open")
        except InputBlockedError as exc:
            par_ctx.cancelled = True
            par_ctx.block_reason = exc.reason
            par_ctx.gate.set()  # unblock waiting tools so they can detect cancellation
            logger.debug("guard[parallel]: L1 blocked, gate cancelled")
            raise

    try:
        async with asyncio.TaskGroup() as tg:
            tg.create_task(l1_coro())
            agent_task = tg.create_task(func(*args, **kwargs))
    except* InputBlockedError as eg:
        for tool_name in par_ctx.executed_tools:
            logger.warning(
                "guard[parallel]: rollback — tool '%s' ran speculatively before L1 block",
                tool_name,
            )
        raise eg.exceptions[0]
    finally:
        set_parallel_context(None)

    result = agent_task.result()

    if output_field is not None:
        output_text = _resolve_output(result, output_field)
        if output_text is not None:
            logger.debug("guard[parallel]: L2 validating output '%s...'", str(output_text)[:50])
            guardian.validate_output(output_text, user_query=user_text, grounding_sources=documents)

    return result


def guard_agent(
    agent_name: str = "default",
    config: str = _DEFAULT_CONFIG,
    param: str = None,
    docs_param: str = None,
    output_field: str = None,
):
    """
    Decorator that applies @guard security AND registers the function in _AGENT_REGISTRY.

    This enables `agentguard test --module <file>` to discover the agent automatically
    without requiring a --function flag.

    Args:
        agent_name: Registry key used by the Promptfoo bridge to look up this agent.
        config: Path to agentguard.yaml config file.
        param: Name of the function parameter containing user text (L1).
        docs_param: Name of the parameter containing documents list (L1 Prompt Shields).
        output_field: Key in the return dict to check for L2 output security.

    Example:
        @guard_agent(agent_name="FinancialBot", param="message", output_field="response")
        def run(message: str) -> dict:
            return {"response": llm.complete(message)}
    """
    def decorator(func):
        guarded = guard(config=config, param=param, docs_param=docs_param, output_field=output_field)(func)
        _AGENT_REGISTRY[agent_name] = (guarded, config, param, output_field)
        return guarded
    return decorator


def _get_guardian(config: str = _DEFAULT_CONFIG) -> Guardian:
    """Return a cached Guardian instance for the given config path."""
    if config not in _guardian_cache:
        logger.debug("Creating new Guardian instance for config: %s", config)
        _guardian_cache[config] = Guardian(config)
    return _guardian_cache[config]


def _extract_param(func, args, kwargs, param_name: str):
    """Extract a named parameter value from function args/kwargs."""
    # Check kwargs first
    if param_name in kwargs:
        return kwargs[param_name]

    # Fall back to positional args using the function signature
    sig = inspect.signature(func)
    params = list(sig.parameters.keys())

    if param_name in params:
        idx = params.index(param_name)
        # Skip 'self' for bound methods
        if params[0] == "self":
            idx -= 1
        if 0 <= idx < len(args):
            return args[idx]

    return None


def guard(
    config: str = _DEFAULT_CONFIG,
    param: str = None,
    docs_param: str = None,
    image_param: str = None,
    output_field: str = None,
):
    """
    Unified decorator: L1 input checks before function, L2 output checks after.

    Args:
        config: Path to agentguard.yaml config file.
        param: Name of the function parameter containing user text (L1).
               If None, uses the first string parameter.
        docs_param: Name of the parameter containing documents list (L1).
        image_param: Name of the parameter containing image(s) (L1).
        output_field: Key in the function's return dict to check for L2.
                      If None, L2 checks are skipped.
                      If the function returns a string (not dict), set to any
                      truthy value and the raw return value is checked.

    Raises:
        InputBlockedError: If input is blocked in enforce mode.
        OutputBlockedError: If output is blocked in enforce mode.

    Example:
        @guard(param="message", output_field="response")
        def chat(message: str):
            return {"response": llm.complete(message)}
    """
    def decorator(func):
        is_async = inspect.iscoroutinefunction(func)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            guardian = _get_guardian(config)

            user_text = _resolve_text(func, args, kwargs, param)
            documents = _resolve_docs(func, args, kwargs, docs_param)
            images = _resolve_images(func, args, kwargs, image_param)

            if user_text is not None and guardian.config.parallel_execution_enabled:
                result = await _parallel_guard(
                    guardian, func, args, kwargs,
                    user_text, documents, images, output_field,
                )
                return result

            # --- Sequential path ---
            if user_text is not None:
                logger.debug("guard: L1 validating input '%s...'", str(user_text)[:50])
                guardian.validate_input(user_text, documents=documents, images=images)

            result = await func(*args, **kwargs)

            if output_field is not None:
                output_text = _resolve_output(result, output_field)
                if output_text is not None:
                    logger.debug("guard: L2 validating output '%s...'", str(output_text)[:50])
                    guardian.validate_output(
                        output_text,
                        user_query=user_text,
                        grounding_sources=documents,
                    )

            return result

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            guardian = _get_guardian(config)

            # --- L1: Input validation ---
            user_text = _resolve_text(func, args, kwargs, param)
            documents = _resolve_docs(func, args, kwargs, docs_param)
            images = _resolve_images(func, args, kwargs, image_param)

            if user_text is not None:
                logger.debug("guard: L1 validating input '%s...'", str(user_text)[:50])
                guardian.validate_input(user_text, documents=documents, images=images)

            # --- Run the function ---
            result = func(*args, **kwargs)

            # --- L2: Output validation ---
            if output_field is not None:
                output_text = _resolve_output(result, output_field)
                if output_text is not None:
                    logger.debug("guard: L2 validating output '%s...'", str(output_text)[:50])
                    guardian.validate_output(
                        output_text,
                        user_query=user_text,
                        grounding_sources=documents,
                    )

            return result

        return async_wrapper if is_async else sync_wrapper
    return decorator


def guard_input(config: str = _DEFAULT_CONFIG, param: str = None, docs_param: str = None, image_param: str = None):
    """
    Backward-compatible L1-only decorator. Alias for @guard() without output_field.

    Args:
        config: Path to agentguard.yaml config file.
        param: Name of the function parameter containing user text.
        docs_param: Optional name of the parameter containing documents list.
        image_param: Optional name of the parameter containing image(s).

    Raises:
        InputBlockedError: If input is blocked in enforce mode.
    """
    return guard(config=config, param=param, docs_param=docs_param, image_param=image_param, output_field=None)


def _parallel_guard_tool(
    guardian,
    fn_name: str,
    fn_args: dict,
    fn,
    ctx: dict,
    *,
    messages: list = None,
    tool_schemas: list = None,
    context: dict = None,
    rollback_fn=None,
):
    """
    Run C3 sequentially, then C1 and tool execution in parallel.

    C3 is zero-latency (pure Python rules) and always runs first — no point
    parallelising it with the tool. C4 (approval workflow) also runs before
    the tool when configured. C1 (Azure entity recognition) is the slow check;
    running it alongside the tool saves its latency on the happy path.

    If C1 blocks after the tool already executed, the tool result is discarded
    (rolled back). An optional rollback_fn is called to undo side-effects.
    """
    from agentguard.exceptions import ToolCallBlockedError
    import time

    start_time = time.time()
    results = []

    # C3: rule-based guards — sequential, fast, must pass before wasting a tool call
    block = guardian._run_c3(fn_name, fn_args, results, start_time, span=None)
    if block is not None:
        return block  # monitor-mode allowed result; enforce mode already raised

    # C4: approval workflow — sequential; human/AI review must happen before execution
    block = guardian._run_c4(fn_name, fn_args, ctx, results, start_time, span=None)
    if block is not None:
        return block

    # C1 + tool execution in parallel
    tool_result_holder = []
    c1_error_holder = []

    def run_c1():
        try:
            block = guardian._run_c1(fn_name, fn_args, results, start_time, span=None)
            if block is not None:
                c1_error_holder.append(("monitor_block", block))
        except ToolCallBlockedError as exc:
            c1_error_holder.append(("blocked", exc))

    def run_tool():
        tool_result_holder.append(fn(**fn_args))

    c1_thread = threading.Thread(target=run_c1, daemon=True)
    tool_thread = threading.Thread(target=run_tool, daemon=True)

    c1_thread.start()
    tool_thread.start()
    c1_thread.join()
    tool_thread.join()

    if c1_error_holder:
        kind, payload = c1_error_holder[0]
        if kind == "blocked":
            # Tool ran but C1 blocked — discard result and roll back
            if tool_result_holder and rollback_fn is not None:
                try:
                    rollback_fn(**fn_args)
                except Exception as rb_exc:
                    logger.warning(
                        "guard_tool[parallel]: rollback_fn for '%s' raised: %s", fn_name, rb_exc
                    )
            logger.warning(
                "guard_tool[parallel]: C1 blocked '%s' after speculative execution — result discarded",
                fn_name,
            )
            raise payload
        # monitor-mode block: tool ran, C1 would have blocked but allowed through
        return payload

    if not tool_result_holder:
        raise RuntimeError(f"Tool '{fn_name}' produced no result (thread may have crashed)")

    result = tool_result_holder[0]

    # C2: MELON post-execution check (sequential, needs tool output)
    out = guardian.validate_tool_output(
        fn_name, fn_args, str(result),
        messages=messages,
        tool_schemas=tool_schemas,
        context=context,
    )

    if out.redacted_output:
        return out.redacted_output
    return result


# ---------------------------------------------------------
# Tool Firewall API
# ---------------------------------------------------------


def guard_tool(
    fn_name: str,
    fn_args: dict,
    fn: callable,
    messages: list = None,
    tool_schemas: list = None,
    config: str = _DEFAULT_CONFIG,
    context: dict = None,
    rollback_fn: callable = None,
) -> str:
    """
    Validate a tool call, execute the tool, then validate the output.

    Pre-execution: Runs Component 3 (rule-based guards) + Component 1
    (entity recognition). Post-execution: Runs Component 2 (MELON).

    Args:
        fn_name: Tool function name.
        fn_args: Tool function arguments dict.
        fn: The actual tool function to call.
        messages: Conversation messages (needed for MELON).
        tool_schemas: Tool schemas in OpenAI format (needed for MELON).
        config: Path to agentguard.yaml config file.
        context: Optional context dict.
        rollback_fn: Optional callable(**fn_args) to undo tool side-effects when
                     parallel C1 check blocks after the tool already executed.

    Returns:
        The tool's output string (possibly redacted by MELON).

    Raises:
        ToolCallBlockedError: If the tool call is blocked in enforce mode.
    """
    guardian = _get_guardian(config)

    ctx = dict(context) if context else {}
    if messages:
        ctx["messages"] = messages

    if guardian.config.parallel_execution_enabled:
        return _parallel_guard_tool(
            guardian, fn_name, fn_args, fn, ctx,
            messages=messages, tool_schemas=tool_schemas, context=context,
            rollback_fn=rollback_fn,
        )

    # Sequential path: C3 + C1 + C4 → tool → C2
    guardian.validate_tool_call(fn_name, fn_args, ctx)

    result = fn(**fn_args)

    out = guardian.validate_tool_output(
        fn_name, fn_args, str(result),
        messages=messages,
        tool_schemas=tool_schemas,
        context=context,
    )

    if out.redacted_output:
        return out.redacted_output
    return result


class GuardedToolRegistry:
    """
    Drop-in wrapper for a tool registry dict that applies tool firewall checks.

    Usage:
        GUARDED = GuardedToolRegistry(TOOL_REGISTRY, TOOL_SCHEMAS)
        # In tool loop:
        GUARDED.set_messages(messages)
        fn = GUARDED.get(fn_name)
        result = fn(**fn_args)
    """

    def __init__(
        self,
        registry: dict,
        tool_schemas: list = None,
        config: str = _DEFAULT_CONFIG,
        rollback_fns: dict = None,
    ):
        self._registry = registry
        self._tool_schemas = tool_schemas or []
        self._config = config
        self._messages: list = []
        self._rollback_fns: dict = rollback_fns or {}

    def set_messages(self, messages: list):
        """Update the current conversation context (call each turn)."""
        self._messages = messages

    def get(self, fn_name: str, default=None):
        """Return a guarded version of the tool function."""
        fn = self._registry.get(fn_name, default)
        if fn is None:
            return default

        config = self._config
        messages = self._messages
        tool_schemas = self._tool_schemas
        rollback_fn = self._rollback_fns.get(fn_name)

        def guarded_fn(**kwargs):
            # --- Parallel gate check ---
            par_ctx = get_parallel_context()
            if par_ctx is not None:
                par_ctx.gate.wait(timeout=60)
                if par_ctx.cancelled:
                    from agentguard.exceptions import ToolCallBlockedError
                    raise ToolCallBlockedError(
                        f"L1 blocked request: {par_ctx.block_reason}"
                    )
                par_ctx.executed_tools.append(fn_name)

            return guard_tool(
                fn_name, kwargs, fn,
                messages=messages,
                tool_schemas=tool_schemas,
                config=config,
                rollback_fn=rollback_fn,
            )

        return guarded_fn

    def __contains__(self, key):
        return key in self._registry


# ---------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------

def _resolve_text(func, args, kwargs, param_name: str = None) -> str:
    """Resolve the user text from function arguments."""
    if param_name:
        return _extract_param(func, args, kwargs, param_name)

    # Auto-detect: use the first string argument
    for arg in args:
        if isinstance(arg, str):
            return arg
    for val in kwargs.values():
        if isinstance(val, str):
            return val

    return None


def _resolve_docs(func, args, kwargs, docs_param: str = None) -> list:
    """Resolve the documents list from function arguments."""
    if not docs_param:
        return None
    return _extract_param(func, args, kwargs, docs_param)


def _resolve_images(func, args, kwargs, image_param: str = None) -> list:
    """Resolve image data from function arguments.

    Returns a list of bytes. If the parameter is a single bytes object,
    wraps it in a list. If None or no param, returns None.
    """
    if not image_param:
        return None
    value = _extract_param(func, args, kwargs, image_param)
    if value is None:
        return None
    # If single bytes, wrap in a list
    if isinstance(value, bytes):
        return [value]
    return value


def _resolve_output(result, output_field: str) -> str:
    """Extract the output text from the function's return value.

    If result is a dict, extracts result[output_field].
    If result is a string, returns it directly.
    Returns None if extraction fails.
    """
    if isinstance(result, dict):
        return result.get(output_field)
    if isinstance(result, str):
        return result
    return None
