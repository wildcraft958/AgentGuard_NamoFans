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

import functools
import inspect
import logging

from agentguard.guardian import Guardian

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

            # --- L1: Input validation ---
            user_text = _resolve_text(func, args, kwargs, param)
            documents = _resolve_docs(func, args, kwargs, docs_param)
            images = _resolve_images(func, args, kwargs, image_param)

            if user_text is not None:
                logger.debug("guard: L1 validating input '%s...'", str(user_text)[:50])
                guardian.validate_input(user_text, documents=documents, images=images)

            # --- Run the function ---
            result = await func(*args, **kwargs)

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

    Returns:
        The tool's output string (possibly redacted by MELON).

    Raises:
        ToolCallBlockedError: If the tool call is blocked in enforce mode.
    """
    guardian = _get_guardian(config)

    # Pre-execution: C3 + C1 + C4
    # Inject messages into context so C4 AITL can access user prompt
    ctx = dict(context) if context else {}
    if messages:
        ctx["messages"] = messages
    guardian.validate_tool_call(fn_name, fn_args, ctx)

    # Execute tool — inside sandbox subprocess if sandbox is enabled
    if guardian._sandbox_executor:
        result = guardian._sandbox_executor.execute(fn, fn_args)
    else:
        result = fn(**fn_args)

    # Post-execution: C2 (MELON)
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
    ):
        self._registry = registry
        self._tool_schemas = tool_schemas or []
        self._config = config
        self._messages: list = []

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

        def guarded_fn(**kwargs):
            return guard_tool(
                fn_name, kwargs, fn,
                messages=messages,
                tool_schemas=tool_schemas,
                config=config,
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
