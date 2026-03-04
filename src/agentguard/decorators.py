"""
AgentGuard -- Decorator API.

Provides the @guard_input decorator to protect functions with
automatic L1 input security validation (Prompt Shields + Content Filters + Image Filters).

Usage:
    from agentguard import guard_input

    @guard_input(param="message")
    def chat(message: str):
        return llm.complete(message)

    @guard_input(param="message", image_param="photo")
    def chat_with_image(message: str, photo: bytes = None):
        return vision_model.analyze(message, photo)
"""

import functools
import inspect
import logging

from agentguard.guardian import Guardian

logger = logging.getLogger("agentguard.decorators")

# Cache Guardian instances per config path to avoid re-init overhead
_guardian_cache: dict[str, Guardian] = {}

_DEFAULT_CONFIG = "agentguard.yaml"


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


def guard_input(config: str = _DEFAULT_CONFIG, param: str = None, docs_param: str = None, image_param: str = None):
    """
    Decorator that validates function input through AgentGuard L1 checks
    (Prompt Shields + Content Filters + Image Filters) before the function runs.

    Args:
        config: Path to agentguard.yaml config file.
        param: Name of the function parameter containing user text.
               If None, uses the first string parameter.
        docs_param: Optional name of the parameter containing documents list.
        image_param: Optional name of the parameter containing image(s).
                     Can be bytes (single image) or list[bytes] (multiple).

    Raises:
        InputBlockedError: If input is blocked in enforce mode.

    Example:
        @guard_input(param="message", image_param="photo")
        def chat(message: str, photo: bytes = None):
            return llm.complete(message)
    """
    def decorator(func):
        is_async = inspect.iscoroutinefunction(func)

        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            guardian = _get_guardian(config)
            user_text = _resolve_text(func, args, kwargs, param)
            documents = _resolve_docs(func, args, kwargs, docs_param)
            images = _resolve_images(func, args, kwargs, image_param)

            if user_text is not None:
                logger.debug("guard_input: validating '%s...'", str(user_text)[:50])
                guardian.validate_input(user_text, documents=documents, images=images)

            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            guardian = _get_guardian(config)
            user_text = _resolve_text(func, args, kwargs, param)
            documents = _resolve_docs(func, args, kwargs, docs_param)
            images = _resolve_images(func, args, kwargs, image_param)

            if user_text is not None:
                logger.debug("guard_input: validating '%s...'", str(user_text)[:50])
                guardian.validate_input(user_text, documents=documents, images=images)

            return func(*args, **kwargs)

        return async_wrapper if is_async else sync_wrapper
    return decorator


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
