"""
AgentGuard Sandbox — OS resource limits.

Applies hard resource caps to the current process using the standard
library `resource` module (wraps Linux setrlimit(2)).

Limits applied:
- RLIMIT_AS    — virtual address space (memory)
- RLIMIT_CPU   — CPU time in seconds
- RLIMIT_FSIZE — maximum file size written
- RLIMIT_NPROC — maximum child processes (prevents fork bombs)
- RLIMIT_NOFILE — maximum open file descriptors (prevents FD exhaustion)

All limits are self-restrictions — no root required.
Must be called first inside the subprocess (before Landlock/seccomp)
so the other modules can still import and initialise.
"""

import logging
import resource

logger = logging.getLogger("agentguard.sandbox.resources")


def apply_resource_limits(limits) -> None:
    """
    Apply OS resource limits to the current process.

    Args:
        limits: ResourceLimits instance.
    """
    applied: list[str] = []

    if limits.max_memory_mb:
        _set(
            resource.RLIMIT_AS,
            limits.max_memory_mb * 1024 * 1024,
            f"memory={limits.max_memory_mb}MB",
            applied,
        )

    if limits.max_cpu_seconds:
        # Soft = configured limit; hard = soft + 5s grace before SIGKILL
        soft = limits.max_cpu_seconds
        hard = soft + 5
        try:
            resource.setrlimit(resource.RLIMIT_CPU, (soft, hard))
            applied.append(f"cpu={limits.max_cpu_seconds}s")
        except (ValueError, resource.error) as e:
            logger.warning("Failed to set CPU time limit: %s", e)

    if limits.max_file_size_mb:
        _set(
            resource.RLIMIT_FSIZE,
            limits.max_file_size_mb * 1024 * 1024,
            f"file_size={limits.max_file_size_mb}MB",
            applied,
        )

    if limits.max_processes is not None:
        _set(
            resource.RLIMIT_NPROC,
            limits.max_processes,
            f"nproc={limits.max_processes}",
            applied,
        )

    if limits.max_open_files is not None:
        _set(
            resource.RLIMIT_NOFILE,
            limits.max_open_files,
            f"nofile={limits.max_open_files}",
            applied,
        )

    if applied:
        logger.info("Resource limits applied: %s", ", ".join(applied))


def _set(rlimit_const: int, value: int, label: str, applied: list) -> None:
    try:
        resource.setrlimit(rlimit_const, (value, value))
        applied.append(label)
    except (ValueError, resource.error) as e:
        logger.warning("Failed to set %s limit: %s", label, e)
