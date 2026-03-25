"""
AgentGuard Sandbox — NemoClaw-inspired subprocess isolation.

Provides four layered defenses applied inside a forked subprocess before
each tool call executes:

    1. Resource limits  — RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE (setrlimit)
    2. Filesystem       — Linux Landlock LSM (kernel 5.13+, no root required)
    3. Syscall filter   — seccomp BPF via libseccomp (no root required)
    4. Network policy   — socket.connect whitelist/block-all (Python-layer)

Enable in agentguard.yaml:

    sandbox:
      enabled: true
      mode: enforce          # enforce | monitor
      timeout_seconds: 30
      filesystem:
        allowed_read: [/tmp, /usr/lib]
        allowed_write: [/tmp]
      network:
        mode: whitelist
        allowed_hosts: ["*.openai.azure.com"]
        allowed_ports: [443]
      syscalls:
        blocked_syscalls: [ptrace, mount, setuid]
      resources:
        max_memory_mb: 512
        max_cpu_seconds: 30
"""

from agentguard.sandbox.executor import SandboxedToolExecutor
from agentguard.sandbox.policies import (
    FilesystemPolicy,
    NetworkPolicy,
    ResourceLimits,
    SandboxPolicy,
    SyscallPolicy,
)

__all__ = [
    "SandboxedToolExecutor",
    "SandboxPolicy",
    "FilesystemPolicy",
    "NetworkPolicy",
    "SyscallPolicy",
    "ResourceLimits",
]
