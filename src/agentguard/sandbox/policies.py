"""
AgentGuard Sandbox — Policy dataclasses.

These dataclasses map 1:1 with the `sandbox:` section in agentguard.yaml.
They are constructed by AgentGuardConfig.sandbox_policy and passed to
SandboxedToolExecutor and each sandbox layer at init time.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class FilesystemPolicy:
    """Controls which filesystem paths the sandboxed process may access."""
    enabled: bool = True
    # Paths the tool may read (and execute) from
    allowed_read: List[str] = field(default_factory=lambda: [
        "/tmp",
        "/usr/lib",
        "/usr/local/lib",
        "/usr/share",
        "/lib",
        "/lib64",
        "/usr/lib64",
    ])
    # Paths the tool may also write to (superset of read rights)
    allowed_write: List[str] = field(default_factory=lambda: ["/tmp"])


@dataclass
class NetworkPolicy:
    """Controls which network connections the sandboxed process may open."""
    enabled: bool = True
    # "whitelist" = only allowed_hosts, "block_all" = no connections
    mode: str = "whitelist"
    # Supports fnmatch wildcards, e.g. "*.openai.azure.com"
    allowed_hosts: List[str] = field(default_factory=list)
    allowed_ports: List[int] = field(default_factory=lambda: [443, 80])


@dataclass
class SyscallPolicy:
    """Controls which Linux syscalls are blocked inside the sandbox."""
    enabled: bool = True
    blocked_syscalls: List[str] = field(default_factory=lambda: [
        "ptrace",
        "mount",
        "setuid",
        "setgid",
        "chroot",
        "sethostname",
        "setns",
        "unshare",
        "perf_event_open",
        "bpf",
        "pivot_root",
        "kexec_load",
        "kexec_file_load",
        "reboot",
        "init_module",
        "delete_module",
    ])


@dataclass
class ResourceLimits:
    """OS-level resource caps applied via setrlimit in the subprocess."""
    enabled: bool = True
    max_memory_mb: Optional[int] = 512       # RLIMIT_AS
    max_cpu_seconds: Optional[int] = 30      # RLIMIT_CPU
    max_file_size_mb: Optional[int] = 100    # RLIMIT_FSIZE
    max_processes: Optional[int] = None      # RLIMIT_NPROC — None=disabled (conflicts with Queue threads)
    max_open_files: Optional[int] = 64       # RLIMIT_NOFILE — prevents FD exhaustion attacks


@dataclass
class SandboxPolicy:
    """Top-level sandbox policy. Composes all sub-policies."""
    enabled: bool = False
    # "enforce" = raise on violation, "monitor" = log + passthrough on violation
    mode: str = "enforce"
    timeout_seconds: int = 30
    filesystem: FilesystemPolicy = field(default_factory=FilesystemPolicy)
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    syscalls: SyscallPolicy = field(default_factory=SyscallPolicy)
    resources: ResourceLimits = field(default_factory=ResourceLimits)
