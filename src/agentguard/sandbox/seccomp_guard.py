"""
AgentGuard Sandbox — seccomp syscall filtering.

Uses libseccomp (via ctypes) to install a default-allow seccomp filter that
blocks specific dangerous syscalls with EPERM.

Key properties:
- Self-restriction: no root privileges required.
- Kernel-enforced via BPF: cannot be bypassed from inside the process.
- Default-allow: only explicitly listed syscalls are blocked.

Falls back gracefully (logs a warning) if libseccomp is not installed.
"""

import ctypes
import ctypes.util
import logging

logger = logging.getLogger("agentguard.sandbox.seccomp")

# ── libseccomp action constants ───────────────────────────────────────────────
_SCMP_ACT_ALLOW = 0x7FFF0000
_SCMP_ACT_ERRNO_EPERM = 0x00050001  # SECCOMP_RET_ERRNO | EPERM(1)

# ── Syscall numbers (x86_64 Linux) ────────────────────────────────────────────
# Only lists syscalls we may want to block. Anything not here is allowed.
_SYSCALL_NR: dict[str, int] = {
    "ptrace": 101,
    "mount": 165,
    "setuid": 105,
    "setgid": 106,
    "chroot": 161,
    "sethostname": 170,
    "setns": 308,
    "unshare": 272,
    "perf_event_open": 298,
    "bpf": 321,
    "pivot_root": 155,
    "kexec_load": 246,
    "kexec_file_load": 320,
    "reboot": 169,
    "syslog": 103,
    "init_module": 175,
    "delete_module": 176,
    "create_module": 174,
    "keyctl": 250,
    "add_key": 248,
    "request_key": 249,
    "iopl": 172,
    "ioperm": 173,
    "lookup_dcookie": 212,
}

# ── libseccomp loader ─────────────────────────────────────────────────────────
_lib = None
_lib_loaded = False


def _get_libseccomp():
    global _lib, _lib_loaded
    if _lib_loaded:
        return _lib
    _lib_loaded = True

    path = ctypes.util.find_library("seccomp")
    if not path:
        logger.info("libseccomp not found — install libseccomp2 for syscall filtering")
        return None

    try:
        lib = ctypes.CDLL(path, use_errno=True)

        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_init.argtypes = [ctypes.c_uint32]

        lib.seccomp_rule_add.restype = ctypes.c_int
        lib.seccomp_rule_add.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint,
        ]

        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_load.argtypes = [ctypes.c_void_p]

        lib.seccomp_release.restype = None
        lib.seccomp_release.argtypes = [ctypes.c_void_p]

        _lib = lib
        logger.debug("libseccomp loaded from %s", path)
    except (OSError, AttributeError) as e:
        logger.warning("Failed to load libseccomp (%s) — syscall filtering skipped", e)

    return _lib


# ── Public API ────────────────────────────────────────────────────────────────


def apply_seccomp(syscall_policy) -> bool:
    """
    Install a seccomp BPF filter on the current process (default-allow).

    Syscalls listed in syscall_policy.blocked_syscalls will return EPERM.
    All other syscalls are allowed through.

    Args:
        syscall_policy: SyscallPolicy instance.

    Returns:
        True  — filter was installed.
        False — libseccomp unavailable or load failed.
    """
    lib = _get_libseccomp()
    if lib is None:
        return False

    # Initialize filter with default-allow action
    ctx = lib.seccomp_init(_SCMP_ACT_ALLOW)
    if not ctx:
        logger.error("seccomp_init returned NULL")
        return False

    blocked: list[str] = []
    try:
        for name in syscall_policy.blocked_syscalls:
            nr = _SYSCALL_NR.get(name)
            if nr is None:
                logger.warning("Seccomp: unknown syscall '%s' — skipping", name)
                continue
            ret = lib.seccomp_rule_add(ctx, _SCMP_ACT_ERRNO_EPERM, nr, 0)
            if ret != 0:
                logger.warning("Seccomp: seccomp_rule_add failed for '%s' (ret=%d)", name, ret)
            else:
                blocked.append(name)

        ret = lib.seccomp_load(ctx)
        if ret != 0:
            logger.error("seccomp_load failed (ret=%d)", ret)
            return False

        logger.info("Seccomp filter applied — blocked syscalls: %s", blocked)
        return True

    finally:
        lib.seccomp_release(ctx)
