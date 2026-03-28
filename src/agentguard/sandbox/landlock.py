"""
AgentGuard Sandbox — Linux Landlock filesystem isolation.

Applies kernel-level, deny-by-default filesystem access control to the
current process using the Linux Landlock LSM (introduced in kernel 5.13).

Key properties:
- Self-restriction: no root privileges required.
- Kernel-enforced: cannot be bypassed from inside the sandboxed process.
- Additive allow-list: everything not explicitly allowed is denied.

Falls back gracefully (logs a warning) on kernels that do not support Landlock.
"""

import ctypes
import errno
import logging
import os

logger = logging.getLogger("agentguard.sandbox.landlock")

# ── Linux syscall numbers (x86_64) ────────────────────────────────────────────
_SYS_LANDLOCK_CREATE_RULESET = 444
_SYS_LANDLOCK_ADD_RULE = 445
_SYS_LANDLOCK_RESTRICT_SELF = 446

# ── prctl ─────────────────────────────────────────────────────────────────────
_PR_SET_NO_NEW_PRIVS = 38

# ── Landlock ABI v1–v3 filesystem access-right flags ─────────────────────────
_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_CHAR = 1 << 6
_FS_MAKE_DIR = 1 << 7
_FS_MAKE_REG = 1 << 8
_FS_MAKE_SOCK = 1 << 9
_FS_MAKE_FIFO = 1 << 10
_FS_MAKE_BLOCK = 1 << 11
_FS_MAKE_SYM = 1 << 12
_FS_REFER = 1 << 13
_FS_TRUNCATE = 1 << 14

# Ruleset handles all known access rights so the kernel can restrict them all.
_ALL_FS_ACCESS = (
    _FS_EXECUTE
    | _FS_WRITE_FILE
    | _FS_READ_FILE
    | _FS_READ_DIR
    | _FS_REMOVE_DIR
    | _FS_REMOVE_FILE
    | _FS_MAKE_CHAR
    | _FS_MAKE_DIR
    | _FS_MAKE_REG
    | _FS_MAKE_SOCK
    | _FS_MAKE_FIFO
    | _FS_MAKE_BLOCK
    | _FS_MAKE_SYM
    | _FS_REFER
    | _FS_TRUNCATE
)

# Access rights for read-only paths
_READ_ONLY = _FS_EXECUTE | _FS_READ_FILE | _FS_READ_DIR

# Access rights for read-write paths
_READ_WRITE = (
    _FS_EXECUTE
    | _FS_WRITE_FILE
    | _FS_READ_FILE
    | _FS_READ_DIR
    | _FS_REMOVE_FILE
    | _FS_MAKE_REG
    | _FS_MAKE_DIR
    | _FS_TRUNCATE
)

_LANDLOCK_RULE_PATH_BENEATH = 1

# ── C structs (must match kernel ABI exactly) ─────────────────────────────────


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneathAttr(ctypes.Structure):
    # __attribute__((packed)) in kernel header — no alignment padding
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


# ── libc handle ───────────────────────────────────────────────────────────────
_libc = None


def _get_libc():
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL("libc.so.6", use_errno=True)
        _libc.syscall.restype = ctypes.c_long
        _libc.prctl.restype = ctypes.c_int
    return _libc


def _syscall(nr: int, *args) -> int:
    return _get_libc().syscall(ctypes.c_long(nr), *args)


# ── Public API ────────────────────────────────────────────────────────────────


def apply_landlock(fs_policy) -> bool:
    """
    Apply Landlock filesystem restrictions to the current process.

    Must be called from inside the sandboxed subprocess before the tool runs.
    After this call, the process can only access paths explicitly listed in
    fs_policy.allowed_read and fs_policy.allowed_write.

    Args:
        fs_policy: FilesystemPolicy instance.

    Returns:
        True  — Landlock was applied.
        False — Landlock unavailable or a non-fatal error occurred.
    """
    libc = _get_libc()

    # PR_SET_NO_NEW_PRIVS is mandatory before landlock_restrict_self.
    ret = libc.prctl(
        ctypes.c_int(_PR_SET_NO_NEW_PRIVS),
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if ret != 0:
        err = ctypes.get_errno()
        logger.warning(
            "prctl(PR_SET_NO_NEW_PRIVS) failed (errno=%d: %s) — Landlock skipped",
            err,
            os.strerror(err),
        )
        return False

    # Create a ruleset that handles all known FS access rights.
    attr = _RulesetAttr(handled_access_fs=_ALL_FS_ACCESS)
    ruleset_fd = _syscall(
        _SYS_LANDLOCK_CREATE_RULESET,
        ctypes.byref(attr),
        ctypes.c_size_t(ctypes.sizeof(attr)),
        ctypes.c_uint32(0),
    )

    if ruleset_fd < 0:
        err = ctypes.get_errno()
        if err in (errno.ENOSYS, errno.EOPNOTSUPP):
            logger.info(
                "Landlock not supported by this kernel (errno=%d) — skipping",
                err,
            )
        else:
            logger.error(
                "landlock_create_ruleset failed (errno=%d: %s)",
                err,
                os.strerror(err),
            )
        return False

    applied = False
    try:
        for path in fs_policy.allowed_read:
            _add_path_rule(ruleset_fd, path, _READ_ONLY)

        for path in fs_policy.allowed_write:
            _add_path_rule(ruleset_fd, path, _READ_WRITE)

        ret = _syscall(
            _SYS_LANDLOCK_RESTRICT_SELF,
            ctypes.c_int(ruleset_fd),
            ctypes.c_uint32(0),
        )
        if ret != 0:
            err = ctypes.get_errno()
            logger.error(
                "landlock_restrict_self failed (errno=%d: %s)",
                err,
                os.strerror(err),
            )
        else:
            logger.info(
                "Landlock applied — read: %s | write: %s",
                fs_policy.allowed_read,
                fs_policy.allowed_write,
            )
            applied = True
    finally:
        os.close(ruleset_fd)

    return applied


def _add_path_rule(ruleset_fd: int, path: str, access_rights: int):
    """Open path with O_PATH and add a Landlock path-beneath rule."""
    O_PATH = 0o4000000  # 0x200000 on x86_64
    O_CLOEXEC = 0o2000000  # 0x80000

    try:
        fd = os.open(path, O_PATH | O_CLOEXEC)
    except OSError as e:
        logger.debug("Landlock: skipping missing path '%s' (%s)", path, e)
        return

    try:
        path_attr = _PathBeneathAttr(
            allowed_access=access_rights,
            parent_fd=fd,
        )
        ret = _syscall(
            _SYS_LANDLOCK_ADD_RULE,
            ctypes.c_int(ruleset_fd),
            ctypes.c_int(_LANDLOCK_RULE_PATH_BENEATH),
            ctypes.byref(path_attr),
            ctypes.c_uint32(0),
        )
        if ret != 0:
            err = ctypes.get_errno()
            logger.warning(
                "Landlock: add_rule failed for '%s' (errno=%d: %s)",
                path,
                err,
                os.strerror(err),
            )
    finally:
        os.close(fd)
