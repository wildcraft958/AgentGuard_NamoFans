"""
AgentGuard Sandbox — socket-level network policy enforcement.

Monkey-patches socket.socket.connect in the subprocess to enforce an
application-layer network whitelist/block-all policy.

This is a Python-layer guard (not kernel-level network namespaces), but it's
effective for all well-behaved Python tool code. For kernel-level isolation,
run AgentGuard inside a NemoClaw container or network namespace.

Supports:
- "block_all"  — refuse every outbound connection
- "whitelist"  — allow only connections to allowed_hosts:allowed_ports
"""

import fnmatch
import ipaddress
import logging
import socket as _socket_module
from typing import List

logger = logging.getLogger("agentguard.sandbox.network")


def apply_network_guard(network_policy) -> None:
    """
    Patch socket.socket.connect in the current process to enforce policy.

    Must be called from inside the sandboxed subprocess.

    Args:
        network_policy: NetworkPolicy instance.
    """
    if network_policy.mode == "block_all":
        _install_block_all()
        logger.info("Network guard: BLOCK_ALL — all outbound connections refused")

    elif network_policy.mode == "whitelist":
        _install_whitelist(network_policy.allowed_hosts, network_policy.allowed_ports)
        logger.info(
            "Network guard: WHITELIST — allowed hosts=%s ports=%s",
            network_policy.allowed_hosts, network_policy.allowed_ports,
        )

    else:
        logger.warning(
            "Network guard: unknown mode '%s' — no policy applied",
            network_policy.mode,
        )


# ── Patch implementations ─────────────────────────────────────────────────────

def _install_block_all() -> None:
    """Replace socket.connect, bind, and listen with functions that always raise."""
    def _blocked_connect(self, address):
        raise ConnectionRefusedError(
            f"[AgentGuard Sandbox] Outbound connection blocked (mode=block_all). "
            f"Attempted: {address}"
        )

    def _blocked_bind(self, address):
        raise ConnectionRefusedError(
            f"[AgentGuard Sandbox] Socket bind blocked (mode=block_all). "
            f"Attempted: {address}"
        )

    def _blocked_listen(self, backlog=0):
        raise ConnectionRefusedError(
            "[AgentGuard Sandbox] Socket listen blocked (mode=block_all)."
        )

    _socket_module.socket.connect = _blocked_connect
    _socket_module.socket.bind = _blocked_bind
    _socket_module.socket.listen = _blocked_listen


def _install_whitelist(allowed_hosts: List[str], allowed_ports: List[int]) -> None:
    """Replace socket.connect with a whitelist-checking wrapper."""
    _original = _socket_module.socket.connect

    def _guarded(self, address):
        if isinstance(address, (tuple, list)) and len(address) >= 2:
            host, port = str(address[0]), int(address[1])
            if not _is_allowed(host, port, allowed_hosts, allowed_ports):
                raise ConnectionRefusedError(
                    f"[AgentGuard Sandbox] Connection to {host}:{port} blocked. "
                    f"Not in network whitelist. Allowed: hosts={allowed_hosts} ports={allowed_ports}"
                )
        return _original(self, address)

    _socket_module.socket.connect = _guarded


# ── Allow-check helper ────────────────────────────────────────────────────────

def _is_allowed(
    host: str,
    port: int,
    allowed_hosts: List[str],
    allowed_ports: List[int],
) -> bool:
    """Return True if host:port is permitted by the whitelist policy."""
    # Always allow loopback (needed for local IPC, Unix sockets, etc.)
    try:
        addr = ipaddress.ip_address(host)
        if addr.is_loopback:
            return True
    except ValueError:
        pass  # hostname, not IP — continue to pattern matching

    # Port check
    if allowed_ports and port not in allowed_ports:
        return False

    # Host check (empty allowed_hosts = allow all hosts on allowed ports)
    if not allowed_hosts:
        return True

    for pattern in allowed_hosts:
        if fnmatch.fnmatch(host, pattern):
            return True
        # "*.example.com" also matches "example.com" itself
        if pattern.startswith("*.") and host == pattern[2:]:
            return True

    return False
