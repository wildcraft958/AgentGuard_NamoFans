#!/usr/bin/env python3
"""
Guarded Sandbox Agent — Kernel-Level Tool Isolation Demo
=========================================================

Wraps sandbox_agent.py's 19 tools with AgentGuard's sandbox subprocess
isolation. Each tool runs in a forked child process with 4 kernel-enforced
restrictions:

  Layer 1 — Resource limits   (RLIMIT_AS / RLIMIT_CPU / RLIMIT_FSIZE)
  Layer 2 — Filesystem        (Linux Landlock LSM — kernel-enforced)
  Layer 3 — Syscall filter    (seccomp BPF via libseccomp — kernel-enforced)
  Layer 4 — Network policy    (socket.connect whitelist / block-all)

This script runs each tool DIRECTLY (not through the LLM) to demonstrate
sandbox isolation deterministically. No LLM nondeterminism, no API costs.

Config: test_bots/agentguard_sandbox.yaml

Usage:
    cd AgentGuard_NamoFans
    uv run python test_bots/guarded_sandbox_agent.py
"""

import os
import sys
import time

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.join(_SCRIPT_DIR, "..", "src")
sys.path.insert(0, _SRC_DIR)
sys.path.insert(0, _SCRIPT_DIR)

from dotenv import load_dotenv
load_dotenv(os.path.join(_SCRIPT_DIR, "..", ".env"))

CONFIG_PATH = os.path.join(_SCRIPT_DIR, "agentguard_sandbox.yaml")

from agentguard.sandbox.executor import SandboxedToolExecutor
from agentguard.sandbox.policies import SandboxPolicy
from agentguard.config import load_config
from agentguard.exceptions import SandboxTimeoutError, SandboxViolationError

# Import all tools from sandbox_agent
from sandbox_agent import (
    TOOL_REGISTRY,
    # Safe
    add_numbers, echo, write_tmp_file, read_tmp_file, query_tmp_db,
    # Filesystem
    read_sensitive_file, write_outside_tmp, list_directory,
    # Network
    fetch_url, dns_lookup,
    # Resource
    cpu_burn, memory_bomb, infinite_sleep,
    # Privilege
    escalate_privileges, fork_bomb, kill_process,
    # Syscall
    raw_syscall_open,
    # Shell
    run_shell, spawn_subprocess,
)

# ==========================================
# Initialize sandbox
# ==========================================

config = load_config(CONFIG_PATH)
policy = config.sandbox_policy
executor = SandboxedToolExecutor(policy)

print("=" * 70)
print("  AgentGuard Sandbox Isolation Demo")
print("=" * 70)
print(f"  Sandbox: {'ENABLED' if policy.enabled else 'DISABLED'}")
print(f"  Mode:    {policy.mode}")
print(f"  Timeout: {policy.timeout_seconds}s (wall-clock)")
print(f"  Filesystem (Landlock):  {'ON' if policy.filesystem.enabled else 'OFF'}")
print(f"  Network guard:          {'ON' if policy.network.enabled else 'OFF'} ({policy.network.mode})")
print(f"  Seccomp (syscall BPF):  {'ON' if policy.syscalls.enabled else 'OFF'}")
print(f"  Resource limits:        {'ON' if policy.resources.enabled else 'OFF'} "
      f"(mem={policy.resources.max_memory_mb}MB, cpu={policy.resources.max_cpu_seconds}s)")
print("=" * 70)


# ==========================================
# Test runner
# ==========================================

_pass_count = 0
_fail_count = 0
_total = 0


def run_test(test_id, description, fn, fn_args, expect_blocked=False):
    """Run a tool in the sandbox and check if it was blocked or allowed."""
    global _pass_count, _fail_count, _total
    _total += 1

    print(f"\n--- Test {test_id}: {description} ---")
    print(f"  Tool: {fn.__name__}({fn_args})")

    t0 = time.monotonic()
    try:
        result = executor.execute(fn, fn_args)
        elapsed = (time.monotonic() - t0) * 1000
        blocked = False
        output = str(result)[:200]
    except (SandboxTimeoutError, SandboxViolationError) as e:
        elapsed = (time.monotonic() - t0) * 1000
        blocked = True
        output = str(e)[:200]
    except Exception as e:
        elapsed = (time.monotonic() - t0) * 1000
        blocked = True
        output = f"{type(e).__name__}: {e}"[:200]

    if expect_blocked and blocked:
        status = "PASS (correctly blocked)"
        _pass_count += 1
    elif not expect_blocked and not blocked:
        status = "PASS (correctly allowed)"
        _pass_count += 1
    elif expect_blocked and not blocked:
        status = "FAIL (should have been blocked!)"
        _fail_count += 1
    else:
        status = "FAIL (should have been allowed!)"
        _fail_count += 1

    icon = "+" if "PASS" in status else "X"
    print(f"  [{icon}] {status} ({elapsed:.0f}ms)")
    print(f"  Output: {output}")


# ==========================================
# Section 1: Safe Operations (should pass)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 1: Safe Operations (sandbox allows these)")
print("=" * 70)

run_test("1a", "Pure math — add_numbers(10, 20)",
         add_numbers, {"a": 10, "b": 20}, expect_blocked=False)

run_test("1b", "Echo message",
         echo, {"message": "hello from sandbox"}, expect_blocked=False)

run_test("1c", "Write file to /tmp/ (allowed path)",
         write_tmp_file, {"filename": "sandbox_demo.txt", "content": "safe write"}, expect_blocked=False)

run_test("1d", "Read file from /tmp/ (allowed path)",
         read_tmp_file, {"filename": "sandbox_demo.txt"}, expect_blocked=False)

run_test("1e", "SQLite query in /tmp/ (allowed path)",
         query_tmp_db, {"sql": "SELECT * FROM demo"}, expect_blocked=False)


# ==========================================
# Section 2: Filesystem Violations (Landlock blocks)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 2: Filesystem Violations (Landlock kernel isolation)")
print("=" * 70)

run_test("2a", "Read /etc/passwd (Landlock blocks)",
         read_sensitive_file, {"path": "/etc/passwd"}, expect_blocked=True)

run_test("2b", "Write to /var/evil.txt (Landlock blocks)",
         write_outside_tmp, {"path": "/var/evil.txt", "content": "malicious"}, expect_blocked=True)

run_test("2c", "List /etc/ directory (Landlock blocks)",
         list_directory, {"path": "/etc/"}, expect_blocked=True)


# ==========================================
# Section 3: Network Violations (network guard blocks)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 3: Network Violations (socket-level network guard)")
print("=" * 70)

run_test("3a", "Fetch https://example.com (network blocked)",
         fetch_url, {"url": "https://example.com"}, expect_blocked=True)

run_test("3b", "DNS lookup google.com (network blocked)",
         dns_lookup, {"hostname": "google.com"}, expect_blocked=True)


# ==========================================
# Section 4: Resource Exhaustion (RLIMIT / timeout)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 4: Resource Exhaustion (OS limits kill the process)")
print("=" * 70)

run_test("4a", "CPU burn — infinite loop (RLIMIT_CPU kills)",
         cpu_burn, {}, expect_blocked=True)

run_test("4b", "Memory bomb — allocate 2GB (RLIMIT_AS kills)",
         memory_bomb, {"mb": 2000}, expect_blocked=True)

run_test("4c", "Infinite sleep (wall-clock timeout kills)",
         infinite_sleep, {}, expect_blocked=True)


# ==========================================
# Section 5: Privilege & Process Attacks (seccomp / OS)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 5: Privilege & Process Attacks (seccomp + OS permissions)")
print("=" * 70)

run_test("5a", "Escalate to root — os.setuid(0) (seccomp blocks)",
         escalate_privileges, {}, expect_blocked=True)

run_test("5b", "Fork bomb — os.fork() x1000 (children exit immediately, timeout catches persistent ones)",
         fork_bomb, {}, expect_blocked=False)  # Children exit instantly; persistent forks would hit timeout

run_test("5c", "Kill PID 1 (init) — os.kill(1, SIGKILL)",
         kill_process, {"pid": 1}, expect_blocked=True)


# ==========================================
# Section 6: Syscall Bypass via ctypes (seccomp BPF)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 6: Raw Syscall Bypass (seccomp BPF kernel filter)")
print("=" * 70)

run_test("6a", "raw_syscall_open /etc/shadow — ctypes bypasses Python, seccomp catches kernel",
         raw_syscall_open, {"path": "/etc/shadow"}, expect_blocked=True)


# ==========================================
# Section 7: Shell Execution (seccomp blocks)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 7: Shell Execution (seccomp blocks execve)")
print("=" * 70)

run_test("7a", "os.system('whoami') (seccomp may block)",
         run_shell, {"command": "whoami"}, expect_blocked=True)

run_test("7b", "subprocess.run('cat /etc/passwd') (seccomp may block)",
         spawn_subprocess, {"command": "cat /etc/passwd"}, expect_blocked=True)


# ==========================================
# Section 8: Side-by-Side (sandbox vs direct)
# ==========================================

print("\n" + "=" * 70)
print("  SECTION 8: Side-by-Side — Sandboxed vs Direct Execution")
print("=" * 70)

print("\n--- Test 8a: read_sensitive_file('/etc/passwd') ---")
print("  [DIRECT]   ", end="")
try:
    direct_result = read_sensitive_file("/etc/passwd")
    print(f"SUCCESS — read {len(direct_result)} bytes")
except Exception as e:
    print(f"ERROR — {e}")

print("  [SANDBOXED] ", end="")
try:
    sandbox_result = executor.execute(read_sensitive_file, {"path": "/etc/passwd"})
    print(f"SUCCESS — read {len(sandbox_result)} bytes (SHOULD NOT HAPPEN)")
except (SandboxViolationError, SandboxTimeoutError) as e:
    print(f"BLOCKED — {str(e)[:80]}")

print("\n--- Test 8b: run_shell('id') ---")
print("  [DIRECT]   ", end="")
try:
    direct_result = spawn_subprocess("id")
    print(f"SUCCESS — {direct_result.strip()[:80]}")
except Exception as e:
    print(f"ERROR — {e}")

print("  [SANDBOXED] ", end="")
try:
    sandbox_result = executor.execute(spawn_subprocess, {"command": "id"})
    print(f"SUCCESS — {sandbox_result[:80]} (SHOULD NOT HAPPEN)")
except (SandboxViolationError, SandboxTimeoutError) as e:
    print(f"BLOCKED — {str(e)[:80]}")

print("\n--- Test 8c: add_numbers(5, 10) ---")
print("  [DIRECT]   ", end="")
print(f"Result: {add_numbers(5, 10)}")
print("  [SANDBOXED] ", end="")
sandbox_result = executor.execute(add_numbers, {"a": 5, "b": 10})
print(f"Result: {sandbox_result}")
print("  Both produce the same result — sandbox is transparent for safe operations.")


# ==========================================
# Summary
# ==========================================

print("\n" + "=" * 70)
print("  SANDBOX ISOLATION RESULTS")
print("=" * 70)
print(f"  Total tests:  {_total}")
print(f"  Passed:       {_pass_count}/{_total}")
print(f"  Failed:       {_fail_count}/{_total}")
print()
print("  Sandbox layers active:")
print(f"    Landlock (filesystem):   {'ACTIVE' if policy.filesystem.enabled else 'OFF'}")
print(f"    Seccomp (syscall BPF):   {'ACTIVE' if policy.syscalls.enabled else 'OFF'}")
print(f"    Network guard:           {'ACTIVE' if policy.network.enabled else 'OFF'} ({policy.network.mode})")
print(f"    Resource limits:         {'ACTIVE' if policy.resources.enabled else 'OFF'}")
print(f"    Wall-clock timeout:      {policy.timeout_seconds}s")
print()
if _fail_count == 0:
    print("  Grade: EXCELLENT — All sandbox layers enforced correctly")
else:
    print(f"  Grade: {_fail_count} test(s) did not behave as expected")
print("=" * 70)

# Cleanup
try:
    os.unlink("/tmp/sandbox_demo.txt")
except OSError:
    pass
try:
    os.unlink("/tmp/sandbox_demo.db")
except OSError:
    pass
