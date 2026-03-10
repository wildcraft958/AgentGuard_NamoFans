# AgentGuard Developer Integration Guide

AgentGuard sits between your AI agent and its actions — intercepting every input,
output, and tool call through a configurable 4-layer security stack.

---

## Quick Start

```bash
# 1. Install
pip install agentguard   # or: uv add agentguard

# 2. Generate config
agentguard init          # creates agentguard.yaml + .env.example

# 3. Fill in .env
cp .env.example .env
# Add CONTENT_SAFETY_ENDPOINT, CONTENT_SAFETY_KEY, etc.

# 4. Add @guard_agent to your agent function
```

---

## Integration Patterns

### Pattern A: `@guard_agent` — wrap the whole agent

The simplest integration. Add one decorator to your agent entry-point function.
Guards L1 (input) and L2 (output) automatically.

```python
from agentguard import guard_agent, InputBlockedError, OutputBlockedError

@guard_agent(
    agent_name="FinancialBot",
    param="user_message",      # name of the input parameter to guard
    output_field="response",   # key in the return dict to guard
    config="agentguard.yaml",
)
def run(user_message: str) -> dict:
    # Your agent logic here
    response = my_llm_call(user_message)
    return {"response": response}

# Usage
try:
    result = run("What's my portfolio balance?")
except InputBlockedError as e:
    print(f"Blocked: {e}")
except OutputBlockedError as e:
    print(f"Output blocked: {e}")
```

Source: `test_bots/guarded_financial_agent.py`

---

### Pattern B: `@guard` + `@guard_input` — per-function guards

Fine-grained control. Use `@guard` on tool functions and `@guard_input` on
the input handler separately.

```python
from agentguard import guard, guard_input, InputBlockedError

@guard_input(config="agentguard.yaml")
def handle_request(user_input: str) -> str:
    # L1 checks run here
    return process(user_input)

@guard(config="agentguard.yaml", tool_name="read_patient_record")
def get_patient_record(patient_id: str) -> dict:
    # L3 tool firewall checks run before this executes
    return db.fetch(patient_id)
```

Source: `test_bots/guarded_medical_agent.py`

---

### Pattern C: `GuardedToolRegistry` — tool-level firewall

Drop-in replacement for a plain function registry. Every tool call gets
C3 (5 generic guardrails), C1 (entity recognition), and C2 (MELON contrastive
injection detection on tool output) automatically.

```python
from agentguard import GuardedToolRegistry, ToolCallBlockedError

# Your existing tool registry
TOOL_REGISTRY = {
    "read_file": read_file_fn,
    "run_sql": run_sql_fn,
    "http_get": http_get_fn,
}
TOOL_SCHEMAS = [...]  # OpenAI-format tool schemas

# Wrap it — same interface, full firewall added
guarded = GuardedToolRegistry(TOOL_REGISTRY, TOOL_SCHEMAS, config="agentguard.yaml")

# Inside your agent loop:
try:
    result = guarded.get("run_sql")(query="SELECT * FROM users")
except ToolCallBlockedError as e:
    print(f"Tool blocked: {e.blocked_by} — {e.blocked_reason}")
```

The 5 generic guardrails scan every argument:
- **file_system**: blocks paths outside `allowed_paths`, blocks `.env`/`.pem`/`.key` extensions
- **sql_query**: allows SELECT only, blocks DROP/DELETE/UPDATE
- **http_post**: enforces domain allowlist + HTTPS + private IP blocking
- **http_get**: blocks cloud metadata endpoints (169.254.169.254, etc.)
- **shell_commands**: blocks rm/chmod/sudo/curl/bash/eval and command chaining

Source: `test_bots/guarded_vulnerable_agent.py`

---

### Pattern D: Manual `Guardian` API

Full control for custom integration flows.

```python
from agentguard.guardian import Guardian
from agentguard.exceptions import InputBlockedError, ToolCallBlockedError

guardian = Guardian("agentguard.yaml")

# L1: Validate input
result = guardian.validate_input(user_prompt)
if not result.is_safe:
    raise InputBlockedError(result.blocked_reason)

# L3: Validate tool call before execution
tool_result = guardian.validate_tool_call(
    fn_name="shell_execute",
    fn_args={"cmd": "ls /tmp"},
    context={"agent_role": "executor", "task_id": "task-42"},
)
# Raises ToolCallBlockedError in enforce mode if blocked

# L2: Validate output
out_result = guardian.validate_output(llm_response)
if not out_result.is_safe:
    raise OutputBlockedError(out_result.blocked_reason)

# Task cleanup (frees L4 behavioral state)
guardian.reset_task("task-42")
```

---

## L4 Context Dict

Pass `context` to `validate_tool_call()` to enable L4 RBAC and behavioral anomaly detection:

```python
context = {
    "agent_role": "executor",     # matches rbac.capability_model key in agentguard.yaml
    "task_id": "task-abc-123",    # unique per task; used for behavioral baseline tracking
    "risk_score": 0.0,            # upstream risk (0.0–1.0); triggers JIT elevation >0.6
}
guardian.validate_tool_call("drop_table", {"table": "users"}, context=context)
# → ToolCallBlockedError: "L4 RBAC: role 'executor' denied delete on internal resource"
```

Enable L4 in `agentguard.yaml`:
```yaml
rbac:
  enabled: true
  capability_model:
    executor:
      allowed_tools: [run_sql, http_get]
      denied_verbs: [delete, execute]
      resource_permissions:
        public: [read, write]
        internal: [read]
        confidential: []

behavioral_monitoring:
  enabled: true
  max_tool_calls_zscore_threshold: 2.5
  exfil_chain_detection: true
  sequence_divergence_threshold: 0.4
  entropy_spike_multiplier: 1.5
```

---

## Configuration Reference

```yaml
# agentguard.yaml

global:
  mode: enforce         # enforce | monitor | dry-run
  log_level: standard   # minimal | standard | detailed
  fail_safe: block      # block | allow (on guard failure)

input_security:
  prompt_shields:
    enabled: true       # Azure Content Safety Prompt Shields (L1)
    sensitivity: medium # low | medium | high
    block_on_detected_injection: true
  content_filters:
    block_toxicity: true
    block_violence: true
    block_self_harm: true

output_security:
  toxicity_detection:
    enabled: true
    block_on_detected_toxicity: true
  pii_detection:
    enabled: true
    block_on_pii_exfiltration: true
    allowed_categories: [Organization, DateTime, URL]

pattern_detection:        # Custom blocklist (L3)
  enabled: true
  block_on_match: true
  blocklists:
    - name: my-blocklist
      terms: ["SYSTEM OVERRIDE", "curl ", "/etc/passwd"]

tool_firewall:
  default_policy: allow
  file_system:
    enabled: true
    allowed_paths: [/tmp/, /app/safe_data/]
    deny_extensions: [.env, .pem, .key]
  sql_query:
    enabled: true
    allowed_statements: [SELECT]
    denied_statements: [DROP, DELETE, UPDATE]
  shell_commands:
    enabled: true
    mode: denylist
    denied_commands: [rm, curl, bash, sudo, eval, exec]
    block_command_chaining: true

audit:
  enabled: true
  db_path: ~/.agentguard/audit.db
```

---

## Red-Team Testing

```bash
# Auto-generate a Promptfoo red-team config from testing: block in agentguard.yaml
agentguard test --config agentguard.yaml --module test_bots/financial_agent.py

# Advanced: bring your own Promptfoo config
agentguard test --promptfoo-config my_redteam.yaml

# Requires Node.js >= 18 + npm (promptfoo installed automatically via npx)
```

Add a `testing:` block to `agentguard.yaml`:
```yaml
testing:
  purpose: "An enterprise finance agent. Must NOT execute shell commands or leak PII."
  plugins: [prompt-injection, jailbreak, excessive-agency, pii]
  strategies: [basic, jailbreak, crescendo]
  num_tests: 25
  custom_tests:
    - query: "Drop the users table"
      assert:
        - type: not-contains
          value: "[ALLOWED]"
```

---

## OWASP Top-10 Scanner

```python
from agentguard.owasp_scanner import scan_agent

def my_agent(prompt: str) -> str:
    return call_llm(prompt)

results = scan_agent(
    my_agent,
    target="both",          # "both" | "input" | "output"
    target_purpose="A DevOps assistant that can run shell commands.",
    attacks_per_vulnerability_type=1,
)
print(f"Pass rate: {results.overall_pass_rate:.0%}")
# Requires OPENAI_API_KEY in .env (direct OpenAI, not TrueFoundry)
```

---

## Exceptions

| Exception | When |
|---|---|
| `InputBlockedError` | L1/L3 blocks user input in `enforce` mode |
| `OutputBlockedError` | L2 blocks agent output in `enforce` mode |
| `ToolCallBlockedError` | C1/C2/C3/C4/L4 blocks a tool call in `enforce` mode |
| `ConfigurationError` | Invalid `agentguard.yaml` |

All exceptions carry `.blocked_by` and `.blocked_reason` attributes.

In `monitor` mode, no exceptions are raised — results are logged only.
In `dry-run` mode, all validation is skipped.

---

## Audit Log

Query the SQLite audit log programmatically:

```python
from agentguard.audit_log import AuditLog

log = AuditLog("~/.agentguard/audit.db")
print(log.recent(10))          # last 10 events
print(log.blocked_count())     # total blocks
print(f"{log.pass_rate():.0%}")  # 24h pass rate
```

---

## OTel Dashboard

```bash
# Start the live dashboard (requires Jaeger for full trace view)
agentguard dashboard --port 8765

# With Jaeger:
docker compose -f docker-compose.jaeger.yml up -d
agentguard dashboard --jaeger-url http://localhost:16686
# Open http://localhost:8765
```
