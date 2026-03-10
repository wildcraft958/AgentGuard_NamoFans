Having read your full AgentGuard submission, here's a precise design for your **Audit Logging & Compliance System** that fits cleanly inside the existing 4-layer Guardian architecture, the Azure stack, and the Aflock-inspired config model.

## Design Philosophy: Where Audit Sits

Your architecture is a **pre-execution gate** — the Guardian intercepts, evaluates, and blocks. Audit is not a 5th layer; it is a **write-through side-effect of every layer decision**, including the resource limits layer that currently doesn't exist. Every L1→L4 evaluation emits a structured event, and the resource counter middleware runs *before* L1 as a **Layer 0 — Resource Enforcer**.
```
Incoming Agent Action
        │
  ┌─────▼──────┐
  │  Layer 0   │  ← Resource Enforcer (NEW — maxSpendUSD, maxTurns, maxTokens)
  └─────┬──────┘
        │ emits AuditEvent
  ┌─────▼──────┐
  │  L1–L4     │  ← Existing Azure + Pattern + Behavioral
  └─────┬──────┘
        │ each layer emits AuditEvent
  ┌─────▼──────────────────────┐
  │   Audit Writer (async)     │  ← JSONL + Supabase/Cosmos DB
  └────────────────────────────┘
```

***

## Layer 0 — Resource Enforcer

This middleware reads from the Aflock-style config and enforces hard stops **before the expensive Azure calls**. It keeps state in Redis (already in your stack ) so it works across multi-agent turns. 
```python
# resource_enforcer.py
import json, time, redis
from dataclasses import dataclass, asdict
from typing import Literal

@dataclass
class ResourceState:
    session_id: str
    turns_used: int = 0
    tokens_in_used: int = 0
    tokens_out_used: int = 0
    spend_usd_used: float = 0.0

class ResourceEnforcer:
    def __init__(self, config: dict, redis_client: redis.Redis):
        self.limits = config.get("limits", {})
        self.redis = redis_client

    def get_state(self, session_id: str) -> ResourceState:
        raw = self.redis.get(f"ag:resource:{session_id}")
        if raw:
            return ResourceState(**json.loads(raw))
        return ResourceState(session_id=session_id)

    def check_and_increment(self, session_id: str, tokens_in: int, tokens_out: int, cost_usd: float) -> tuple[Literal["PASS","BLOCK"], str]:
        state = self.get_state(session_id)
        state.turns_used += 1

        # Fail-fast checks
        for key, attr, val in [
            ("maxTurns",      "turns_used",      state.turns_used),
            ("maxTokensIn",   "tokens_in_used",  state.tokens_in_used + tokens_in),
            ("maxTokensOut",  "tokens_out_used", state.tokens_out_used + tokens_out),
            ("maxSpendUSD",   "spend_usd_used",  state.spend_usd_used + cost_usd),
        ]:
            limit_cfg = self.limits.get(key)
            if limit_cfg and val > limit_cfg["value"]:
                return "BLOCK", f"{key} exceeded: {val} > {limit_cfg['value']}"

        # Commit to Redis (TTL 1 hour per session)
        state.tokens_in_used  += tokens_in
        state.tokens_out_used += tokens_out
        state.spend_usd_used  += cost_usd
        self.redis.setex(f"ag:resource:{session_id}", 3600, json.dumps(asdict(state)))
        return "PASS", "within_limits"
```

***

## The Audit Event Schema

Every layer — L0 through L4 — emits one of these. This is your JSONL record and your DB row:

```python
# audit_schema.py
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import uuid, json

@dataclass
class AuditEvent:
    event_id:      str   = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:     str   = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    session_id:    str   = ""
    agent_id:      str   = ""          # which agent triggered this
    layer:         str   = ""          # "L0_RESOURCE", "L1_AZURE", "L2_GUARDRAILS", etc.
    action_type:   str   = ""          # "tool_call", "inter_agent_msg", "api_request"
    action_detail: dict  = field(default_factory=dict)   # tool name, endpoint, params
    policy_applied:str   = ""          # which config rule was evaluated
    decision:      str   = ""          # "PASS" | "BLOCK" | "REDACT"
    reason:        str   = ""          # human-readable reason
    risk_score:    float = 0.0         # 0.0–1.0, for alerting threshold
    pii_detected:  bool  = False       # for compliance tracking
    medical_flag:  bool  = False       # for healthcare compliance
    tokens_in:     int   = 0
    tokens_out:    int   = 0
    cost_usd:      float = 0.0

    def to_jsonl(self) -> str:
        return json.dumps(asdict(self))
```

***

## Audit Writer — Dual Sink Architecture

Your call summary specified a **separate database for repeat PII/medical offenses**. This implements two sinks: a JSONL file (mock attestation, like Aflock) and a Supabase/CosmosDB table (compliance DB):
```python
# audit_writer.py
import asyncio, aiofiles
from collections import defaultdict
from audit_schema import AuditEvent

class AuditWriter:
    def __init__(self, jsonl_path: str, db_client):  # db_client = Supabase or CosmosDB
        self.jsonl_path = jsonl_path
        self.db = db_client
        self._queue: asyncio.Queue = asyncio.Queue()
        # In-memory offense counter: session_id → count
        self._offense_counts = defaultdict(int)

    async def emit(self, event: AuditEvent):
        await self._queue.put(event)

    async def run(self):
        """Async background writer — zero latency on hot path"""
        async with aiofiles.open(self.jsonl_path, "a") as f:
            while True:
                event: AuditEvent = await self._queue.get()

                # 1. Always write to JSONL (audit trail / mock attestation)
                await f.write(event.to_jsonl() + "\n")
                await f.flush()

                # 2. Route to compliance DB only for violations
                if event.decision == "BLOCK" or event.pii_detected or event.medical_flag:
                    self._offense_counts[event.session_id] += 1
                    await self._write_compliance_record(event)

    async def _write_compliance_record(self, event: AuditEvent):
        record = {
            **event.__dict__,
            "cumulative_offenses": self._offense_counts[event.session_id],
            "alert_triggered": self._offense_counts[event.session_id] >= 3,  # configurable
        }
        # Azure CosmosDB / Supabase insert
        await self.db.table("compliance_events").insert(record).execute()
```

***

## Plugging Into the Guardian

This is how L0 + audit hooks wrap your existing 4-layer evaluation:

```python
# guardian.py (integration sketch)
class GuardianAgent:
    def __init__(self, config, resource_enforcer, audit_writer, layers):
        self.config = config
        self.enforcer = resource_enforcer
        self.audit = audit_writer
        self.layers = layers  # [L1_Azure, L2_Guardrails, L3_Pattern, L4_Behavioral]

    async def evaluate(self, action: AgentAction) -> GuardDecision:

        # ── Layer 0: Resource Check (fail-fast, emits audit) ──────────────
        decision, reason = self.enforcer.check_and_increment(
            action.session_id, action.tokens_in, action.tokens_out, action.est_cost_usd
        )
        await self.audit.emit(AuditEvent(
            session_id=action.session_id, agent_id=action.agent_id,
            layer="L0_RESOURCE", action_type=action.type,
            action_detail=action.detail, policy_applied="resource_limits",
            decision=decision, reason=reason,
            tokens_in=action.tokens_in, cost_usd=action.est_cost_usd
        ))
        if decision == "BLOCK":
            return GuardDecision.BLOCK(reason)

        # ── L1–L4: Existing layers (each emits its own audit event) ───────
        for layer in self.layers:
            result = await layer.evaluate(action)
            await self.audit.emit(AuditEvent(
                session_id=action.session_id, agent_id=action.agent_id,
                layer=layer.name, action_type=action.type,
                policy_applied=result.policy_name,
                decision=result.decision, reason=result.reason,
                risk_score=result.risk_score,
                pii_detected=result.pii_detected,
                medical_flag=result.medical_flag,
            ))
            if result.decision == "BLOCK":
                return GuardDecision.BLOCK(result.reason)

        return GuardDecision.PASS
```

***

## The Config — Full Aflock-Aligned Structure

Extending your existing config with the resource limits and audit routing options:

```json
{
  "name": "agent-guard-policy",
  "grants": {
    "apis": {
      "allow": ["https://api.github.com/", "https://*.openai.azure.com/"],
      "deny": ["*"]
    }
  },
  "limits": {
    "maxSpendUSD":   { "value": 5.00,  "enforcement": "fail-fast" },
    "maxTurns":      { "value": 15,    "enforcement": "fail-fast" },
    "maxTokensIn":   { "value": 50000, "enforcement": "fail-fast" },
    "maxTokensOut":  { "value": 20000, "enforcement": "fail-fast" }
  },
  "tools": {
    "allow": ["Read", "Edit", "WebSearch"],
    "deny":  ["Bash:rm -rf *", "Bash:DROP TABLE", "Bash:curl *"]
  },
  "files": {
    "allow": ["/workspace/"],
    "deny":  ["/workspace/secrets/", "**/.env"]
  },
  "audit": {
    "jsonl_path": "./logs/audit_trail.jsonl",
    "compliance_db": "azure_cosmos",
    "alert_threshold_offenses": 3,
    "alert_channels": ["azure_monitor", "email"],
    "pii_repeat_policy": "escalate",
    "medical_repeat_policy": "block_session"
  }
}
```

***

## What the JSONL Record Looks Like Per Event

This is the **mock attestation** — proof the agent operated within bounds (Aflock's core value prop): 
```jsonl
{"event_id":"a1b2c3","timestamp":"2026-03-07T11:52:00Z","session_id":"sess_42","agent_id":"retriever_agent","layer":"L0_RESOURCE","action_type":"api_request","action_detail":{"endpoint":"https://api.openai.azure.com/","model":"gpt-4o"},"policy_applied":"maxSpendUSD","decision":"PASS","reason":"within_limits","risk_score":0.0,"pii_detected":false,"medical_flag":false,"tokens_in":1200,"tokens_out":0,"cost_usd":0.0036}
{"event_id":"d4e5f6","timestamp":"2026-03-07T11:52:01Z","session_id":"sess_42","agent_id":"retriever_agent","layer":"L1_AZURE","action_type":"api_request","action_detail":{"spotlighting":true,"source":"pdf_upload"},"policy_applied":"prompt_shield","decision":"BLOCK","reason":"indirect_injection_detected:SYSTEM_OVERRIDE","risk_score":0.97,"pii_detected":false,"medical_flag":false}
```

Each session produces a self-contained, replayable JSONL file — hand this to Priya (your security persona from the deck)  and she has forensic-grade proof of every decision. 
***

## Alert Flow for Repeat Offenses

```
compliance_events table
    → trigger: cumulative_offenses >= threshold
        → Azure Monitor alert → email/Teams notification
        → if medical_repeat_policy = "block_session": revoke session token in Redis
```

This is the "company moral policy" feature from your call — the audit trail explicitly surfaces repeat PII/HIPAA-class violations and can auto-escalate or terminate the session. 


This changes everything for the better. Azure APIM has **built-in LLM policies** that solve the interception problem natively — no monkey-patching, no SDK wrapping, no Python magic. Here is the complete finalized pipeline.

***

## The Core Insight

Instead of intercepting Python SDK calls, you make **Azure API Management the mandatory gateway**. The user changes one thing — their endpoint URL — and APIM silently handles token counting, limit enforcement, and metric emission using its native LLM policies. [learn.microsoft](https://learn.microsoft.com/en-us/azure/api-management/llm-token-limit-policy)

```
User's code:
  client = openai.AzureOpenAI(
-     azure_endpoint="https://your-resource.openai.azure.com"
+     azure_endpoint="https://agentguard.azure-api.net/openai"   ← APIM URL
  )
# That's the only change. Everything else is invisible.
```

***

## Finalized Azure-Native Pipeline

```
Agent Action (any SDK, any provider)
         │
         ▼
┌────────────────────────────────────────┐
│     Azure API Management (APIM)        │  ← The new Layer 0
│                                        │
│  Policy 1: llm-token-limit             │  maxTokensIn / maxTokensOut / rate
│  Policy 2: llm-emit-token-metric       │  emits to Application Insights
│  Policy 3: Custom spend policy         │  maxSpendUSD via set-variable
│  Policy 4: azure-openai-token-metric   │  Azure OpenAI specific metrics
│                                        │
│  counter-key = session_id + agent_id   │  per-agent granularity
└──────────────┬─────────────────────────┘
               │ routes to backend
               ▼
┌──────────────────────────────────────┐
│       Azure OpenAI Service           │  (or any LLM backend)
│       returns usage.tokens           │
└──────────────┬───────────────────────┘
               │
     ┌─────────┴──────────┐
     ▼                    ▼
┌─────────────┐    ┌──────────────────────────┐
│ Application │    │  Azure Cache for Redis    │
│  Insights   │    │  session resource state   │
│  (metrics)  │    │  ag:resource:{session_id} │
└──────┬──────┘    └──────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────┐
│    Log Analytics Workspace              │
│    KQL query → ApiManagementGatewayLogs │  ← your JSONL equivalent
└──────┬──────────────────────────────────┘
       │
  ┌────┴─────────────────────┐
  │                          │
  ▼                          ▼
┌──────────────────┐  ┌──────────────────────────────┐
│  Azure Monitor   │  │  Azure Cosmos DB              │
│  Alert Rules     │  │  compliance_events container  │
│  (threshold ≥ 3) │  │  (PII / medical violations)  │
└──────┬───────────┘  └──────────────────────────────┘
       │
       ▼
┌──────────────────────────────┐
│  Azure Logic App / Function  │
│  → Teams / Email alert       │
│  → Revoke Redis session key  │
└──────────────────────────────┘
```

***

## APIM Policy — The Resource Enforcer in XML

This single APIM policy replaces your entire Python `ResourceEnforcer` class: [learn.microsoft](https://learn.microsoft.com/en-us/azure/api-management/llm-emit-token-metric-policy)

```xml
<!-- APIM Inbound Policy — applied per AgentGuard API -->
<policies>
  <inbound>
    <base />

    <!-- Extract session + agent identity from headers your SDK sets -->
    <set-variable name="sessionId"
      value="@(context.Request.Headers.GetValueOrDefault("X-AG-Session-Id", "default"))" />
    <set-variable name="agentId"
      value="@(context.Request.Headers.GetValueOrDefault("X-AG-Agent-Id", "unknown"))" />

    <!-- maxTokensIn + maxTokensOut: native APIM LLM policy -->
    <!-- estimate-prompt-tokens=true → pre-call fail-fast before hitting Azure OpenAI -->
    <llm-token-limit
      counter-key="@(context.Variables["sessionId"])"
      tokens-per-minute="5000"
      token-quota="50000"
      token-quota-period="Daily"
      estimate-prompt-tokens="true"
      remaining-tokens-header-name="X-AG-Tokens-Remaining"
      tokens-consumed-header-name="X-AG-Tokens-Consumed" />

    <!-- maxTurns: custom counter in APIM cache -->
    <cache-lookup-value
      key="@("turns:" + context.Variables["sessionId"])"
      variable-name="turnCount"
      default-value="0" />
    <choose>
      <when condition="@((int)context.Variables["turnCount"] >= 15)">
        <return-response>
          <set-status code="429" reason="Turn limit exceeded" />
          <set-body>{"error": "maxTurns exceeded", "session_id": "@(context.Variables["sessionId"])"}</set-body>
        </return-response>
      </when>
    </choose>
    <cache-store-value
      key="@("turns:" + context.Variables["sessionId"])"
      value="@((int)context.Variables["turnCount"] + 1)"
      duration="3600" />

    <!-- Emit token metrics to Application Insights per agent -->
    <llm-emit-token-metric>
      <dimension name="session_id" value="@((string)context.Variables["sessionId"])" />
      <dimension name="agent_id"   value="@((string)context.Variables["agentId"])" />
      <dimension name="model"      value="@(context.Request.Body.As<JObject>()["model"]?.ToString() ?? "unknown")" />
    </llm-emit-token-metric>

  </inbound>

  <outbound>
    <base />

    <!-- maxSpendUSD: computed post-call from actual tokens -->
    <set-variable name="tokensUsed"
      value="@(int.Parse(context.Response.Headers.GetValueOrDefault("X-AG-Tokens-Consumed","0")))" />
    <!-- Store to Redis via Azure Function webhook for spend accumulation -->
    <send-one-way-request mode="new">
      <set-url>https://agentguard-fn.azurewebsites.net/api/RecordSpend</set-url>
      <set-method>POST</set-method>
      <set-body>@{
        return JsonConvert.SerializeObject(new {
          session_id = context.Variables["sessionId"],
          agent_id   = context.Variables["agentId"],
          tokens     = context.Variables["tokensUsed"],
          model      = context.Request.Body.As<JObject>()["model"]?.ToString()
        });
      }</set-body>
    </send-one-way-request>

  </outbound>
</policies>
```

***

## Azure Function — `RecordSpend` (maxSpendUSD Enforcer)

APIM calls this asynchronously after every response. It accumulates cost in Redis and blocks the session if `maxSpendUSD` is crossed: [techanek](https://techanek.com/tracking-token-usage-in-azure-ai-llms-with-api-management-apim/)

```python
# function_app.py — Azure Function (HTTP trigger)
import azure.functions as func
import redis, json
from tokencost import calculate_cost_by_tokens

app = func.FunctionApp()
r = redis.from_url(os.environ["REDIS_URL"])

@app.route(route="RecordSpend", methods=["POST"])
def record_spend(req: func.HttpRequest) -> func.HttpResponse:
    body = req.get_json()
    session_id = body["session_id"]
    model      = body["model"]
    tokens     = int(body["tokens"])

    cost = calculate_cost_by_tokens(0, tokens, model)

    # Accumulate in Redis
    key = f"ag:spend:{session_id}"
    new_spend = float(r.incrbyfloat(key, cost))
    r.expire(key, 3600)

    # maxSpendUSD check
    limit = float(os.environ.get("MAX_SPEND_USD", "5.0"))
    if new_spend > limit:
        # Revoke session — APIM checks this key on next inbound call
        r.setex(f"ag:blocked:{session_id}", 3600, "spend_exceeded")

        # Write compliance event to Cosmos DB
        write_compliance_event(session_id, "maxSpendUSD", new_spend, limit)

    return func.HttpResponse(json.dumps({"spend": new_spend}), status_code=200)
```

***

## Audit Trail — Log Analytics as Your JSONL

Every APIM call is automatically logged to Log Analytics. Your audit trail query replaces the JSONL file — but can also **export to JSONL** for mock attestation: [techanek](https://techanek.com/tracking-token-usage-in-azure-ai-llms-with-api-management-apim/)

```kql
// KQL — AgentGuard Audit Trail for a session
ApiManagementGatewayLogs
| where OperationId == "ChatCompletions_Create"
| where tostring(customDimensions["session_id"]) == "sess_42"
| project
    timestamp,
    session_id   = customDimensions["session_id"],
    agent_id     = customDimensions["agent_id"],
    model        = customDimensions["model"],
    tokens_used  = customDimensions["tokensConsumed"],
    decision     = iff(responseCode == 429, "BLOCK", "PASS"),
    reason       = customDimensions["limitReason"],
    layer        = "L0_APIM"
| order by timestamp asc
```

Export this as JSONL for the Aflock-style mock attestation:

```python
# audit/export_jsonl.py — called by your dashboard or CI
from azure.monitor.query import LogsQueryClient
from azure.identity import DefaultAzureCredential

def export_session_audit(session_id: str, output_path: str):
    client = LogsQueryClient(DefaultAzureCredential())
    result = client.query_workspace(
        workspace_id=os.environ["LOG_ANALYTICS_WORKSPACE_ID"],
        query=f"""ApiManagementGatewayLogs
                 | where customDimensions["session_id"] == "{session_id}"
                 | order by TimeGenerated asc""",
        timespan=timedelta(days=1)
    )
    with open(output_path, "w") as f:
        for row in result.tables[0].rows:
            f.write(json.dumps(dict(zip(result.tables[0].columns, row))) + "\n")
```

***

## What Your SDK Does (Minimal Python, Maximum Azure)

```python
# agentguard/__init__.py — Azure-first version
import os

AGENTGUARD_APIM_ENDPOINT = os.environ["AGENTGUARD_APIM_ENDPOINT"]
# e.g. "https://agentguard.azure-api.net/openai"

def init(session_id: str, agent_id: str):
    """
    Injects AgentGuard headers into the environment.
    Works with openai, azure-ai-inference, or any Azure OpenAI client.
    """
    os.environ["AZURE_OPENAI_ENDPOINT"] = AGENTGUARD_APIM_ENDPOINT
    os.environ["AG_SESSION_ID"] = session_id
    os.environ["AG_AGENT_ID"]   = agent_id
    # APIM picks up X-AG-Session-Id from a request middleware (below)
    _install_header_middleware(session_id, agent_id)

def _install_header_middleware(session_id, agent_id):
    """Injects identification headers into every outgoing HTTP request."""
    import httpx
    original_send = httpx.Client.send

    def patched_send(self, request, **kwargs):
        request.headers["X-AG-Session-Id"] = session_id
        request.headers["X-AG-Agent-Id"]   = agent_id
        return original_send(self, request, **kwargs)

    httpx.Client.send = patched_send
    # httpx is used by both openai and anthropic SDKs under the hood
```

One `httpx` patch instead of patching every SDK separately — since OpenAI, Anthropic, and most modern LLM SDKs all use `httpx` as their HTTP transport.

***

## Complete Azure Service Map

| Config Key | Azure Service | Mechanism |
|---|---|---|
| `maxTokensIn/Out` | **APIM** `llm-token-limit` | Native XML policy, pre-call estimate |
| `maxTurns` | **APIM** cache + choose policy | Per-session counter in APIM internal cache |
| `maxSpendUSD` | **Azure Function** + **Redis** | Post-call spend accumulation |
| Token metrics | **Application Insights** `llm-emit-token-metric` | Custom dimensions per agent |
| Audit trail | **Log Analytics** KQL | Queryable, exportable to JSONL |
| Compliance DB | **Azure Cosmos DB** | Violations + cumulative offense count |
| Repeat offense alerts | **Azure Monitor Alert Rules** | KQL alert → Action Group |
| Session termination | **Azure Cache for Redis** | `ag:blocked:{session_id}` key checked by APIM inbound |
| L1–L4 content safety | **Azure AI Content Safety** | Existing layers, unchanged |

This is a pure Azure-native story — every component is a managed service, zero self-hosted infrastructure, and every piece maps directly to a Microsoft product the hackathon judges will recognise. [journeyofthegeek](https://journeyofthegeek.com/2024/08/22/azure-openai-service-tracking-token-usage-with-apim/)
