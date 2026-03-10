# AgentGuard: Presentation Template

---

## Slide 1: Problem Statement & Context
**What problem are you solving, and for whom?**

*   **Target User:** Enterprise AI Teams and Developers deploying Multi-Agent Systems.
*   **The Challenge:** LLM agents are prone to prompt injection, PII leakage, and unauthorized tool execution, yet security layers are often added as an afterthought or are too restrictive.
*   **Existing Gaps:** Current solutions (static filters, RBAC-only tools) are too rigid for dynamic agentic workflows or lack specialized "firewalls" for tool-calling loops.
*   **The Pain Point:** A single malicious prompt can hijack an agent to leak sensitive database information or perform destructive actions via connected tools — OWASP Agentic AI Top 10 (2025) identifies 10 such attack classes.
*   **Why Now:** As enterprises move from RAG to fully autonomous agents, the attack surface expands exponentially. Microsoft's own Agent Governance Toolkit focuses on cryptographic identity — but the LLM attack surface (prompt injection, PII leakage, indirect injection) remains unaddressed.
*   **Impact:** Without AgentGuard, enterprises face data breaches, compliance violations, and loss of trust in AI initiatives.

---

## Slide 2: Solution Overview
**What have you built?**

*   **Product:** **AgentGuard**, a Multi-Agent Security & Governance Platform.
*   **Primary Value:** "Security-as-Code" via decorators and a centralized Guardian that inspects inputs, monitors tool calls, and sanitizes outputs in real-time with a layered defense stack.
*   **The Workflow:**
    1. User input is scanned offline (33 regex patterns, <1s) + via Azure Prompt Shields (L1).
    2. Agent execution is monitored — tool calls pass through a 5-guardrail Tool Firewall + RBAC + behavioral anomaly detection (L3/L4).
    3. Agent responses are scrubbed for PII and toxicity before reaching the user (L2).
*   **Distinct Approach:** AgentGuard is **developer-centric** — one `@guard_agent` decorator wraps any existing agent without architectural changes.
*   **Proven:** 95–97.5% attack block rate across 40 adversarial tests (CRITICAL severity: 96%).

---

## Slide 3: Key Features & User Flow
**How does it work end to end?**

*   **Key Features:**
    1. **L1 Input Shielding:** Fast offline regex (0.65s avg) + Azure Prompt Shields + blocklists. Catches: prompt injection, jailbreaks, SYSTEM OVERRIDE, shell injection strings.
    2. **L2 Output Guardrails:** Azure PII detection + toxicity filtering. Blocks: credential leakage, harmful content in agent responses.
    3. **L3 Tool Firewall:** 5 generic guardrails scan every tool argument (file_system, sql_query, http_post, http_get, shell_commands) + C1 entity recognition + C2 MELON contrastive injection detection.
    4. **L4 RBAC + Behavioral Anomaly:** Zero-trust ABAC policy engine + 5-signal behavioral anomaly scorer (Z-score, Levenshtein sequence divergence, read→exfil chain, domain allowlist, Shannon entropy).
    5. **OTel Dashboard:** Live performance spans + Jaeger trace visualization at `localhost:8765`.
    6. **Red-Team CLI:** `agentguard test` auto-generates Promptfoo config from `agentguard.yaml` and fires 25+ attack scenarios.

*   **User Flow:**
    `User Input → L1 Shield → Agent Logic → L4 RBAC → L4 Behavioral → L3 Tool Firewall (C3/C1/C4/C2) → L2 Guardrail → Safe Output`

*   **Interaction:** Developers run `agentguard init` → fill `.env` → add `@guard_agent` → done.

---

## Slide 4: Architecture & Technology Approach
**How is your prototype built?**

*   **Conceptual Architecture:** Middleware-based "Guardian" pattern sitting between agent and actions.
*   **Key Components:**
    - **Guardian Class:** Core orchestrator managing the 4-layer pipeline + OTel spans + SQLite audit log.
    - **Decorator Layer:** `@guard_agent`, `@guard`, `@guard_input` connect Guardian to any Python agent.
    - **GuardedToolRegistry:** Drop-in tool dict replacement that automatically fires L3 on every call.
    - **L4 Engines:** `L4RBACEngine` (ABAC) + `BehavioralAnomalyDetector` (5 signals) operating in-process, zero external dependencies.
    - **Config Engine:** YAML-based security policies (`agentguard.yaml`), `agentguard init` for quick start.
*   **Tech Stack:**
    - **Language:** Python 3.11+, package manager: `uv`
    - **Security APIs:** Azure AI Content Safety (L1), Azure AI Language / PII (L2)
    - **Observability:** OpenTelemetry (spans + metrics) → Jaeger, SQLite audit log (compliance)
    - **Red-team:** Promptfoo (via npx), DeepTeam (OWASP scanner)
    - **LLM Gateway:** TrueFoundry (OpenAI-compatible), Gemini Flash via Vertex AI

---

## Slide 5: Design Decisions & Trade-offs

*   **ABAC over flat RBAC:** Tool access depends on *context* (resource sensitivity, upstream risk score), not just role. Role "executor" may read public data but must elevate to access confidential resources. Decided: ABAC via capability_model in YAML; external IdP (SPIFFE) is a phase-2 production concern.

*   **Dual observability (OTel + SQLite audit):** OTel carries performance spans and latency metrics for SRE dashboards. SQLite audit log captures every blocking decision for compliance forensics. Different consumers, kept separate. Trade-off: slight overhead on block paths (both write); acceptable given blocking is the exception.

*   **Offline fast-inject-detect first:** 33 curated regex patterns fire in <1ms before any Azure call. Blocks >40% of injection attempts with zero API cost. Trade-off: regex precision vs. recall — medium sensitivity tuned to minimize false positives on legitimate complex prompts.

*   **MELON contrastive detection (C2):** Compare original run vs. masked run (injection as file attachment). If tool call sequence diverges, injection confirmed. Trade-off: requires 2 LLM calls per tool output check — disabled for latency-sensitive deployments, enable for high-security medical/financial agents.

*   **Promptfoo for red-teaming:** Industry-standard attack coverage (7 plugins × 4 strategies) without building a custom fuzzer. Trade-off: Node.js dependency, first run downloads ~30s.

---

## Slide 6: Current Status, Limitations & Next Steps

*   **Fully Implemented:**
    - L1: Azure Prompt Shields + 33-pattern offline filter + custom blocklists ✅
    - L2: PII detection (Azure) + output toxicity ✅
    - L3: Tool Firewall (5 guardrails + C1 entity recognition + C2 MELON + C4 HITL/AITL) ✅
    - L4: ABAC policy engine + 5-signal behavioral anomaly detector ✅
    - SQLite audit log (compliance forensics) ✅
    - OpenTelemetry + Jaeger dashboard ✅
    - CLI: `agentguard init`, `agentguard test`, `agentguard dashboard` ✅
    - Red-team + OWASP scanner ✅

*   **Benchmark Results:**
    - **Security rate:** 95–97.5% (40-test adversarial suite)
    - **CRITICAL severity block rate:** 96%
    - **Fast-path block latency:** 0.65s avg (offline regex/blocklist)
    - **Unit test suite:** 410 tests, 0 failures

*   **Known Limitations:**
    - L4 behavioral detector uses seeded baselines (avg=5, std=2) — production needs per-agent historical data accumulation.
    - Azure API rate limits under high traffic — Redis caching is config-stubbed, not yet implemented.
    - Spotlighting (Azure AI Foundry) requires special endpoint — disabled.

*   **Next Steps:**
    - Accumulate per-agent behavioral baselines from production telemetry (OTel → ClickHouse).
    - SPIFFE/SVID integration for cryptographic agent identity (complements Microsoft Agent Governance Toolkit).
    - Textual TUI for interactive setup and attack testing.
    - Redis caching for hot-path Azure API responses.
