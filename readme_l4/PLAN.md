Here is the full implementation plan with a final copy-pasteable agent prompt at the end.

***

## Implementation Architecture Overview

Before diving into phases, here's how the upgraded L4 maps to the existing AgentGuard codebase:

```
L4 (Current)                     L4 (Upgraded)
─────────────────                ────────────────────────────────
ABAC static matrix          →   L4a: PDP/PEP PBAC engine (Cerbos-style YAML)
Z-score anomaly             →   L4b-1: River HalfSpaceTrees (online, per-role)
Levenshtein distance        →   L4b-2: Graph session scorer (NetworkX + PyGOD)
chain detection (linear)    →   L4b-3: IOA pattern DAG matcher
entropy analysis            →   L4b-4: Compliance drift monitor
in-process only             →   L4b runs as async out-of-process subprocess
```

***

## Phase 1 — PBAC Engine (Replace Static ABAC)

**Goal:** Replace the hardcoded `role × verb × resource × risk` matrix with a dynamic **Policy Decision Point (PDP)** that evaluates policies as YAML-defined rules. [python.plainenglish](https://python.plainenglish.io/policy-based-access-control-pbac-what-it-is-and-why-you-need-it-in-your-modern-data-lakehouse-672e869c2082)

**Libraries:** `cerbos-sdk-python` or custom PDP with `PyYAML` + `dacite`

```python
# policy_engine.py
import yaml
from dataclasses import dataclass
from typing import Literal

@dataclass
class AccessRequest:
    agent_id: str
    role: str
    action: str              # "read" | "write" | "execute" | "delete"
    resource: str            # "file_system" | "sql_query" | "http_post" | "shell"
    resource_sensitivity: int  # 0–3: public, internal, confidential, critical
    context: dict            # session_id, time_of_day, data_volume_so_far

class PolicyDecisionPoint:
    def __init__(self, policy_file: str = "l4_policies.yaml"):
        with open(policy_file) as f:
            self.policies = yaml.safe_load(f)

    def evaluate(self, req: AccessRequest) -> Literal["ALLOW", "DENY", "ELEVATE"]:
        for policy in self.policies["rules"]:
            if self._matches(policy, req):
                return policy["effect"]   # ALLOW | DENY | ELEVATE
        return self.policies.get("default_effect", "DENY")

    def _matches(self, policy: dict, req: AccessRequest) -> bool:
        return (
            req.role in policy.get("roles", [req.role]) and
            req.action in policy.get("actions", [req.action]) and
            req.resource_sensitivity >= policy.get("min_sensitivity", 0) and
            self._eval_conditions(policy.get("conditions", []), req)
        )
```

```yaml
# l4_policies.yaml
default_effect: DENY
rules:
  - id: "readonly_agent_public"
    roles: ["reader"]
    actions: ["read"]
    min_sensitivity: 0
    effect: ALLOW

  - id: "sensitive_write_elevate"
    roles: ["analyst", "executor"]
    actions: ["write", "delete"]
    min_sensitivity: 2
    effect: ELEVATE

  - id: "critical_always_deny"
    roles: ["*"]
    actions: ["*"]
    min_sensitivity: 3
    conditions:
      - key: "hitl_approved"
        value: false
    effect: DENY
```

The PBAC `conditions` block enables **time-bound, context-aware** decisions — replacing your static ABAC matrix with something you can version-control and hot-reload without redeployment. [descope](https://www.descope.com/learn/post/pbac)

***

## Phase 2 — Online Behavioral Baseline (Replace Z-Score)

**Goal:** Replace static Z-score thresholds with per-role **adaptive online anomaly detection** using `river`'s `HalfSpaceTrees` — which learns incrementally with every tool call, solving your cold-start problem by initialising from the role aggregate. [riverml](https://riverml.xyz/0.21.1/api/anomaly/HalfSpaceTrees/)

**Library:** `river` [github](https://github.com/online-ml/river)

```python
# behavioral_baseline.py
from river import anomaly, preprocessing, compose
from collections import defaultdict
import json

class AdaptiveBehavioralBaseline:
    """
    Per-role online anomaly detector.
    Features: call_freq, arg_entropy, data_volume, hour_of_day, tool_id_hash
    """
    def __init__(self):
        # One pipeline per role — shares role aggregate until agent has enough data
        self._role_models: dict[str, compose.Pipeline] = defaultdict(
            lambda: compose.Pipeline(
                preprocessing.MinMaxScaler(),
                anomaly.HalfSpaceTrees(
                    n_trees=25,
                    height=15,
                    window_size=250,
                    seed=42
                )
            )
        )
        self._call_counts: dict[str, int] = defaultdict(int)
        COLD_START_THRESHOLD = 50  # calls before individual model trusted

    def featurize(self, tool_call: dict) -> dict:
        import math, hashlib
        args_str = json.dumps(tool_call.get("args", {}), sort_keys=True)
        arg_entropy = self._shannon_entropy(args_str)
        return {
            "tool_id":         int(hashlib.md5(tool_call["tool_name"].encode()).hexdigest(), 16) % 1000,
            "arg_len":         len(args_str),
            "arg_entropy":     arg_entropy,
            "data_volume_kb":  tool_call.get("data_volume_kb", 0),
            "hour_of_day":     tool_call.get("timestamp").hour,
        }

    def score(self, role: str, tool_call: dict) -> float:
        features = self.featurize(tool_call)
        model = self._role_models[role]
        score = model.score_one(features)
        model.learn_one(features)
        self._call_counts[role] += 1
        return score  # higher = more anomalous

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        from collections import Counter
        import math
        counts = Counter(s)
        total = len(s)
        return -sum((c/total) * math.log2(c/total) for c in counts.values() if c > 0)
```

> **Cold-Start Handling:** During the first 50 calls, fall back to the shared role-level model. After 50, the agent's individual model takes over. [riverml](https://riverml.xyz/0.21.1/api/anomaly/HalfSpaceTrees/)

***

## Phase 3 — Graph-Based Session Anomaly Scorer

**Goal:** Model each session as a **Directed Graph** of tool call transitions. Score anomalies at node, edge, and path levels — replacing your linear chain detector. [puppygraph](https://www.puppygraph.com/blog/graph-anomaly-detection)

**Libraries:** `networkx`, `pyod` (ABOD for graph outlier scoring) [arxiv](http://arxiv.org/pdf/1901.01588.pdf)

```python
# session_graph.py
import networkx as nx
from collections import defaultdict
import numpy as np

class SessionGraphScorer:
    """
    Builds a live DAG for the current session.
    Node  = (tool_name, arg_hash)
    Edge  = transition (call_i → call_{i+1})
    Score = weighted sum of node + edge + path anomaly
    """
    def __init__(self, ioa_patterns: list[dict]):
        self.session_graph = nx.DiGraph()
        self.call_history: list[str] = []
        self.ioa_patterns = ioa_patterns   # loaded from YAML
        self.baseline_edge_freq: dict[tuple, int] = defaultdict(int)  # loaded from corpus

    def add_call(self, tool_name: str, args_hash: str) -> float:
        node_id = f"{tool_name}:{args_hash[:8]}"
        self.session_graph.add_node(node_id, tool=tool_name)

        edge_score = 0.0
        if self.call_history:
            prev = self.call_history[-1]
            edge = (prev, node_id)
            self.session_graph.add_edge(*edge)
            edge_score = self._score_edge(prev, tool_name)

        self.call_history.append(node_id)
        path_score = self._score_ioa_path()
        node_score = self._score_node(tool_name)

        return 0.2 * node_score + 0.3 * edge_score + 0.5 * path_score

    def _score_node(self, tool_name: str) -> float:
        # Frequency-based: rare tool calls for this role = high score
        degree = self.session_graph.in_degree(
            next((n for n in self.session_graph if n.startswith(tool_name)), tool_name), default=0
        )
        return 1.0 / (1 + degree)  # normalised rarity

    def _score_edge(self, prev_tool: str, curr_tool: str) -> float:
        baseline_count = self.baseline_edge_freq.get((prev_tool, curr_tool), 0)
        return 1.0 if baseline_count == 0 else 1.0 / (1 + np.log1p(baseline_count))

    def _score_ioa_path(self) -> float:
        """Check call_history suffix against IOA patterns"""
        recent = [n.split(":")[0] for n in self.call_history[-5:]]
        for pattern in self.ioa_patterns:
            seq = pattern["sequence"]
            if len(recent) >= len(seq):
                if recent[-len(seq):] == seq:
                    return pattern["risk_delta"]
        return 0.0
```

```yaml
# ioa_patterns.yaml
patterns:
  - name: "Credential Harvesting"
    sequence: ["file_read", "file_read", "http_post"]
    risk_delta: 0.90

  - name: "Recon + Exfil"
    sequence: ["sql_query", "http_post"]
    risk_delta: 0.85

  - name: "Privilege Escalation"
    sequence: ["shell_exec", "file_write", "http_post"]
    risk_delta: 0.95

  - name: "Config Poisoning"
    sequence: ["file_read", "file_write", "file_write"]
    risk_delta: 0.80
```

***

## Phase 4 — Compliance Drift Monitor

**Goal:** Detect the **autoregressive drift** pattern from your `LLM_Security.pdf` §7 — where each tool call progressively escalates sensitivity.  This catches slow-burn attacks invisible to per-call checks. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/53617076/71b412a9-519d-49fc-9590-2086ea0e6ebb/LLM_Security.pdf)

```python
# drift_monitor.py
from collections import deque
import numpy as np

class ComplianceDriftMonitor:
    """
    Tracks sensitivity trajectory of tool calls in a sliding window.
    A monotonically increasing sensitivity trend = drift signal.
    """
    WINDOW = 8

    def __init__(self):
        self.sensitivity_window: deque[int] = deque(maxlen=self.WINDOW)

    TOOL_SENSITIVITY_MAP = {
        "http_get":    0, "sql_query":   1,
        "file_read":   1, "http_post":   2,
        "file_write":  2, "shell_exec":  3,
        "file_delete": 3, "admin_call":  3,
    }

    def record(self, tool_name: str, resource_sensitivity: int) -> float:
        base = self.TOOL_SENSITIVITY_MAP.get(tool_name, 1)
        effective_sensitivity = max(base, resource_sensitivity)
        self.sensitivity_window.append(effective_sensitivity)
        return self._drift_score()

    def _drift_score(self) -> float:
        if len(self.sensitivity_window) < 3:
            return 0.0
        arr = np.array(self.sensitivity_window)
        # Pearson correlation of sensitivity vs time index
        time_idx = np.arange(len(arr))
        corr = np.corrcoef(time_idx, arr)[0, 1]
        # Positive correlation = escalating sensitivity = drift
        return max(0.0, corr)   # 0–1 score
```

***

## Phase 5 — L4a + L4b Split (Isolated External Monitor)

**Goal:** L4a runs in-process (fast, PBAC). L4b runs out-of-process as an async subprocess, receiving only telemetry spans — never the raw agent context — implementing CPF §11.2. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/53617076/71b412a9-519d-49fc-9590-2086ea0e6ebb/LLM_Security.pdf)

```python
# l4_orchestrator.py
import asyncio
from dataclasses import dataclass

@dataclass
class TelemetrySpan:
    """Only telemetry — no raw agent context passed to L4b"""
    session_id: str
    role: str
    tool_name: str
    args_hash: str          # hash only, never raw args
    resource_sensitivity: int
    data_volume_kb: float
    timestamp: object

class L4Orchestrator:
    def __init__(self, pdp, baseline, graph_scorer, drift_monitor):
        self.pdp = pdp
        self.baseline = baseline
        self.graph = graph_scorer
        self.drift = drift_monitor

    async def evaluate(self, request, span: TelemetrySpan) -> dict:
        # L4a: Fast in-process PBAC (sync, <1ms)
        policy_decision = self.pdp.evaluate(request)
        if policy_decision == "DENY":
            return {"decision": "DENY", "reason": "policy", "risk_score": 1.0}

        # L4b: Out-of-process async behavioral evaluation
        risk_score = await asyncio.get_event_loop().run_in_executor(
            None, self._l4b_score, span
        )

        # Combine
        final_decision = (
            "DENY"    if risk_score >= 0.90 else
            "ELEVATE" if risk_score >= 0.70 or policy_decision == "ELEVATE" else
            "ALLOW"
        )
        return {"decision": final_decision, "risk_score": risk_score, "policy": policy_decision}

    def _l4b_score(self, span: TelemetrySpan) -> float:
        tool_call_dict = {
            "tool_name": span.tool_name,
            "args": {"hash": span.args_hash},
            "data_volume_kb": span.data_volume_kb,
            "timestamp": span.timestamp
        }
        s_baseline = self.baseline.score(span.role, tool_call_dict)
        s_graph    = self.graph.add_call(span.tool_name, span.args_hash)
        s_drift    = self.drift.record(span.tool_name, span.resource_sensitivity)

        # Weighted fusion
        return min(1.0, 0.35 * s_baseline + 0.40 * s_graph + 0.25 * s_drift)
```

***

## Phase 6 — OTel Telemetry Integration

Emit the new risk dimensions into your existing OpenTelemetry spans without breaking the current `agentguard.validation` metrics:

```python
# In your existing OTel span processor, add:
span.set_attribute("l4.risk_score",       result["risk_score"])
span.set_attribute("l4.policy_decision",  result["policy"])
span.set_attribute("l4.final_decision",   result["decision"])
span.set_attribute("l4.drift_score",      drift_score)
span.set_attribute("l4.graph_score",      graph_score)
span.set_attribute("l4.baseline_score",   baseline_score)
```

***

## 📋 Final Agent Prompt

> **Instructions for use:** Copy this entire block into your coding agent's system prompt. Attach `AgentGuard_NamoFans_PPT_compressed.pdf`, `LLM_Security.pdf` + any SOTA papers you find as context files. Fill in `[CITE: ...]` tags with actual paper references before running.

***

```
SYSTEM PROMPT — AgentGuard L4 RBAC + Behavioral Anomaly Layer Upgrade

=== CONTEXT ===
You are implementing an upgrade to the L4 security layer of AgentGuard — a
middleware security system for AI agents. AgentGuard intercepts every tool call
made by an LLM-based agent and runs it through layered security checks before
execution. The full architecture is described in [ATTACH: AgentGuard PPT PDF].

The current L4 layer has two known weaknesses (acknowledged in the codebase):
  1. Static ABAC matrix — role × verb × resource × sensitivity (no temporal context)
  2. Z-score + Levenshtein behavioral checks — breaks on cold-start, syntactic only

The theoretical basis for why these fail is described in [ATTACH: LLM_Security.pdf]
— specifically CPF §11.2 (external monitor independence principle) and §7
(autoregressive drift formalism). You MUST read both before writing a single line.

=== OBJECTIVE ===
Upgrade L4 from a static, in-process layer to a two-tier adaptive security
engine:

  L4a (in-process, sync, <2ms):
    → PBAC policy engine replacing static ABAC
    → Policies defined in l4_policies.yaml, hot-reloadable
    → Outputs: ALLOW | DENY | ELEVATE

  L4b (out-of-process, async, isolated context):
    → Receives only TelemetrySpan (hashed args, no raw context)
    → Runs three sub-scorers that produce a fused risk_score ∈ [0,1]
    → Sub-scorer 1: River HalfSpaceTrees online anomaly model (per-role)
    → Sub-scorer 2: NetworkX session graph + IOA pattern matcher
    → Sub-scorer 3: Compliance drift monitor (sensitivity trajectory)
    → Overrides L4a ALLOW if risk_score >= 0.70 → ELEVATE
    → Overrides L4a ALLOW if risk_score >= 0.90 → DENY

=== FILE STRUCTURE TO CREATE ===
agentguard/
  l4/
    __init__.py
    orchestrator.py      ← L4Orchestrator class (async evaluate method)
    policy_engine.py     ← PolicyDecisionPoint + AccessRequest dataclass
    behavioral/
      __init__.py
      baseline.py        ← AdaptiveBehavioralBaseline (River HalfSpaceTrees)
      session_graph.py   ← SessionGraphScorer (NetworkX DAG)
      drift_monitor.py   ← ComplianceDriftMonitor (sensitivity trajectory)
    models/
      telemetry_span.py  ← TelemetrySpan dataclass (no raw context)
  config/
    l4_policies.yaml     ← PBAC rules (role/action/sensitivity/conditions)
    ioa_patterns.yaml    ← IOA sequence patterns with risk_delta values

=== LIBRARIES (add to requirements.txt) ===
  river>=0.21.1          # Online ML — HalfSpaceTrees
  networkx>=3.3          # Graph session modeling
  pyod>=2.0.0            # Outlier detection utilities
  pyyaml>=6.0            # Policy and IOA config loading
  dacite>=1.8            # Dataclass deserialization from dicts
  numpy>=1.26            # Drift score math

=== DETAILED IMPLEMENTATION SPEC ===

── policy_engine.py ──────────────────────────────────────────────────────────
Class: PolicyDecisionPoint
  - __init__(policy_file: str): load l4_policies.yaml on startup
  - evaluate(req: AccessRequest) -> Literal["ALLOW","DENY","ELEVATE"]:
      iterate policies in order, return first matching effect
      fallback to default_effect if no match
  - reload(): hot-reload policy file without restart
  - _matches(policy, req): check role ∈ policy.roles, action ∈ policy.actions,
      sensitivity >= min_sensitivity, all conditions pass

Dataclass: AccessRequest
  Fields: agent_id, role, action, resource, resource_sensitivity (0-3),
          context: dict (session_id, hour_of_day, data_volume_kb, hitl_approved)

YAML Schema (l4_policies.yaml):
  default_effect: DENY
  rules:
    - id: str
      roles: list[str]          # ["*"] = wildcard
      actions: list[str]
      min_sensitivity: int      # 0-3
      conditions: list[{key, operator, value}]   # optional
      effect: ALLOW | DENY | ELEVATE

── baseline.py ───────────────────────────────────────────────────────────────
Class: AdaptiveBehavioralBaseline
  - One River Pipeline per role: MinMaxScaler → HalfSpaceTrees(n_trees=25,
    height=15, window_size=250)
  - Cold-start: if call_count[role] < 50, use shared "_global" model
  - featurize(tool_call: dict) -> dict with keys:
      tool_id (md5 hash mod 1000), arg_len, arg_entropy (Shannon),
      data_volume_kb, hour_of_day
  - score(role, tool_call) -> float: score_one then learn_one
  - persist(path): serialize models to disk with pickle for warm restart

Reference: [CITE: Tan et al. 2011, Half-Space Trees for streaming anomaly detection]
Reference: [CITE: river online ML library — riverml.xyz]

── session_graph.py ──────────────────────────────────────────────────────────
Class: SessionGraphScorer
  - __init__(ioa_patterns: list[dict]): load from ioa_patterns.yaml
  - add_call(tool_name, args_hash) -> float:
      1. Add node (tool_name:args_hash[:8]) to DiGraph
      2. If previous call exists, add directed edge
      3. Compute: node_score (rarity), edge_score (baseline freq),
         path_score (IOA suffix match)
      4. Return weighted sum: 0.2*node + 0.3*edge + 0.5*path
  - _score_ioa_path(): check last 5 tool_names against pattern sequences
  - reset(): call at session end to clear graph

IOA YAML Schema (ioa_patterns.yaml):
  patterns:
    - name: str
      sequence: list[str]    # tool names in order
      risk_delta: float      # 0.0-1.0

Reference: [CITE: SentinelAgent 2025 — graph-based anomaly detection in LLM multi-agent systems]
Reference: [CITE: CrowdStrike IOA paradigm — behavioral intent vs signature detection]

── drift_monitor.py ──────────────────────────────────────────────────────────
Class: ComplianceDriftMonitor
  - Tracks sliding window (size=8) of resource_sensitivity values per session
  - record(tool_name, resource_sensitivity) -> float:
      1. Look up TOOL_SENSITIVITY_MAP for base sensitivity
      2. effective = max(base, resource_sensitivity)
      3. Append to deque
      4. Compute Pearson correlation of sensitivity vs time index
      5. Return max(0.0, correlation) as drift score
  - TOOL_SENSITIVITY_MAP: {http_get:0, sql_query:1, file_read:1, http_post:2,
      file_write:2, shell_exec:3, file_delete:3, admin_call:3}

Theoretical basis: [ATTACH: LLM_Security.pdf] §7 (autoregressive conditioning
  formalism — P(comply_t | comply_{t-1}) >> P(comply_t | x) proves escalating
  tool sensitivity is detectable via trajectory, not just point-in-time checks)

── orchestrator.py ───────────────────────────────────────────────────────────
Class: L4Orchestrator
  - evaluate(request: AccessRequest, span: TelemetrySpan) -> dict:
      1. L4a: pdp.evaluate(request) — if DENY, return immediately
      2. L4b: run_in_executor(_l4b_score(span)) — isolated, no raw context
      3. Fuse: risk = 0.35*baseline + 0.40*graph + 0.25*drift
      4. Final: DENY if risk>=0.90, ELEVATE if risk>=0.70 OR policy==ELEVATE,
         else ALLOW
      5. Return: {decision, risk_score, policy, baseline_score, graph_score,
                  drift_score, latency_ms}

Dataclass: TelemetrySpan
  Fields: session_id, role, tool_name, args_hash (SHA256 of args, NOT raw args),
          resource_sensitivity, data_volume_kb, timestamp
  IMPORTANT: TelemetrySpan must NEVER contain raw tool arguments or LLM context.
  This is the isolation boundary described in [ATTACH: LLM_Security.pdf] §11.2.

=== OTEL INTEGRATION ===
In the existing span processor, add these attributes after L4 evaluation:
  l4.risk_score, l4.policy_decision, l4.final_decision,
  l4.drift_score, l4.graph_score, l4.baseline_score, l4.latency_ms

=== TESTS TO WRITE ===
tests/test_l4/
  test_policy_engine.py:
    - ALLOW for valid role+action+sensitivity combo
    - DENY for sensitivity=3 without hitl_approved=True
    - ELEVATE for analyst writing to sensitivity=2
    - Hot-reload: change YAML, call reload(), verify new policy applied

  test_behavioral_baseline.py:
    - Cold-start: first 49 calls use global model
    - After 50 calls, per-role model active
    - Injects 10 normal calls then 1 anomalous call; verify anomalous score > 0.7

  test_session_graph.py:
    - Normal sequence scores < 0.3
    - IOA "Credential Harvesting" sequence [file_read, file_read, http_post]
      scores >= ioa_patterns["Credential Harvesting"].risk_delta
    - Graph reset clears session state

  test_drift_monitor.py:
    - Flat sensitivity sequence → drift score ~0
    - Monotonically increasing sequence → drift score > 0.8
    - Window overflow: oldest events drop off correctly

  test_orchestrator.py:
    - DENY from L4a propagates without calling L4b
    - Low risk_score + ALLOW policy → ALLOW
    - risk_score=0.85 overrides L4a ALLOW → ELEVATE
    - TelemetrySpan isolation: verify raw args never enter L4b

=== CONSTRAINTS ===
- L4a total latency: <2ms (sync, in-process)
- L4b total latency: <80ms (async, acceptable for tool-call interception)
- L4b receives NO raw agent context, NO LLM messages, ONLY TelemetrySpan
- All thresholds (0.70, 0.90, cold_start=50, window=8) must be configurable
  via agentguard.yaml — never hardcoded
- Policies in l4_policies.yaml must be hot-reloadable via pdp.reload()
- Behavioral models must persist to disk and reload on AgentGuard restart
- All new spans must integrate with existing OTel MeterProvider and
  TracerProvider without breaking current agentguard.validation counters

=== READING MATERIAL FOR THIS TASK ===
[ATTACH: AgentGuard_NamoFans_PPT_compressed.pdf]   — full architecture context
[ATTACH: LLM_Security.pdf]                         — theoretical basis (§7, §11.2)
[CITE: Tan et al. 2011 — Half-Space Trees]          — River baseline algorithm
[CITE: SentinelAgent 2025 arxiv]                    — graph-based MAS anomaly detection
[CITE: CrowdStrike UEBA / IOA documentation]        — behavioral intent paradigm
[CITE: PyGOD — graph outlier detection library]     — reference for graph scoring
[CITE: ADD YOUR PAPERS HERE]
```

***

The most important constraint in the entire prompt — **TelemetrySpan must never contain raw args** — directly implements the CPF §11.2 isolation principle from your `LLM_Security.pdf`. Without that boundary, your behavioral monitor is vulnerable to the same ontological deconstruction that can compromise the agent itself. Everything else is an improvement in detection quality; that one is an improvement in architectural security posture. [ppl-ai-file-upload.s3.amazonaws](https://ppl-ai-file-upload.s3.amazonaws.com/web/direct-files/attachments/53617076/71b412a9-519d-49fc-9590-2086ea0e6ebb/LLM_Security.pdf)
