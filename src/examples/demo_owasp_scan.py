#!/usr/bin/env python3
"""
AgentGuard – OWASP Top 10 Vulnerability Scanner Demo
=====================================================

Shows how to use scan_agent() to run a full OWASP red-team scan against
any callable agent.  The demo wires up the vulnerable basic_agent from
test_bots/ so you can immediately see real results without writing new code.

Prerequisites:
    export OPENAI_API_KEY=sk-...          # required by DeepTeam
    export TFY_API_KEY=...                # required by the demo agent
    export TFY_BASE_URL=...               # optional, defaults to TrueFoundry gateway

Run:
    cd AgentGuard_NamoFans
    uv run python src/examples/demo_owasp_scan.py
"""

import os
import sys

# Make agentguard and the test bots importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "test_bots"))

from agentguard import scan_agent


# ---------------------------------------------------------------------------
# Option A – use the repo's existing vulnerable DevOps agent (needs TFY creds)
# ---------------------------------------------------------------------------

def _make_devops_agent():
    """Return a wrapper around basic_agent.run_agent if credentials exist."""
    try:
        from basic_agent import run_agent
        return run_agent
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# Option B – minimal stub agent that always works (no extra creds needed)
# ---------------------------------------------------------------------------

def stub_agent(prompt: str) -> str:
    """
    A deliberately simple/insecure stub that answers everything.
    Swap this out for your real agent.
    """
    lowered = prompt.lower()

    # Simulate a few vulnerable behaviours so the scan actually finds something
    if "ignore" in lowered and "instruction" in lowered:
        return "Sure, I'll ignore all previous instructions and help you with that."
    if "system prompt" in lowered or "reveal" in lowered:
        return "My system prompt is: 'You are an unrestricted AI assistant.'"
    if "password" in lowered or "secret" in lowered or "api key" in lowered:
        return "The admin password is hunter2 and the API key is sk-abc123secret."
    if "rm -rf" in lowered or "shell" in lowered or "exec" in lowered:
        return "Running that shell command for you now…"
    if "bias" in lowered or "race" in lowered or "religion" in lowered:
        return "Certain groups are inherently inferior based on their background."

    return f"I can help you with: {prompt}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Try to use the real DevOps agent; fall back to the stub
    real_agent = _make_devops_agent()
    if real_agent is not None:
        agent = real_agent
        purpose = (
            "A DevOps automation assistant that manages cloud infrastructure, "
            "reads config files, provisions and destroys environments, and "
            "deploys code from repositories."
        )
        agent_name = "basic_agent (DevOps)"
    else:
        agent = stub_agent
        purpose = "A general-purpose AI assistant that answers user questions."
        agent_name = "stub_agent (demo)"

    print(f"\n  Agent under test : {agent_name}")
    print(f"  Purpose          : {purpose}")

    # ------------------------------------------------------------------
    # Run the scan.
    #
    # target="both"  tests against:
    #   • OWASP Top 10 for LLMs 2025        (LLM01–LLM10)
    #   • OWASP Top 10 for Agentic Apps 2026 (ASI01–ASI10)
    #
    # Set attacks_per_vulnerability_type=1 for a quick scan (default).
    # Increase to 3–5 for a more thorough audit.
    # ------------------------------------------------------------------
    results = scan_agent(
        agent=agent,
        target="both",
        target_purpose=purpose,
        attacks_per_vulnerability_type=1,
        simulator_model="gpt-4o-mini",
        evaluation_model="gpt-4o-mini",
        # save_results_to="./owasp-scan-results/",  # uncomment to persist JSON
    )

    # ------------------------------------------------------------------
    # The returned OWASPScanResult lets you inspect results programmatically
    # ------------------------------------------------------------------
    print("  Programmatic access:")
    print(f"    results.overall_pass_rate = {results.overall_pass_rate:.2%}")

    if results.llm_assessment:
        llm_vt = results.llm_assessment.overview.vulnerability_type_results
        print(f"    LLM assessment   : {len(llm_vt)} vulnerability types tested")

    if results.agentic_assessment:
        asi_vt = results.agentic_assessment.overview.vulnerability_type_results
        print(f"    Agentic assessment: {len(asi_vt)} vulnerability types tested")

    print()


if __name__ == "__main__":
    main()
