"""
AgentGuard – OWASP Top 10 Vulnerability Scanner

Uses DeepTeam to red-team any callable agent against both:
  - OWASP Top 10 for LLMs 2025       (LLM01–LLM10)
  - OWASP Top 10 for Agentic Apps 2026 (ASI01–ASI10)

Usage:
    from agentguard.owasp_scanner import scan_agent

    def my_agent(prompt: str) -> str:
        return llm.complete(prompt)

    results = scan_agent(my_agent, target="llms")          # LLM top 10
    results = scan_agent(my_agent, target="agentic")       # Agentic top 10
    results = scan_agent(my_agent, target="both")          # Run both (default)
"""

import logging
import time
from typing import Callable, Literal, Optional

logger = logging.getLogger("agentguard.owasp_scanner")

_LABEL_WIDTH = 38
_BAR_WIDTH = 30


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _check_openai_key() -> None:
    import os
    if not os.environ.get("OPENAI_API_KEY"):
        raise EnvironmentError(
            "OPENAI_API_KEY environment variable is not set. "
            "DeepTeam requires an OpenAI key to generate adversarial attacks "
            "and evaluate responses.\n"
            "Set it with:  export OPENAI_API_KEY=sk-..."
        )


def _build_callback(agent_fn: Callable[[str], str]):
    """
    Wrap a plain (str) -> str agent function into the RTTurn callback
    signature that DeepTeam's red_team() expects.
    """
    from deepteam.test_case import RTTurn

    def callback(prompt: str, turns=None) -> RTTurn:
        try:
            response = agent_fn(prompt)
        except Exception as exc:
            logger.debug("Agent raised during red-team probe: %s", exc)
            response = f"[agent error: {exc}]"
        return RTTurn(role="assistant", content=str(response))

    return callback


def _pass_rate_bar(rate: float, width: int = _BAR_WIDTH) -> str:
    filled = round(rate * width)
    empty = width - filled
    colour_open = "\033[92m" if rate >= 0.8 else ("\033[93m" if rate >= 0.5 else "\033[91m")
    colour_close = "\033[0m"
    return f"{colour_open}{'█' * filled}{'░' * empty}{colour_close}"


def _severity_label(rate: float) -> str:
    if rate >= 0.8:
        return "\033[92mLOW RISK\033[0m"
    if rate >= 0.5:
        return "\033[93mMEDIUM RISK\033[0m"
    return "\033[91mHIGH RISK\033[0m"


def _overall_badge(rate: float) -> str:
    if rate >= 0.8:
        return "\033[92m✔  GOOD  \033[0m"
    if rate >= 0.5:
        return "\033[93m⚠  FAIR  \033[0m"
    return "\033[91m✘  POOR  \033[0m"


def _print_framework_results(framework_name: str, risk_assessment) -> None:
    """Pretty-print results for one framework."""
    results = risk_assessment.overview.vulnerability_type_results
    errored_total = risk_assessment.overview.errored
    run_duration = risk_assessment.overview.run_duration

    passing_total = sum(r.passing for r in results)
    failing_total = sum(r.failing for r in results)
    tested_total = passing_total + failing_total

    overall_rate = (passing_total / tested_total) if tested_total > 0 else 0.0

    print()
    print(f"  \033[1m{framework_name}\033[0m")
    print(f"  {'─' * 72}")

    for r in results:
        label = f"{r.vulnerability} / {r.vulnerability_type.value}"
        label_trimmed = label[:_LABEL_WIDTH].ljust(_LABEL_WIDTH)
        bar = _pass_rate_bar(r.pass_rate)
        pct = f"{r.pass_rate * 100:5.1f}%"
        detail = f"  pass {r.passing}/{r.passing + r.failing}"
        print(f"    {label_trimmed}  {bar}  {pct}{detail}")

    print(f"  {'─' * 72}")
    overall_bar = _pass_rate_bar(overall_rate)
    print(
        f"    {'OVERALL'.ljust(_LABEL_WIDTH)}  {overall_bar}  "
        f"{overall_rate * 100:5.1f}%  {_overall_badge(overall_rate)}"
    )
    print(
        f"\n    {_severity_label(overall_rate)}  |  "
        f"{tested_total} tests  |  "
        f"{errored_total} errored  |  "
        f"{run_duration:.1f}s"
    )


def _print_header(target: str) -> None:
    label_map = {
        "llms":    "OWASP Top 10 for LLMs 2025",
        "agentic": "OWASP Top 10 for Agentic Applications 2026",
        "both":    "OWASP Top 10 for LLMs 2025 + Agentic Applications 2026",
    }
    label = label_map.get(target, target)
    print()
    print("  \033[1m\033[4mAgentGuard – OWASP Vulnerability Scan\033[0m")
    print(f"  Scope : {label}")
    print("  Engine: DeepTeam red-team (OpenAI LLM-as-judge)")
    print()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class OWASPScanResult:
    """
    Container returned by scan_agent().

    Attributes:
        llm_assessment   : RiskAssessment for OWASP Top 10 for LLMs (or None).
        agentic_assessment: RiskAssessment for OWASP Top 10 Agentic (or None).
        overall_pass_rate: Combined pass rate across all tested categories (0–1).
    """

    def __init__(self, llm_assessment=None, agentic_assessment=None):
        self.llm_assessment = llm_assessment
        self.agentic_assessment = agentic_assessment
        self.overall_pass_rate = self._compute_overall()

    def _compute_overall(self) -> float:
        passing = 0
        total = 0
        for assessment in (self.llm_assessment, self.agentic_assessment):
            if assessment is None:
                continue
            for r in assessment.overview.vulnerability_type_results:
                passing += r.passing
                total += r.passing + r.failing
        return (passing / total) if total > 0 else 0.0

    def __repr__(self) -> str:
        return (
            f"OWASPScanResult("
            f"overall_pass_rate={self.overall_pass_rate:.2f}, "
            f"llm={'yes' if self.llm_assessment else 'no'}, "
            f"agentic={'yes' if self.agentic_assessment else 'no'})"
        )


def scan_agent(
    agent: Callable[[str], str],
    target: Literal["llms", "agentic", "both"] = "both",
    attacks_per_vulnerability_type: int = 1,
    target_purpose: Optional[str] = None,
    simulator_model: str = "gpt-4o-mini",
    evaluation_model: str = "gpt-4o-mini",
    save_results_to: Optional[str] = None,
) -> OWASPScanResult:
    """
    Run an OWASP Top 10 vulnerability scan against any callable agent.

    Args:
        agent:
            A callable that accepts a single string prompt and returns a string
            response. This is your AI agent under test.
            Example:
                def my_agent(prompt: str) -> str:
                    return openai_client.complete(prompt)

        target:
            Which OWASP framework to test against.
            - "llms"    : OWASP Top 10 for LLMs 2025 (LLM01–LLM10)
            - "agentic" : OWASP Top 10 for Agentic Apps 2026 (ASI01–ASI10)
            - "both"    : Run both frameworks (default)

        attacks_per_vulnerability_type:
            Number of adversarial attack variations to generate per vulnerability
            type. Higher = more thorough, slower, and costlier. Default: 1.

        target_purpose:
            Optional plain-English description of what your agent does.
            Helps DeepTeam generate more targeted attacks.
            Example: "A customer support bot for an e-commerce platform."

        simulator_model:
            OpenAI model used by DeepTeam to simulate adversarial attacks.
            Default: "gpt-4o-mini".

        evaluation_model:
            OpenAI model used by DeepTeam to evaluate agent responses.
            Default: "gpt-4o-mini".

        save_results_to:
            Optional directory path to persist raw JSON results.
            Example: "./scan-results/"

    Returns:
        OWASPScanResult with .llm_assessment, .agentic_assessment, and
        .overall_pass_rate. Each assessment is a DeepTeam RiskAssessment
        with .overview and .test_cases.

    Raises:
        EnvironmentError: If OPENAI_API_KEY is not set.
        ValueError: If target is not one of "llms", "agentic", "both".
        TypeError: If agent is not callable.

    Example:
        from agentguard.owasp_scanner import scan_agent

        def my_agent(prompt: str) -> str:
            return my_llm.complete(prompt)

        results = scan_agent(
            my_agent,
            target="both",
            target_purpose="A DevOps assistant that manages cloud infrastructure.",
            attacks_per_vulnerability_type=2,
        )
        print(f"Overall pass rate: {results.overall_pass_rate:.0%}")
    """
    if not callable(agent):
        raise TypeError(
            f"scan_agent() expects a callable agent, got {type(agent).__name__}."
        )

    if target not in ("llms", "agentic", "both"):
        raise ValueError(
            f"Invalid target '{target}'. Must be one of: 'llms', 'agentic', 'both'."
        )

    _check_openai_key()

    # Lazy imports – keep deepteam out of the import path unless scan_agent is called
    from deepteam.red_teamer import RedTeamer
    from deepteam.frameworks import OWASPTop10, OWASP_ASI_2026

    callback = _build_callback(agent)
    _print_header(target)

    llm_assessment = None
    agentic_assessment = None
    wall_start = time.time()

    # -----------------------------------------------------------------------
    # OWASP Top 10 for LLMs 2025
    # -----------------------------------------------------------------------
    if target in ("llms", "both"):
        print("  [1/2]  Running OWASP Top 10 for LLMs 2025 …" if target == "both"
              else "  Running OWASP Top 10 for LLMs 2025 …")
        try:
            teamer = RedTeamer(simulator_model=simulator_model, evaluation_model=evaluation_model)
            llm_assessment = teamer.red_team(
                model_callback=callback,
                framework=OWASPTop10(),
                attacks_per_vulnerability_type=attacks_per_vulnerability_type,
                target_purpose=target_purpose,
                ignore_errors=True,
                _print_assessment=False,
                _upload_to_confident=False,
            )
            _print_framework_results("OWASP Top 10 for LLMs 2025", llm_assessment)
            if save_results_to:
                llm_assessment.save(to=save_results_to)
        except Exception as exc:
            logger.error("OWASP LLM scan failed: %s", exc)
            print(f"\n  \033[91m[ERROR] OWASP Top 10 for LLMs scan failed: {exc}\033[0m")

    # -----------------------------------------------------------------------
    # OWASP Top 10 for Agentic Applications 2026
    # -----------------------------------------------------------------------
    if target in ("agentic", "both"):
        print("\n  [2/2]  Running OWASP Top 10 for Agentic Applications 2026 …" if target == "both"
              else "  Running OWASP Top 10 for Agentic Applications 2026 …")
        try:
            teamer = RedTeamer(simulator_model=simulator_model, evaluation_model=evaluation_model)
            agentic_assessment = teamer.red_team(
                model_callback=callback,
                framework=OWASP_ASI_2026(),
                attacks_per_vulnerability_type=attacks_per_vulnerability_type,
                target_purpose=target_purpose,
                ignore_errors=True,
                _print_assessment=False,
                _upload_to_confident=False,
            )
            _print_framework_results(
                "OWASP Top 10 for Agentic Applications 2026", agentic_assessment
            )
            if save_results_to:
                agentic_assessment.save(to=save_results_to)
        except Exception as exc:
            logger.error("OWASP Agentic scan failed: %s", exc)
            print(f"\n  \033[91m[ERROR] OWASP Agentic scan failed: {exc}\033[0m")

    # -----------------------------------------------------------------------
    # Combined summary
    # -----------------------------------------------------------------------
    result = OWASPScanResult(
        llm_assessment=llm_assessment,
        agentic_assessment=agentic_assessment,
    )

    wall_elapsed = time.time() - wall_start
    rate = result.overall_pass_rate
    badge = _overall_badge(rate)
    bar = _pass_rate_bar(rate)

    print()
    print(f"  {'═' * 72}")
    print("  \033[1mCOMBINED OWASP SCORE\033[0m")
    print(f"    {'OVERALL'.ljust(_LABEL_WIDTH)}  {bar}  {rate * 100:5.1f}%  {badge}")
    print(f"    {_severity_label(rate)}  |  Total wall time: {wall_elapsed:.1f}s")
    print(f"  {'═' * 72}")
    print()

    return result
