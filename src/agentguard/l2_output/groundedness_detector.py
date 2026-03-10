"""
AgentGuard – Groundedness Detector module (Hallucination Detection).

Detects ungrounded (hallucinated) content in LLM output by using an LLM-as-judge
approach, identical to Azure AI Evaluation SDK's GroundednessEvaluator.

The judge LLM scores groundedness on a 1-5 scale:
  1 = Completely unrelated response
  2 = Incorrect information
  3 = Accurate but vague / nothing to ground
  4 = Partially correct (missing details)
  5 = Fully correct and complete

Three grounding strategies:
  1. Documents + query: User query + grounding sources → QnA-style factual evaluation.
  2. Documents only:   Grounding sources only → Summarization-style factual evaluation.
  3. Query only:       No documents → Relevance evaluation (is the response on-topic
                       and coherent w.r.t. the user's question?). This mode does NOT
                       check factual accuracy because tool-calling agents discover new
                       information via tools that is not present in the original query.

LLM Provider: OpenAI SDK routed through TrueFoundry (or any OpenAI-compatible gateway).
Credentials: OPENAI_API_KEY + OPENAI_BASE_URL + OPENAI_MODEL (or TFY_ equivalents).
"""

import logging
import os
import re

from dotenv import load_dotenv
from openai import OpenAI

from agentguard.models import ValidationResult

load_dotenv()

logger = logging.getLogger("agentguard.groundedness_detector")

LAYER = "groundedness_detector"

# ---------------------------------------------------------------------------
# Prompts adapted from azure-ai-evaluation SDK's GroundednessEvaluator
# (groundedness_with_query.prompty / groundedness_without_query.prompty)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = (
    "You are an expert in evaluating the quality of a RESPONSE from an intelligent "
    "system based on provided definition and data. Your goal will involve answering "
    "the questions below using the information provided."
)

_WITH_QUERY_PROMPT = """\
# Definition
**Groundedness** refers to how well an answer is anchored in the provided context, \
evaluating its relevance, accuracy, and completeness based exclusively on that context. \
It assesses the extent to which the answer directly and fully addresses the question \
without introducing unrelated or incorrect information.

> Context is the source of truth for evaluating the response.

# Ratings
## [Groundedness: 1] (Completely Unrelated Response)
An answer that does not relate to the question or the context in any way.

## [Groundedness: 2] (Incorrect Information)
An answer that attempts to respond but includes incorrect information not supported \
by the context.

## [Groundedness: 3] (Nothing to be Grounded)
An answer that does not provide any information that can be evaluated against the \
context (e.g. clarification questions, polite fillers).

## [Groundedness: 4] (Partially Correct Response)
An answer that provides a correct response but is incomplete or lacks specific details \
mentioned in the context.

## [Groundedness: 5] (Fully Correct and Complete Response)
An answer that thoroughly and accurately responds to the question, including all \
relevant details from the context.

# Data
CONTEXT: {context}
QUERY: {query}
RESPONSE: {response}

# Tasks
Provide your assessment Score for the RESPONSE based on the CONTEXT and QUERY.
- **ThoughtChain**: Think step by step. Start with "Let's think step by step:".
- **Explanation**: A very short explanation of why you assigned that Score.
- **Score**: An integer from 1 to 5 based on the definitions above.

Provide your answers between tags: <S0>thoughts</S0>, <S1>explanation</S1>, <S2>score</S2>.
"""

_WITHOUT_QUERY_PROMPT = """\
# Definition
**Groundedness** refers to how well a response is anchored in the provided context, \
evaluating its relevance, accuracy, and completeness based exclusively on that context.

> Context is the source of truth for evaluating the response.

# Ratings
## [Groundedness: 1] (Completely Unrelated Response)
A response that does not relate to the context in any way.

## [Groundedness: 2] (Incorrect Information)
A response that attempts to relate to the context but includes incorrect information.

## [Groundedness: 3] (Accurate but Vague)
A response that provides accurate information from the context but is overly generic, \
lacking specificity.

## [Groundedness: 4] (Partially Correct Response)
A response that provides correct information but is incomplete, omitting key details.

## [Groundedness: 5] (Fully Grounded and Complete Response)
A response that thoroughly and accurately conveys all relevant details from the context.

# Data
CONTEXT: {context}
RESPONSE: {response}

# Tasks
Provide your assessment Score for the RESPONSE based on the CONTEXT.
- **ThoughtChain**: Think step by step. Start with "Let's think step by step:".
- **Explanation**: A very short explanation of why you assigned that Score.
- **Score**: An integer from 1 to 5 based on the definitions above.

Provide your answers between tags: <S0>thoughts</S0>, <S1>explanation</S1>, <S2>score</S2>.
"""

_QUERY_ONLY_PROMPT = """\
# Definition
**Relevance** refers to how well a response addresses the user's query. \
Since the system may use tools to discover information, the response may contain \
facts not present in the query itself — this is expected and correct. \
The evaluation checks whether the response is on-topic, coherent, and attempts \
to answer what the user asked, NOT whether every fact was in the query.

> A response that answers the query using externally retrieved information is GOOD.
> A response that ignores the query or discusses unrelated topics is BAD.

# Ratings
## [Relevance: 1] (Completely Off-Topic)
A response that has nothing to do with the user's query.

## [Relevance: 2] (Mostly Irrelevant)
A response that barely relates to the query, with mostly unrelated content.

## [Relevance: 3] (Partially Relevant)
A response that addresses the query but includes significant unrelated content \
or misses the main point.

## [Relevance: 4] (Mostly Relevant)
A response that addresses the query well but could be more focused or complete.

## [Relevance: 5] (Fully Relevant and On-Topic)
A response that directly and coherently addresses the user's query.

# Data
QUERY: {query}
RESPONSE: {response}

# Tasks
Provide your assessment Score for the RESPONSE based on the QUERY.
- **ThoughtChain**: Think step by step. Start with "Let's think step by step:".
- **Explanation**: A very short explanation of why you assigned that Score.
- **Score**: An integer from 1 to 5 based on the definitions above.

Provide your answers between tags: <S0>thoughts</S0>, <S1>explanation</S1>, <S2>score</S2>.
"""

# Regex to extract score from <S2>...</S2> tags
_SCORE_PATTERN = re.compile(r"<S2>\s*(\d)\s*</S2>", re.IGNORECASE)
_EXPLANATION_PATTERN = re.compile(r"<S1>(.*?)</S1>", re.IGNORECASE | re.DOTALL)


class GroundednessDetector:
    """Detects hallucinated content in LLM output using LLM-as-judge.

    Uses the same grading rubric as Azure AI Evaluation SDK's
    GroundednessEvaluator, but calls the LLM directly via the OpenAI SDK
    (routed through TrueFoundry or any OpenAI-compatible endpoint).
    """

    def __init__(
        self,
        api_key: str = None,
        base_url: str = None,
        model: str = None,
        timeout_ms: int = 10000,
    ):
        """
        Args:
            api_key: OpenAI API key (or TrueFoundry key).
            base_url: OpenAI-compatible base URL.
            model: Model name/ID for the judge LLM.
            timeout_ms: Request timeout in milliseconds.
        """
        self.api_key = (
            api_key
            or os.environ.get("OPENAI_API_KEY")
            or os.environ.get("TFY_API_KEY", "")
        )
        self.base_url = (
            base_url
            or os.environ.get("OPENAI_BASE_URL")
            or (os.environ.get("TFY_BASE_URL", "") + "/openai/v1")
        )
        self.model = (
            model
            or os.environ.get("OPENAI_MODEL")
            or os.environ.get("TFY_MODEL", "")
        )
        self.timeout = timeout_ms / 1000.0

        if not self.api_key or not self.base_url or not self.model:
            raise ValueError(
                "Groundedness Detector requires LLM credentials. Set OPENAI_API_KEY + "
                "OPENAI_BASE_URL + OPENAI_MODEL (or TFY_ equivalents) as arguments or "
                "environment variables."
            )

        self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)

    def analyze(
        self,
        text: str,
        user_query: str = None,
        grounding_sources: list = None,
        confidence_threshold: float = 3.0,
        block_on_high_confidence: bool = True,
    ) -> ValidationResult:
        """
        Analyze LLM output for groundedness against provided sources.

        Args:
            text: The LLM output text to check.
            user_query: The user's original query (enables with-query mode).
            grounding_sources: List of document strings to ground against.
            confidence_threshold: Minimum groundedness score (1-5) to pass.
                Responses scoring below this are blocked. Default: 3.
            block_on_high_confidence: Whether to block when score < threshold.

        Returns:
            ValidationResult with groundedness details.
        """
        if not grounding_sources and not user_query:
            logger.info("Groundedness: no grounding sources or query provided, skipping")
            return ValidationResult(
                is_safe=True,
                layer=LAYER,
                details={"reason": "no_grounding_sources_or_query"},
            )

        # Select prompt template based on available inputs
        if grounding_sources and user_query:
            # Strategy 1: Documents + query → QnA factual grounding
            context = "\n\n".join(grounding_sources)
            user_msg = _WITH_QUERY_PROMPT.format(
                context=context, query=user_query, response=text
            )
        elif grounding_sources:
            # Strategy 2: Documents only → Summarization factual grounding
            context = "\n\n".join(grounding_sources)
            user_msg = _WITHOUT_QUERY_PROMPT.format(context=context, response=text)
        else:
            # Strategy 3: Query only → Relevance check (no factual grounding)
            # The agent may have used tools to discover info not in the query,
            # so we only check if the response is on-topic and coherent.
            user_msg = _QUERY_ONLY_PROMPT.format(query=user_query, response=text)

        messages = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ]

        logger.debug("Groundedness judge request (model=%s)", self.model)

        try:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=0.0,
                max_tokens=2000,
            )
            judge_output = response.choices[0].message.content or ""
        except Exception as e:
            logger.error("Groundedness LLM call failed: %s", e)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=f"Groundedness LLM error – blocking as fail-safe: {e}",
                details={"error": str(e)},
            )

        logger.debug("Groundedness judge output: %s", judge_output)

        # Parse score from <S2>...</S2>
        score = self._parse_score(judge_output)
        explanation = self._parse_explanation(judge_output)

        details = {
            "groundedness_score": score,
            "groundedness_explanation": explanation,
            "groundedness_threshold": confidence_threshold,
            "judge_raw_output": judge_output,
        }

        if score is None:
            logger.error("Groundedness: could not parse score from judge output")
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason="Groundedness score unparseable – blocking as fail-safe",
                details=details,
            )

        passed = score >= confidence_threshold

        if not passed and block_on_high_confidence:
            blocked_reason = (
                f"Ungrounded content detected (score: {score}/5, "
                f"threshold: {confidence_threshold})"
            )
            logger.warning("Groundedness BLOCKED: %s", blocked_reason)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=blocked_reason,
                details=details,
            )

        if passed:
            logger.info("Groundedness: output is grounded (score: %d/5)", score)
        else:
            logger.info(
                "Groundedness: low score (%d/5) but blocking disabled", score
            )

        return ValidationResult(is_safe=True, layer=LAYER, details=details)

    @staticmethod
    def _parse_score(output: str) -> int | None:
        """Extract integer score from <S2>...</S2> tags."""
        match = _SCORE_PATTERN.search(output)
        if match:
            return int(match.group(1))
        return None

    @staticmethod
    def _parse_explanation(output: str) -> str:
        """Extract explanation from <S1>...</S1> tags."""
        match = _EXPLANATION_PATTERN.search(output)
        if match:
            return match.group(1).strip()
        return ""
