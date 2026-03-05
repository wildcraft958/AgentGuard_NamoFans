"""
AgentGuard – Output Toxicity module.

Detects harmful content (hate, self-harm, sexual, violence) in LLM output
by reusing the existing L1 ContentFilters.analyze_text() method.

This is a thin wrapper that re-labels the result layer as "output_toxicity"
to distinguish L2 output checks from L1 input checks.
"""

import logging

from agentguard.l1_input.content_filters import ContentFilters
from agentguard.models import ValidationResult

logger = logging.getLogger("agentguard.output_toxicity")


class OutputToxicity:
    """Checks LLM output for harmful content using Azure Content Safety.

    Delegates to the existing ContentFilters.analyze_text() and re-labels
    the result layer from "content_filters" to "output_toxicity".
    """

    def __init__(self, content_filters: ContentFilters):
        """
        Args:
            content_filters: Existing ContentFilters instance (shared with L1).
        """
        self._content_filters = content_filters

    def analyze(
        self,
        text: str,
        block_toxicity: bool = True,
        block_violence: bool = True,
        block_self_harm: bool = True,
        severity_threshold: int = 0,
    ) -> ValidationResult:
        """
        Analyze LLM output text for harmful content.

        Args:
            text: The LLM output text to check.
            block_toxicity: Whether to block on hate/toxicity.
            block_violence: Whether to block on violence.
            block_self_harm: Whether to block on self-harm.
            severity_threshold: Minimum severity to trigger block (0-6).

        Returns:
            ValidationResult with layer="output_toxicity".
        """
        logger.info("Running output toxicity check...")

        result = self._content_filters.analyze_text(
            text=text,
            block_toxicity=block_toxicity,
            block_violence=block_violence,
            block_self_harm=block_self_harm,
            severity_threshold=severity_threshold,
        )

        # Re-label the layer for L2
        result.layer = "output_toxicity"
        return result
