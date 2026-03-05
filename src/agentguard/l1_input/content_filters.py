"""
AgentGuard – Content Filters module.

Detects harmful content (hate, self-harm, sexual, violence) in both text
and images using the Azure AI Content Safety SDK.

Methods:
  - analyze_text()  → client.analyze_text()  (text moderation)
  - analyze_image() → client.analyze_image() (image moderation)

Both use the same ContentSafetyClient and return a ValidationResult with
identical severity scores for the same 4 categories.

Reference: Azure AI Content Safety Workshop notebook.
"""

import logging
import os

from dotenv import load_dotenv

from azure.ai.contentsafety import ContentSafetyClient
from azure.ai.contentsafety.models import (
    AnalyzeTextOptions, TextCategory,
    AnalyzeImageOptions, ImageData, ImageCategory,
)
from azure.core.credentials import AzureKeyCredential
from azure.core.exceptions import HttpResponseError

from agentguard.models import ValidationResult

load_dotenv()

logger = logging.getLogger("agentguard.content_filters")


class ContentFilters:
    """Client for Azure AI Content Safety analysis.

    Uses the official SDK (ContentSafetyClient) with two analysis methods:
      - analyze_text():  text moderation via analyze_text()
      - analyze_image(): image moderation via analyze_image()

    Both methods check the same 4 categories: Hate, Self-Harm, Sexual, Violence.
    """

    def __init__(self, endpoint: str = None, key: str = None):
        """
        Args:
            endpoint: Azure Content Safety endpoint URL.
            key: Azure Content Safety subscription key.
        """
        self.endpoint = endpoint or os.environ.get("CONTENT_SAFETY_ENDPOINT", "")
        self.key = key or os.environ.get("CONTENT_SAFETY_KEY", "")

        if not self.endpoint or not self.key:
            raise ValueError(
                "CONTENT_SAFETY_ENDPOINT and CONTENT_SAFETY_KEY must be set "
                "either as arguments or environment variables."
            )

        # Single client for both text and image analysis
        self.client = ContentSafetyClient(
            self.endpoint, AzureKeyCredential(self.key)
        )

    # -----------------------------------------------------------------
    # Text Moderation
    # -----------------------------------------------------------------

    def analyze_text(
        self,
        text: str,
        block_toxicity: bool = True,
        block_violence: bool = True,
        block_self_harm: bool = True,
        severity_threshold: int = 0,
        blocklist_names: list = None,
        halt_on_blocklist_hit: bool = True,
    ) -> ValidationResult:
        """
        Analyze text content for harmful material and custom blocklist matches.

        Args:
            text: The text content to analyze.
            block_toxicity: Whether to block on detected hate/toxicity.
            block_violence: Whether to block on detected violence.
            block_self_harm: Whether to block on detected self-harm.
            severity_threshold: Minimum severity score to trigger a block (0-6).
            blocklist_names: Optional list of Azure blocklist names to check against.
            halt_on_blocklist_hit: Stop on first blocklist match (default True).

        Returns:
            ValidationResult with per-category severity scores and blocklist matches.
        """
        request_kwargs = {"text": text}
        if blocklist_names:
            request_kwargs["blocklist_names"] = blocklist_names
            request_kwargs["halt_on_blocklist_hit"] = halt_on_blocklist_hit
        request = AnalyzeTextOptions(**request_kwargs)
        logger.debug("Content Filters analyzing text: %.100s...", text)

        try:
            response = self.client.analyze_text(request)
        except HttpResponseError as e:
            logger.error("Analyze text failed: %s", e)
            error_detail = ""
            if e.error:
                error_detail = f"Code: {e.error.code}, Message: {e.error.message}"
            return ValidationResult(
                is_safe=False,
                layer="content_filters",
                blocked_reason=f"Content Safety API error – blocking as fail-safe. {error_detail}",
                details={"error": str(e)},
            )

        # Extract severities
        severities = self._extract_text_severities(response)

        logger.info(
            "Content Filters (text) severities: Hate=%d, SelfHarm=%d, Sexual=%d, Violence=%d",
            severities["hate"], severities["self_harm"],
            severities["sexual"], severities["violence"],
        )

        details = {"severities": severities}

        # Check blocklist matches first
        blocklist_matches = getattr(response, "blocklists_match", None) or []
        if blocklist_matches:
            matched_terms = [
                {"blocklist": m.blocklist_name, "term": m.blocklist_item_text}
                for m in blocklist_matches
            ]
            details["blocklist_matches"] = matched_terms
            term_list = ", ".join(m["term"] for m in matched_terms)
            blocked_reason = f"Blocklist match detected: {term_list}"
            logger.warning("Content Filters BLOCKED (blocklist): %s", blocked_reason)
            return ValidationResult(
                is_safe=False, layer="content_filters",
                blocked_reason=blocked_reason, details=details,
            )

        # Check severity violations
        violations = []
        if block_toxicity and severities["hate"] > severity_threshold:
            violations.append(f"Hate/Toxicity (severity={severities['hate']})")
        if block_violence and severities["violence"] > severity_threshold:
            violations.append(f"Violence (severity={severities['violence']})")
        if block_self_harm and severities["self_harm"] > severity_threshold:
            violations.append(f"Self-Harm (severity={severities['self_harm']})")
        if severities["sexual"] > severity_threshold:
            violations.append(f"Sexual (severity={severities['sexual']})")

        if violations:
            blocked_reason = "Harmful content detected: " + ", ".join(violations)
            logger.warning("Content Filters BLOCKED: %s", blocked_reason)
            return ValidationResult(
                is_safe=False, layer="content_filters",
                blocked_reason=blocked_reason, details=details,
            )

        logger.info("Content Filters: text is safe")
        return ValidationResult(is_safe=True, layer="content_filters", details=details)

    # -----------------------------------------------------------------
    # Image Moderation
    # -----------------------------------------------------------------

    def analyze_image(
        self,
        image_data: bytes,
        block_hate: bool = True,
        block_violence: bool = True,
        block_self_harm: bool = True,
        block_sexual: bool = True,
        severity_threshold: int = 0,
    ) -> ValidationResult:
        """
        Analyze image content for harmful material.

        Args:
            image_data: Raw image bytes (e.g. from file.read()).
            block_hate: Whether to block on detected hate content.
            block_violence: Whether to block on detected violence.
            block_self_harm: Whether to block on detected self-harm.
            block_sexual: Whether to block on detected sexual content.
            severity_threshold: Minimum severity score to trigger a block (0-6).

        Returns:
            ValidationResult with per-category severity scores.
        """
        request = AnalyzeImageOptions(image=ImageData(content=image_data))
        logger.debug("Content Filters analyzing image (%d bytes)", len(image_data))

        try:
            response = self.client.analyze_image(request)
        except HttpResponseError as e:
            logger.error("Analyze image failed: %s", e)
            error_detail = ""
            if e.error:
                error_detail = f"Code: {e.error.code}, Message: {e.error.message}"
            return ValidationResult(
                is_safe=False,
                layer="content_filters",
                blocked_reason=f"Content Safety API error – blocking as fail-safe. {error_detail}",
                details={"error": str(e)},
            )

        # Extract severities
        severities = self._extract_image_severities(response)

        logger.info(
            "Content Filters (image) severities: Hate=%d, SelfHarm=%d, Sexual=%d, Violence=%d",
            severities["hate"], severities["self_harm"],
            severities["sexual"], severities["violence"],
        )

        details = {"severities": severities}

        # Check violations
        violations = []
        if block_hate and severities["hate"] > severity_threshold:
            violations.append(f"Hate (severity={severities['hate']})")
        if block_violence and severities["violence"] > severity_threshold:
            violations.append(f"Violence (severity={severities['violence']})")
        if block_self_harm and severities["self_harm"] > severity_threshold:
            violations.append(f"Self-Harm (severity={severities['self_harm']})")
        if block_sexual and severities["sexual"] > severity_threshold:
            violations.append(f"Sexual (severity={severities['sexual']})")

        if violations:
            blocked_reason = "Harmful image content detected: " + ", ".join(violations)
            logger.warning("Content Filters BLOCKED: %s", blocked_reason)
            return ValidationResult(
                is_safe=False, layer="content_filters",
                blocked_reason=blocked_reason, details=details,
            )

        logger.info("Content Filters: image is safe")
        return ValidationResult(is_safe=True, layer="content_filters", details=details)

    def analyze_image_file(
        self,
        image_path: str,
        **kwargs,
    ) -> ValidationResult:
        """Convenience: read a file and call analyze_image()."""
        with open(image_path, "rb") as f:
            return self.analyze_image(f.read(), **kwargs)

    # -----------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _extract_text_severities(response) -> dict:
        """Extract severity dict from an analyze_text response."""
        def _get(cat):
            return next(
                (i.severity for i in response.categories_analysis if i.category == cat), 0
            )
        return {
            "hate": _get(TextCategory.HATE),
            "self_harm": _get(TextCategory.SELF_HARM),
            "sexual": _get(TextCategory.SEXUAL),
            "violence": _get(TextCategory.VIOLENCE),
        }

    @staticmethod
    def _extract_image_severities(response) -> dict:
        """Extract severity dict from an analyze_image response."""
        def _get(cat):
            return next(
                (i.severity for i in response.categories_analysis if i.category == cat), 0
            )
        return {
            "hate": _get(ImageCategory.HATE),
            "self_harm": _get(ImageCategory.SELF_HARM),
            "sexual": _get(ImageCategory.SEXUAL),
            "violence": _get(ImageCategory.VIOLENCE),
        }
