"""
AgentGuard – Tool Input Analyzer (Component 1).

Uses Azure Text Analytics entity recognition to scan tool arguments
for entities (IP addresses, URLs, file paths, etc.) that shouldn't
reach certain tools.

Reuses the same AZURE_LANGUAGE_ENDPOINT + AZURE_LANGUAGE_KEY as PIIDetector.
"""

import logging
import os

from dotenv import load_dotenv
from azure.ai.textanalytics import TextAnalyticsClient
from azure.core.credentials import AzureKeyCredential

from agentguard.models import ValidationResult

load_dotenv()

logger = logging.getLogger("agentguard.tool_input_analyzer")

LAYER = "tool_input_analyzer"


class ToolInputAnalyzer:
    """Analyzes tool arguments for suspicious entities using Azure entity recognition.

    Per-tool configuration specifies which entity categories to block.
    For example, `read_config_file` might block IPAddress and URL entities
    in its arguments.
    """

    def __init__(self, client: TextAnalyticsClient = None, endpoint: str = None, key: str = None):
        """
        Args:
            client: Existing TextAnalyticsClient to reuse (e.g., from PIIDetector).
            endpoint: Azure Language Service endpoint (fallback if no client).
            key: Azure Language Service key (fallback if no client).
        """
        if client is not None:
            self.client = client
        else:
            self.endpoint = endpoint or os.environ.get("AZURE_LANGUAGE_ENDPOINT", "")
            self.key = key or os.environ.get("AZURE_LANGUAGE_KEY", "")

            if not self.endpoint or not self.key:
                raise ValueError(
                    "AZURE_LANGUAGE_ENDPOINT and AZURE_LANGUAGE_KEY must be set "
                    "either as arguments or environment variables."
                )

            self.client = TextAnalyticsClient(
                endpoint=self.endpoint,
                credential=AzureKeyCredential(self.key),
            )

    def analyze(
        self,
        fn_name: str,
        fn_args: dict,
        blocked_categories_map: dict = None,
    ) -> ValidationResult:
        """
        Analyze tool arguments for blocked entity categories.

        Args:
            fn_name: The tool function name.
            fn_args: The tool function arguments dict.
            blocked_categories_map: Dict mapping tool names to lists of blocked
                entity categories. E.g., {"read_config_file": ["IPAddress", "URL"]}.

        Returns:
            ValidationResult with is_safe=False if blocked entities are found.
        """
        blocked_categories_map = blocked_categories_map or {}
        blocked_categories = blocked_categories_map.get(fn_name, [])

        if not blocked_categories:
            logger.debug("No blocked entity categories for tool '%s', skipping", fn_name)
            return ValidationResult(is_safe=True, layer=LAYER)

        # Serialize all string argument values into one text block
        text_parts = []
        for arg_name, arg_value in fn_args.items():
            if isinstance(arg_value, str):
                text_parts.append(f"{arg_name}: {arg_value}")
            else:
                text_parts.append(f"{arg_name}: {arg_value!s}")

        text = "\n".join(text_parts)
        if not text.strip():
            return ValidationResult(is_safe=True, layer=LAYER)

        logger.info("Running entity recognition on tool '%s' arguments...", fn_name)

        try:
            result = self.client.recognize_entities([text])
            doc = result[0]

            if doc.is_error:
                logger.error("Entity recognition error: %s", doc.error.message)
                return ValidationResult(
                    is_safe=False,
                    layer=LAYER,
                    blocked_reason=f"Entity recognition API error – blocking as fail-safe: {doc.error.message}",
                    details={"error": doc.error.message},
                )

        except Exception as e:
            logger.error("Entity recognition failed: %s", e)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=f"Entity recognition API error – blocking as fail-safe: {e}",
                details={"error": str(e)},
            )

        # Check for blocked entity categories
        flagged_entities = [
            {
                "text": entity.text,
                "category": entity.category,
                "subcategory": entity.subcategory,
                "confidence_score": entity.confidence_score,
            }
            for entity in doc.entities
            if entity.category in blocked_categories
        ]

        details = {
            "all_entities": [
                {"text": e.text, "category": e.category, "confidence": e.confidence_score}
                for e in doc.entities
            ],
            "flagged_entities": flagged_entities,
            "tool_name": fn_name,
        }

        if flagged_entities:
            categories_found = sorted(set(e["category"] for e in flagged_entities))
            entity_texts = [e["text"] for e in flagged_entities]
            reason = (
                f"Blocked entity in tool args: {', '.join(categories_found)} "
                f"({', '.join(entity_texts)})"
            )
            logger.warning("Tool Input Analyzer BLOCKED: %s", reason)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=reason,
                details=details,
            )

        logger.info("Tool Input Analyzer: args are safe for '%s'", fn_name)
        return ValidationResult(is_safe=True, layer=LAYER, details=details)
