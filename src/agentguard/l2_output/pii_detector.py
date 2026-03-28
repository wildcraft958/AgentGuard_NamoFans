"""
AgentGuard – PII Detector module.

Detects and redacts Personally Identifiable Information (PII) in LLM output
using the Azure AI Text Analytics SDK.

Azure Service: azure-ai-textanalytics (recognize_pii_entities)
Credentials: AZURE_LANGUAGE_ENDPOINT + AZURE_LANGUAGE_KEY
"""

import logging
import os

from dotenv import load_dotenv
from azure.ai.textanalytics import TextAnalyticsClient
from azure.ai.textanalytics.aio import TextAnalyticsClient as AsyncTextAnalyticsClient
from azure.core.credentials import AzureKeyCredential

from agentguard.models import ValidationResult

load_dotenv()

logger = logging.getLogger("agentguard.pii_detector")


class PIIDetector:
    """Detects PII in LLM output using Azure Text Analytics.

    Uses recognize_pii_entities() which returns both detected entities
    and an auto-redacted version of the text.
    """

    def __init__(self, endpoint: str = None, key: str = None):
        """
        Args:
            endpoint: Azure Language Service endpoint URL.
            key: Azure Language Service subscription key.
        """
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
        text: str,
        block_on_pii: bool = True,
        allowed_categories: list = None,
    ) -> ValidationResult:
        """
        Analyze text for PII entities.

        Args:
            text: The LLM output text to scan for PII.
            block_on_pii: Whether to mark as unsafe when PII is found.
            allowed_categories: PII categories to ignore (e.g. ["PersonType", "Organization"]).

        Returns:
            ValidationResult with detected PII details and redacted_text.
        """
        allowed_categories = allowed_categories or []
        logger.info("Running PII detection check...")

        try:
            result = self.client.recognize_pii_entities([text])
            doc = result[0]

            if doc.is_error:
                logger.error("PII detection error: %s", doc.error.message)
                return ValidationResult(
                    is_safe=False,
                    layer="pii_detector",
                    blocked_reason=f"PII detection API error – blocking as fail-safe: {doc.error.message}",
                    details={"error": doc.error.message},
                )

        except Exception as e:
            logger.error("PII detection failed: %s", e)
            return ValidationResult(
                is_safe=False,
                layer="pii_detector",
                blocked_reason=f"PII detection API error – blocking as fail-safe: {e}",
                details={"error": str(e)},
            )

        # Filter out allowed categories
        flagged_entities = [
            {
                "text": entity.text,
                "category": entity.category,
                "subcategory": entity.subcategory,
                "confidence_score": entity.confidence_score,
            }
            for entity in doc.entities
            if entity.category not in allowed_categories
        ]

        details = {
            "redacted_text": doc.redacted_text,
            "entities": flagged_entities,
            "entity_count": len(flagged_entities),
        }

        if flagged_entities and block_on_pii:
            categories_found = sorted(set(e["category"] for e in flagged_entities))
            blocked_reason = f"PII detected in output: {', '.join(categories_found)}"
            logger.warning("PII Detector BLOCKED: %s", blocked_reason)
            return ValidationResult(
                is_safe=False,
                layer="pii_detector",
                blocked_reason=blocked_reason,
                details=details,
            )

        if flagged_entities:
            logger.info(
                "PII detected but not blocking (block_on_pii=False): %d entities",
                len(flagged_entities),
            )
        else:
            logger.info("PII Detector: no PII found")

        return ValidationResult(is_safe=True, layer="pii_detector", details=details)

    # ------------------------------------------------------------------
    # Async variant — uses azure.ai.textanalytics.aio for real cancellation
    # ------------------------------------------------------------------

    def _get_async_client(self) -> AsyncTextAnalyticsClient:
        if not hasattr(self, "_async_client") or self._async_client is None:
            self._async_client = AsyncTextAnalyticsClient(
                endpoint=self.endpoint,
                credential=AzureKeyCredential(self.key),
            )
        return self._async_client

    async def aanalyze(
        self,
        text: str,
        block_on_pii: bool = True,
        allowed_categories: list = None,
    ) -> ValidationResult:
        """Async version of analyze(). Uses azure.ai.textanalytics.aio."""
        allowed_categories = allowed_categories or []
        logger.info("Running PII detection check (async)...")

        try:
            client = self._get_async_client()
            result = await client.recognize_pii_entities([text])
            doc = result[0]

            if doc.is_error:
                logger.error("PII detection error (async): %s", doc.error.message)
                return ValidationResult(
                    is_safe=False,
                    layer="pii_detector",
                    blocked_reason=(
                        f"PII detection API error – blocking as fail-safe: {doc.error.message}"
                    ),
                    details={"error": doc.error.message},
                )
        except Exception as e:
            logger.error("PII detection failed (async): %s", e)
            return ValidationResult(
                is_safe=False,
                layer="pii_detector",
                blocked_reason=f"PII detection API error – blocking as fail-safe: {e}",
                details={"error": str(e)},
            )

        flagged_entities = [
            {
                "text": entity.text,
                "category": entity.category,
                "subcategory": entity.subcategory,
                "confidence_score": entity.confidence_score,
            }
            for entity in doc.entities
            if entity.category not in allowed_categories
        ]

        details = {
            "redacted_text": doc.redacted_text,
            "entities": flagged_entities,
            "entity_count": len(flagged_entities),
        }

        if flagged_entities and block_on_pii:
            categories_found = sorted(set(e["category"] for e in flagged_entities))
            blocked_reason = f"PII detected in output: {', '.join(categories_found)}"
            logger.warning("PII Detector BLOCKED (async): %s", blocked_reason)
            return ValidationResult(
                is_safe=False,
                layer="pii_detector",
                blocked_reason=blocked_reason,
                details=details,
            )

        return ValidationResult(is_safe=True, layer="pii_detector", details=details)

    async def aclose(self):
        """Close the async Azure client."""
        if hasattr(self, "_async_client") and self._async_client is not None:
            await self._async_client.close()
            self._async_client = None
