"""
AgentGuard – Prompt Shields module.

Detects prompt injection attacks (user prompt attacks and document attacks)
using the Azure AI Content Safety shieldPrompt REST API.

Reference: Azure AI Content Safety Workshop notebook patterns.
API: POST {endpoint}/contentsafety/text:shieldPrompt?api-version=2024-09-01
"""

import logging
import os

import requests
from dotenv import load_dotenv

from agentguard.models import ValidationResult

load_dotenv()

logger = logging.getLogger("agentguard.prompt_shields")

API_VERSION = "2024-09-01"


class PromptShields:
    """Client for Azure AI Content Safety Prompt Shields API."""

    def __init__(self, endpoint: str = None, key: str = None, timeout_ms: int = 5000):
        """
        Args:
            endpoint: Azure Content Safety endpoint URL.
            key: Azure Content Safety subscription key.
            timeout_ms: Request timeout in milliseconds.
        """
        self.endpoint = endpoint or os.environ.get("CONTENT_SAFETY_ENDPOINT", "")
        self.key = key or os.environ.get("CONTENT_SAFETY_KEY", "")
        self.timeout = timeout_ms / 1000.0  # convert to seconds for requests lib

        if not self.endpoint or not self.key:
            raise ValueError(
                "CONTENT_SAFETY_ENDPOINT and CONTENT_SAFETY_KEY must be set "
                "either as arguments or environment variables."
            )

        # Strip trailing slash from endpoint
        self.endpoint = self.endpoint.rstrip("/")

        self.url = (
            f"{self.endpoint}/contentsafety/text:shieldPrompt"
            f"?api-version={API_VERSION}"
        )
        self.headers = {
            "Ocp-Apim-Subscription-Key": self.key,
            "Content-Type": "application/json",
        }

    def analyze(
        self,
        user_prompt: str,
        documents: list = None,
    ) -> ValidationResult:
        """
        Analyze a user prompt (and optional documents) for prompt injection attacks.

        This follows the same pattern used in the Azure AI Content Safety workshop:
        - POST to /contentsafety/text:shieldPrompt
        - Check userPromptAnalysis.attackDetected
        - Check documentsAnalysis[].attackDetected

        Args:
            user_prompt: The user's input prompt to analyze.
            documents: Optional list of document strings to check for indirect attacks.

        Returns:
            ValidationResult with is_safe=False if an attack is detected.
        """
        # Build request payload
        payload = {"userPrompt": user_prompt}
        if documents:
            payload["documents"] = documents

        logger.debug("Prompt Shields request: %s", payload)

        try:
            response = requests.post(
                self.url,
                headers=self.headers,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
            result = response.json()
        except requests.exceptions.Timeout:
            logger.error("Prompt Shields API timed out")
            return ValidationResult(
                is_safe=False,
                layer="prompt_shields",
                blocked_reason="API timeout – blocking as fail-safe",
                details={"error": "timeout"},
            )
        except requests.exceptions.RequestException as e:
            logger.error("Prompt Shields API error: %s", e)
            return ValidationResult(
                is_safe=False,
                layer="prompt_shields",
                blocked_reason=f"API error – blocking as fail-safe: {e}",
                details={"error": str(e)},
            )

        logger.debug("Prompt Shields response: %s", result)

        # Parse response
        user_attack = result.get("userPromptAnalysis", {}).get("attackDetected", False)
        doc_analyses = result.get("documentsAnalysis", [])
        doc_attacks = [d.get("attackDetected", False) for d in doc_analyses]
        any_doc_attack = any(doc_attacks)

        details = {
            "userPromptAttackDetected": user_attack,
            "documentAttacksDetected": doc_attacks,
            "raw_response": result,
        }

        if user_attack or any_doc_attack:
            reasons = []
            if user_attack:
                reasons.append("User prompt injection attack detected")
            if any_doc_attack:
                attacked_indices = [i for i, a in enumerate(doc_attacks) if a]
                reasons.append(
                    f"Document attack detected in document(s): {attacked_indices}"
                )
            blocked_reason = "; ".join(reasons)

            logger.warning("Prompt Shields BLOCKED: %s", blocked_reason)

            return ValidationResult(
                is_safe=False,
                layer="prompt_shields",
                blocked_reason=blocked_reason,
                details=details,
            )

        logger.info("Prompt Shields: input is safe")
        return ValidationResult(
            is_safe=True,
            layer="prompt_shields",
            details=details,
        )
