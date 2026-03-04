"""
AgentGuard – Guardian facade.

The main entry point for AgentGuard. Orchestrates all security layers
and provides the validate_input() / validate_output() interface.
"""

import logging
import time

from agentguard.config import load_config, AgentGuardConfig
from agentguard.models import (
    GuardMode,
    InputValidationResult,
    ValidationResult,
    SENSITIVITY_THRESHOLDS,
)
from agentguard.l1_input.prompt_shields import PromptShields
from agentguard.l1_input.content_filters import ContentFilters
from agentguard.exceptions import InputBlockedError

logger = logging.getLogger("agentguard")


class Guardian:
    """
    AgentGuard Guardian – sits between AI agents and their actions.

    Usage:
        guardian = Guardian("agentguard.yaml")
        result = guardian.validate_input(user_input)
        if not result.is_safe:
            # handle blocked input
    """

    def __init__(self, config_path: str):
        """
        Initialize the Guardian with a config file.

        Args:
            config_path: Path to the agentguard.yaml config file.
        """
        self.config = load_config(config_path)
        self._setup_logging()

        logger.info(
            "AgentGuard initialized (mode=%s, log_level=%s)",
            self.config.mode.value,
            self.config.log_level,
        )

        # Initialize L1 modules
        self._prompt_shields = None
        self._content_filters = None

        if self.config.prompt_shields_enabled:
            try:
                self._prompt_shields = PromptShields(
                    timeout_ms=self.config.max_validation_latency_ms
                )
                logger.info("Prompt Shields module: ENABLED")
            except ValueError as e:
                logger.error("Failed to initialize Prompt Shields: %s", e)

        if self._any_content_filter_enabled() or self.config.image_filters_enabled:
            try:
                self._content_filters = ContentFilters()
                logger.info("Content Filters module: ENABLED (text + image)")
            except ValueError as e:
                logger.error("Failed to initialize Content Filters: %s", e)

    def _setup_logging(self):
        """Configure logging based on config level."""
        level_map = {
            "minimal": logging.WARNING,
            "standard": logging.INFO,
            "detailed": logging.DEBUG,
        }
        log_level = level_map.get(self.config.log_level, logging.INFO)

        # Configure the agentguard logger
        ag_logger = logging.getLogger("agentguard")
        if not ag_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter(
                    "[AgentGuard %(levelname)s] %(name)s - %(message)s"
                )
            )
            ag_logger.addHandler(handler)
        ag_logger.setLevel(log_level)

    def _any_content_filter_enabled(self) -> bool:
        """Check if any content filter category is enabled."""
        return (
            self.config.content_filters_block_toxicity
            or self.config.content_filters_block_violence
            or self.config.content_filters_block_self_harm
        )

    def validate_input(
        self,
        user_input: str,
        documents: list = None,
        images: list = None,
        context: dict = None,
    ) -> InputValidationResult:
        """
        Validate user input through all L1 (Input Security) checks.

        Runs checks in order:
        1. Prompt Shields -- detect prompt injection attacks
        2. Content Filters -- detect harmful content (hate, violence, etc.)
        3. Image Filters -- detect harmful content in images

        Args:
            user_input: The user's text input to validate.
            documents: Optional list of document strings for Prompt Shields.
            images: Optional list of image bytes for Image Filters.
            context: Optional context dict (agent_id, user_role, task_id).

        Returns:
            InputValidationResult indicating whether input is safe.

        Raises:
            InputBlockedError: In enforce mode, if input is blocked.
        """
        if self.config.mode == GuardMode.DRY_RUN:
            logger.info("DRY-RUN mode: skipping all validation checks")
            return InputValidationResult(is_safe=True, results=[])

        start_time = time.time()
        results = []

        # -------------------------------------------------------
        # L1 Check 1: Prompt Shields (Prompt Injection Detection)
        # -------------------------------------------------------
        if self._prompt_shields and self.config.prompt_shields_enabled:
            logger.info("Running Prompt Shields check...")
            ps_result = self._prompt_shields.analyze(user_input, documents)
            results.append(ps_result)

            if not ps_result.is_safe:
                if self.config.block_on_detected_injection:
                    return self._handle_block(
                        results, ps_result, "prompt_shields", start_time
                    )
                else:
                    logger.warning(
                        "Prompt injection detected but blocking is disabled"
                    )

        # -------------------------------------------------------
        # L1 Check 2: Content Filters (Toxicity, Violence, etc.)
        # -------------------------------------------------------
        if self._content_filters and self._any_content_filter_enabled():
            logger.info("Running Content Filters check...")
            # Determine severity threshold from sensitivity config
            sensitivity = self.config.prompt_shields_sensitivity
            threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, 0)

            cf_result = self._content_filters.analyze_text(
                text=user_input,
                block_toxicity=self.config.content_filters_block_toxicity,
                block_violence=self.config.content_filters_block_violence,
                block_self_harm=self.config.content_filters_block_self_harm,
                severity_threshold=threshold,
            )
            results.append(cf_result)

            if not cf_result.is_safe:
                return self._handle_block(
                    results, cf_result, "content_filters", start_time
                )

        # -------------------------------------------------------
        # L1 Check 3: Image Content Filters (Harmful Image Detection)
        # -------------------------------------------------------
        if self._content_filters and self.config.image_filters_enabled and images:
            sensitivity = self.config.prompt_shields_sensitivity
            threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, 0)

            for i, image_data in enumerate(images):
                logger.info("Running Image Content Filters on image %d/%d...", i + 1, len(images))
                img_result = self._content_filters.analyze_image(
                    image_data=image_data,
                    block_hate=self.config.image_filters_block_hate,
                    block_violence=self.config.image_filters_block_violence,
                    block_self_harm=self.config.image_filters_block_self_harm,
                    block_sexual=self.config.image_filters_block_sexual,
                    severity_threshold=threshold,
                )
                results.append(img_result)

                if not img_result.is_safe:
                    return self._handle_block(
                        results, img_result, "content_filters", start_time
                    )

        elapsed_ms = (time.time() - start_time) * 1000
        logger.info("All L1 checks passed (%.1fms)", elapsed_ms)

        return InputValidationResult(is_safe=True, results=results)

    def validate_output(self, model_output: str) -> InputValidationResult:
        """
        Validate model output through L2 checks.

        Stub for future L2 implementation (hallucination detection, PII, etc.).

        Args:
            model_output: The LLM's output text to validate.

        Returns:
            InputValidationResult (currently always safe – L2 not yet implemented).
        """
        logger.info("L2 output validation: not yet implemented, passing through")
        return InputValidationResult(is_safe=True, results=[])

    def detect_patterns(self, call) -> None:
        """L3 pattern detection stub."""
        logger.debug("L3 pattern detection: not yet implemented")

    def enforce_rbac(self, call, context: dict) -> None:
        """L4 RBAC enforcement stub."""
        logger.debug("L4 RBAC enforcement: not yet implemented")

    def detect_behavioral_anomaly(self, call, context: dict) -> None:
        """L4 behavioral anomaly detection stub."""
        logger.debug("L4 behavioral anomaly detection: not yet implemented")

    def validate_tool_call(self, call, context: dict) -> None:
        """Tool firewall enforcement stub."""
        logger.debug("Tool firewall: not yet implemented")

    def monitor_post_execution(self, call, result, context: dict) -> None:
        """L4 post-execution monitoring stub."""
        logger.debug("L4 post-execution monitoring: not yet implemented")

    def _handle_block(
        self,
        results: list,
        blocking_result: ValidationResult,
        blocked_by: str,
        start_time: float,
    ) -> InputValidationResult:
        """Handle a blocked input depending on mode (enforce vs monitor)."""
        elapsed_ms = (time.time() - start_time) * 1000

        if self.config.mode == GuardMode.MONITOR:
            logger.warning(
                "MONITOR mode: would block (%s: %s) but allowing through (%.1fms)",
                blocked_by,
                blocking_result.blocked_reason,
                elapsed_ms,
            )
            return InputValidationResult(
                is_safe=True,
                results=results,
                blocked_by=None,
                blocked_reason=None,
            )

        # ENFORCE mode
        logger.warning(
            "ENFORCE mode: BLOCKING input (%s: %s) (%.1fms)",
            blocked_by,
            blocking_result.blocked_reason,
            elapsed_ms,
        )

        result = InputValidationResult(
            is_safe=False,
            results=results,
            blocked_by=blocked_by,
            blocked_reason=blocking_result.blocked_reason,
        )

        raise InputBlockedError(
            reason=blocking_result.blocked_reason,
            details={
                "blocked_by": blocked_by,
                "elapsed_ms": elapsed_ms,
                "validation_result": result,
            },
        )
