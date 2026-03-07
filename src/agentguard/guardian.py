"""
AgentGuard – Guardian facade.

The main entry point for AgentGuard. Orchestrates all security layers
and provides the validate_input() / validate_output() interface.
"""

import logging
import time

from agentguard.config import load_config
from agentguard.models import (
    GuardMode,
    InputValidationResult,
    OutputValidationResult,
    ToolCallValidationResult,
    ValidationResult,
    SENSITIVITY_THRESHOLDS,
)
from agentguard.l1_input.prompt_shields import PromptShields
from agentguard.l1_input.content_filters import ContentFilters
from agentguard.exceptions import InputBlockedError, OutputBlockedError, ToolCallBlockedError

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
        self._blocklist_manager = None
        self._blocklist_names = []

        if self.config.prompt_shields_enabled:
            try:
                self._prompt_shields = PromptShields(
                    timeout_ms=self.config.max_validation_latency_ms
                )
                logger.info("Prompt Shields module: ENABLED")
            except ValueError as e:
                logger.error("Failed to initialize Prompt Shields: %s", e)

        needs_content_filters = (
            self._any_content_filter_enabled()
            or self.config.image_filters_enabled
            or self.config.output_toxicity_enabled
            or self.config.pattern_detection_enabled
        )
        if needs_content_filters:
            try:
                self._content_filters = ContentFilters()
                logger.info("Content Filters module: ENABLED (text + image)")
            except ValueError as e:
                logger.error("Failed to initialize Content Filters: %s", e)

        # Initialize L3: Blocklist Manager
        if self.config.pattern_detection_enabled:
            try:
                from agentguard.l1_input.blocklist_manager import BlocklistManager
                self._blocklist_manager = BlocklistManager()
                self._blocklist_names = self._blocklist_manager.sync_blocklists(
                    self.config.blocklists_config
                )
                logger.info(
                    "Blocklist Manager module: ENABLED (%d blocklist(s))",
                    len(self._blocklist_names),
                )
            except (ValueError, Exception) as e:
                logger.error("Failed to initialize Blocklist Manager: %s", e)

        # Initialize L2 modules
        self._output_toxicity = None
        self._pii_detector = None

        if self.config.output_toxicity_enabled and self._content_filters:
            from agentguard.l2_output.output_toxicity import OutputToxicity
            self._output_toxicity = OutputToxicity(self._content_filters)
            logger.info("Output Toxicity module: ENABLED")

        if self.config.pii_detection_enabled:
            try:
                from agentguard.l2_output.pii_detector import PIIDetector
                self._pii_detector = PIIDetector()
                logger.info("PII Detector module: ENABLED")
            except ValueError as e:
                logger.error("Failed to initialize PII Detector: %s", e)

        # Initialize Tool Firewall modules
        self._tool_specific_guards = None
        self._tool_input_analyzer = None
        self._melon_detector = None

        if self.config.tool_firewall_enabled:
            try:
                from agentguard.tool_firewall.tool_specific_guards import ToolSpecificGuards
                self._tool_specific_guards = ToolSpecificGuards(self.config)
                logger.info("Tool Specific Guards module: ENABLED")
            except Exception as e:
                logger.error("Failed to initialize Tool Specific Guards: %s", e)

        if self.config.tool_input_analysis_enabled:
            try:
                from agentguard.tool_firewall.tool_input_analyzer import ToolInputAnalyzer
                ta_client = self._pii_detector.client if self._pii_detector else None
                self._tool_input_analyzer = ToolInputAnalyzer(client=ta_client)
                logger.info("Tool Input Analyzer module: ENABLED")
            except (ValueError, Exception) as e:
                logger.error("Failed to initialize Tool Input Analyzer: %s", e)

        if self.config.melon_enabled:
            try:
                from agentguard.tool_firewall.melon_detector import MelonDetector
                self._melon_detector = MelonDetector(
                    threshold=self.config.melon_threshold,
                    embedding_model=self.config.melon_embedding_model,
                )
                logger.info("MELON Detector module: ENABLED (threshold=%.2f)", self.config.melon_threshold)
            except (ValueError, Exception) as e:
                logger.error("Failed to initialize MELON Detector: %s", e)

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
        # L1 Check 2: Content Filters + Blocklists (single API call)
        # -------------------------------------------------------
        if self._content_filters and (self._any_content_filter_enabled() or self._blocklist_names):
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
                blocklist_names=self._blocklist_names or None,
                halt_on_blocklist_hit=self.config.halt_on_blocklist_hit,
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

    def validate_output(self, model_output: str) -> OutputValidationResult:
        """
        Validate model output through L2 (Output Security) checks.

        Runs checks in order:
        1. Output Toxicity -- detect harmful content in LLM output
        2. PII Detection -- detect and flag PII leakage in output

        Args:
            model_output: The LLM's output text to validate.

        Returns:
            OutputValidationResult indicating whether output is safe.

        Raises:
            OutputBlockedError: In enforce mode, if output is blocked.
        """
        if self.config.mode == GuardMode.DRY_RUN:
            logger.info("DRY-RUN mode: skipping all L2 output checks")
            return OutputValidationResult(is_safe=True, results=[])

        start_time = time.time()
        results = []
        redacted_text = None

        # -------------------------------------------------------
        # L2 Check 1: Output Toxicity (Content Filtering on output)
        # -------------------------------------------------------
        if self._output_toxicity and self.config.output_toxicity_enabled:
            sensitivity = self.config.prompt_shields_sensitivity
            threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, 0)

            tox_result = self._output_toxicity.analyze(
                text=model_output,
                block_toxicity=self.config.content_filters_block_toxicity,
                block_violence=self.config.content_filters_block_violence,
                block_self_harm=self.config.content_filters_block_self_harm,
                severity_threshold=threshold,
            )
            results.append(tox_result)

            if not tox_result.is_safe and self.config.output_toxicity_block:
                return self._handle_output_block(
                    results, tox_result, "output_toxicity", start_time, redacted_text
                )

        # -------------------------------------------------------
        # L2 Check 2: PII Detection
        # -------------------------------------------------------
        if self._pii_detector and self.config.pii_detection_enabled:
            pii_result = self._pii_detector.analyze(
                text=model_output,
                block_on_pii=self.config.pii_block_on_detection,
                allowed_categories=self.config.pii_allowed_categories,
            )
            results.append(pii_result)

            # Capture redacted text regardless of blocking
            if pii_result.details.get("redacted_text"):
                redacted_text = pii_result.details["redacted_text"]

            if not pii_result.is_safe:
                return self._handle_output_block(
                    results, pii_result, "pii_detector", start_time, redacted_text
                )

        elapsed_ms = (time.time() - start_time) * 1000
        logger.info("All L2 checks passed (%.1fms)", elapsed_ms)

        return OutputValidationResult(
            is_safe=True, results=results, redacted_text=redacted_text
        )

    def validate_tool_call(
        self,
        fn_name: str,
        fn_args: dict,
        context: dict = None,
    ) -> ToolCallValidationResult:
        """
        Pre-execution tool firewall: validate tool name + arguments.

        Runs Component 3 (rule-based guards) first, then Component 1
        (entity recognition) if C3 passes.

        Args:
            fn_name: Tool function name.
            fn_args: Tool function arguments dict.
            context: Optional context dict.

        Returns:
            ToolCallValidationResult.

        Raises:
            ToolCallBlockedError: In enforce mode if blocked.
        """
        if self.config.mode == GuardMode.DRY_RUN:
            logger.info("DRY-RUN mode: skipping tool call validation")
            return ToolCallValidationResult(is_safe=True, tool_name=fn_name)

        start_time = time.time()
        results = []

        # --- C3: Tool-Specific Guards (pure Python, zero latency) ---
        if self._tool_specific_guards:
            logger.info("Running Tool-Specific Guards for '%s'...", fn_name)
            c3_result = self._tool_specific_guards.check(fn_name, fn_args)
            results.append(c3_result)

            if not c3_result.is_safe:
                return self._handle_tool_block(
                    results, c3_result, "tool_specific_guards",
                    start_time, fn_name,
                )

        # --- C1: Tool Input Analyzer (Azure entity recognition) ---
        if self._tool_input_analyzer and self.config.tool_input_analysis_enabled:
            logger.info("Running Tool Input Analyzer for '%s'...", fn_name)
            c1_result = self._tool_input_analyzer.analyze(
                fn_name, fn_args,
                blocked_categories_map=self.config.tool_input_blocked_categories,
            )
            results.append(c1_result)

            if not c1_result.is_safe:
                return self._handle_tool_block(
                    results, c1_result, "tool_input_analyzer",
                    start_time, fn_name,
                )

        elapsed_ms = (time.time() - start_time) * 1000
        logger.info("Tool call pre-checks passed for '%s' (%.1fms)", fn_name, elapsed_ms)
        return ToolCallValidationResult(is_safe=True, results=results, tool_name=fn_name)

    def validate_tool_output(
        self,
        fn_name: str,
        fn_args: dict,
        tool_result: str,
        messages: list = None,
        tool_schemas: list = None,
        context: dict = None,
    ) -> ToolCallValidationResult:
        """
        Post-execution tool firewall: MELON contrastive PI detection.

        Called after tool executes, before output enters LLM message history.

        Args:
            fn_name: Tool function name.
            fn_args: Tool function arguments dict.
            tool_result: The tool's output string.
            messages: Full conversation messages (needed for MELON).
            tool_schemas: Tool schemas in OpenAI format (needed for MELON).
            context: Optional context dict.

        Returns:
            ToolCallValidationResult with redacted_output if injection detected.

        Raises:
            ToolCallBlockedError: In enforce mode if blocked and raise_on_injection.
        """
        if self.config.mode == GuardMode.DRY_RUN:
            logger.info("DRY-RUN mode: skipping tool output validation")
            return ToolCallValidationResult(is_safe=True, tool_name=fn_name)

        start_time = time.time()
        results = []

        # --- C2: MELON Detector ---
        if self._melon_detector and self.config.melon_enabled and messages is not None:
            logger.info("Running MELON detection for tool '%s' output...", fn_name)
            c2_result = self._melon_detector.check_tool_output(messages, tool_schemas or [])
            results.append(c2_result)

            if not c2_result.is_safe:
                redacted = c2_result.details.get("redacted_output")
                elapsed_ms = (time.time() - start_time) * 1000

                if self.config.mode == GuardMode.MONITOR:
                    logger.warning(
                        "MONITOR mode: would block tool output (%s: %s) but allowing (%.1fms)",
                        "melon_detector", c2_result.blocked_reason, elapsed_ms,
                    )
                    return ToolCallValidationResult(
                        is_safe=True, results=results, tool_name=fn_name,
                        redacted_output=redacted,
                    )

                # ENFORCE mode
                logger.warning(
                    "ENFORCE mode: BLOCKING tool output (%s: %s) (%.1fms)",
                    "melon_detector", c2_result.blocked_reason, elapsed_ms,
                )

                tc_result = ToolCallValidationResult(
                    is_safe=False, results=results,
                    blocked_by="melon_detector",
                    blocked_reason=c2_result.blocked_reason,
                    redacted_output=redacted,
                    tool_name=fn_name,
                )

                if self.config.melon_raise_on_injection:
                    raise ToolCallBlockedError(
                        reason=c2_result.blocked_reason,
                        details={
                            "blocked_by": "melon_detector",
                            "elapsed_ms": elapsed_ms,
                            "validation_result": tc_result,
                        },
                    )
                return tc_result

        elapsed_ms = (time.time() - start_time) * 1000
        logger.info("Tool output post-checks passed for '%s' (%.1fms)", fn_name, elapsed_ms)
        return ToolCallValidationResult(is_safe=True, results=results, tool_name=fn_name)

    def enforce_rbac(self, call, context: dict) -> None:
        """L4 RBAC enforcement stub."""
        logger.debug("L4 RBAC enforcement: not yet implemented")

    def detect_behavioral_anomaly(self, call, context: dict) -> None:
        """L4 behavioral anomaly detection stub."""
        logger.debug("L4 behavioral anomaly detection: not yet implemented")

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

    def _handle_tool_block(
        self,
        results: list,
        blocking_result: ValidationResult,
        blocked_by: str,
        start_time: float,
        tool_name: str,
    ) -> ToolCallValidationResult:
        """Handle a blocked tool call depending on mode (enforce vs monitor)."""
        elapsed_ms = (time.time() - start_time) * 1000

        if self.config.mode == GuardMode.MONITOR:
            logger.warning(
                "MONITOR mode: would block tool call (%s: %s) but allowing (%.1fms)",
                blocked_by, blocking_result.blocked_reason, elapsed_ms,
            )
            return ToolCallValidationResult(
                is_safe=True, results=results, tool_name=tool_name,
            )

        # ENFORCE mode
        logger.warning(
            "ENFORCE mode: BLOCKING tool call (%s: %s) (%.1fms)",
            blocked_by, blocking_result.blocked_reason, elapsed_ms,
        )

        result = ToolCallValidationResult(
            is_safe=False, results=results,
            blocked_by=blocked_by,
            blocked_reason=blocking_result.blocked_reason,
            tool_name=tool_name,
        )

        raise ToolCallBlockedError(
            reason=blocking_result.blocked_reason,
            details={
                "blocked_by": blocked_by,
                "elapsed_ms": elapsed_ms,
                "validation_result": result,
            },
        )

    def _handle_output_block(
        self,
        results: list,
        blocking_result: ValidationResult,
        blocked_by: str,
        start_time: float,
        redacted_text: str = None,
    ) -> OutputValidationResult:
        """Handle a blocked output depending on mode (enforce vs monitor)."""
        elapsed_ms = (time.time() - start_time) * 1000

        if self.config.mode == GuardMode.MONITOR:
            logger.warning(
                "MONITOR mode: would block output (%s: %s) but allowing through (%.1fms)",
                blocked_by,
                blocking_result.blocked_reason,
                elapsed_ms,
            )
            return OutputValidationResult(
                is_safe=True,
                results=results,
                redacted_text=redacted_text,
            )

        # ENFORCE mode
        logger.warning(
            "ENFORCE mode: BLOCKING output (%s: %s) (%.1fms)",
            blocked_by,
            blocking_result.blocked_reason,
            elapsed_ms,
        )

        result = OutputValidationResult(
            is_safe=False,
            results=results,
            blocked_by=blocked_by,
            blocked_reason=blocking_result.blocked_reason,
            redacted_text=redacted_text,
        )

        raise OutputBlockedError(
            reason=blocking_result.blocked_reason,
            details={
                "blocked_by": blocked_by,
                "elapsed_ms": elapsed_ms,
                "validation_result": result,
            },
        )
