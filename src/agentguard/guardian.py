"""
AgentGuard – Guardian facade.

The main entry point for AgentGuard. Orchestrates all security layers
and provides the validate_input() / validate_output() interface.
"""

import logging
import time

from opentelemetry.trace import Tracer

from agentguard.config import load_config
from agentguard.telemetry import init_telemetry
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
from agentguard.l1_input.fast_injection_detect import fast_inject_detect
from agentguard.audit_log import AuditLog
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

        # Initialize OTel telemetry (only when enabled in config)
        self._tracer: Tracer | None = None
        self._meter = None
        if self.config.telemetry_enabled:
            self._tracer, self._meter = init_telemetry(
                service_name=self.config.telemetry_service_name,
                otlp_endpoint=self.config.telemetry_endpoint,
            )
            logger.info(
                "OTel telemetry: ENABLED (service=%s, endpoint=%s)",
                self.config.telemetry_service_name,
                self.config.telemetry_endpoint or "console",
            )

        # Initialize Audit Log
        self._audit: AuditLog | None = None
        if self.config.audit_enabled:
            try:
                self._audit = AuditLog(self.config.audit_db_path)
                logger.info("Audit Log: ENABLED (%s)", self.config.audit_db_path)
            except Exception as e:
                logger.error("Failed to initialize Audit Log: %s", e)

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
        self._groundedness_detector = None

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

        if self.config.groundedness_enabled:
            try:
                from agentguard.l2_output.groundedness_detector import GroundednessDetector
                self._groundedness_detector = GroundednessDetector()
                logger.info("Groundedness Detector module: ENABLED")
            except ValueError as e:
                logger.error("Failed to initialize Groundedness Detector: %s", e)

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
                    judge_model=self.config.melon_judge_model,
                )
                logger.info(
                    "MELON Detector module: ENABLED (LLM judge, model=%s)",
                    self.config.melon_judge_model or "TFY_MODEL",
                )
            except (ValueError, Exception) as e:
                logger.error("Failed to initialize MELON Detector: %s", e)

        # Initialize L4: RBAC + Behavioral Anomaly
        self._l4_rbac = None
        self._l4_behavioral = None

        if self.config.rbac_enabled:
            from agentguard.l4_rbac import L4RBACEngine
            self._l4_rbac = L4RBACEngine(self.config)
            logger.info("L4 RBAC Engine: ENABLED")

        if self.config.behavioral_monitoring_enabled:
            from agentguard.l4_behavioral import BehavioralAnomalyDetector
            self._l4_behavioral = BehavioralAnomalyDetector(self.config)
            logger.info("L4 Behavioral Anomaly Detector: ENABLED")

        # Initialize C4: Approval Workflow (HITL / AITL)
        self._approval_workflow = None
        if self.config.approval_workflow_enabled:
            try:
                from agentguard.tool_firewall.approval_workflow import ApprovalWorkflow
                self._approval_workflow = ApprovalWorkflow(self.config)
                logger.info(
                    "Approval Workflow module: ENABLED (mode=%s)",
                    self.config.approval_workflow_mode,
                )
            except Exception as e:
                logger.error("Failed to initialize Approval Workflow: %s", e)

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

        with self._span("agentguard.validate_input") as parent_span:
            # -------------------------------------------------------
            # L1 Check 0: Fast Offline Injection Pre-filter (zero latency)
            # -------------------------------------------------------
            with self._span("agentguard.check.fast_inject_detect"):
                detected, matched_pattern = fast_inject_detect(user_input)
            if detected:
                logger.info("Fast inject pre-filter matched pattern: %s", matched_pattern)
                from agentguard.models import ValidationResult
                fake_result = ValidationResult(
                    is_safe=False,
                    layer="l1_input",
                    blocked_reason=f"Prompt injection pattern detected: {matched_pattern}",
                )
                results.append(fake_result)
                return self._handle_block(results, fake_result, "fast_inject_detect", start_time, span=parent_span)

            # -------------------------------------------------------
            # L1 Check 1: Prompt Shields (Prompt Injection Detection)
            # -------------------------------------------------------
            if self._prompt_shields and self.config.prompt_shields_enabled:
                logger.info("Running Prompt Shields check...")
                with self._span("agentguard.check.prompt_shields"):
                    ps_result = self._prompt_shields.analyze(user_input, documents)
                results.append(ps_result)

                if not ps_result.is_safe:
                    if self.config.block_on_detected_injection:
                        return self._handle_block(
                            results, ps_result, "prompt_shields", start_time, span=parent_span
                        )
                    else:
                        logger.warning(
                            "Prompt injection detected but blocking is disabled"
                        )

            # -------------------------------------------------------
            # L1 Check 2: Content Filters + Blocklists (single API call)
            # -------------------------------------------------------
            if self._content_filters and (
                self._any_content_filter_enabled() or self._blocklist_names
            ):
                logger.info("Running Content Filters check...")
                # Determine severity threshold from sensitivity config
                sensitivity = self.config.prompt_shields_sensitivity
                threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, 0)

                with self._span("agentguard.check.content_filters"):
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
                        results, cf_result, "content_filters", start_time, span=parent_span
                    )

            # -------------------------------------------------------
            # L1 Check 3: Image Content Filters (Harmful Image Detection)
            # -------------------------------------------------------
            if self._content_filters and self.config.image_filters_enabled and images:
                sensitivity = self.config.prompt_shields_sensitivity
                threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, 0)

                for i, image_data in enumerate(images):
                    logger.info(
                        "Running Image Content Filters on image %d/%d...", i + 1, len(images)
                    )
                    with self._span("agentguard.check.image_filters"):
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
                            results, img_result, "image_filters", start_time, span=parent_span
                        )

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info("All L1 checks passed (%.1fms)", elapsed_ms)

            self._notify_security_event(
                action="validate_input", layer="l1_input",
                blocked_by="", reason=None,
                is_safe=True, start_time=start_time, span=parent_span,
            )

        return InputValidationResult(is_safe=True, results=results)

    def validate_output(
        self,
        model_output: str,
        user_query: str = None,
        grounding_sources: list = None,
    ) -> OutputValidationResult:
        """
        Validate model output through L2 (Output Security) checks.

        Runs checks in order:
        1. Output Toxicity -- detect harmful content in LLM output
        2. PII Detection -- detect and flag PII leakage in output
        3. Groundedness Detection -- detect hallucinated content

        Args:
            model_output: The LLM's output text to validate.
            user_query: Optional user query for groundedness checking.
            grounding_sources: Optional list of document strings for groundedness.

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

        with self._span("agentguard.validate_output") as parent_span:
            # -------------------------------------------------------
            # L2 Check 1: Output Toxicity (Content Filtering on output)
            # -------------------------------------------------------
            if self._output_toxicity and self.config.output_toxicity_enabled:
                sensitivity = self.config.prompt_shields_sensitivity
                threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, 0)

                with self._span("agentguard.check.output_toxicity"):
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
                        results, tox_result, "output_toxicity", start_time, redacted_text, span=parent_span
                    )

            # -------------------------------------------------------
            # L2 Check 2: PII Detection
            # -------------------------------------------------------
            if self._pii_detector and self.config.pii_detection_enabled:
                with self._span("agentguard.check.pii_detector"):
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
                        results, pii_result, "pii_detector", start_time, redacted_text, span=parent_span
                    )

            # -------------------------------------------------------
            # L2 Check 3: Groundedness Detection (Hallucination Detection)
            # -------------------------------------------------------
            if self._groundedness_detector and self.config.groundedness_enabled:
                if user_query or grounding_sources:
                    logger.info("Running Groundedness Detection check...")
                    with self._span("agentguard.check.groundedness_detector"):
                        ground_result = self._groundedness_detector.analyze(
                            text=model_output,
                            user_query=user_query,
                            grounding_sources=grounding_sources,
                            confidence_threshold=self.config.groundedness_confidence_threshold,
                            block_on_high_confidence=self.config.groundedness_block_on_high_confidence,
                        )
                    results.append(ground_result)

                    if not ground_result.is_safe:
                        self._set_span_attrs(
                            parent_span,
                            is_safe=False,
                            blocked_by="groundedness_detector",
                            blocked_reason=ground_result.blocked_reason,
                        )
                        self._record_metrics(
                            "l2_output", "groundedness_detector", "block", start_time
                        )
                        return self._handle_output_block(
                            results, ground_result, "groundedness_detector",
                            start_time, redacted_text
                        )

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info("All L2 checks passed (%.1fms)", elapsed_ms)

            self._notify_security_event(
                action="validate_output", layer="l2_output",
                blocked_by="", reason=None,
                is_safe=True, start_time=start_time, span=parent_span,
            )

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
        ctx = context or {}

        with self._span("agentguard.validate_tool_call") as parent_span:
            # --- L4a: RBAC check (zero-trust default-deny) ---
            if self._l4_rbac:
                from agentguard.l4_rbac import AccessContext, infer_verb, infer_sensitivity
                rbac_ctx = AccessContext(
                    agent_role=ctx.get("agent_role", "default_agent"),
                    tool_name=fn_name,
                    task_id=ctx.get("task_id", ""),
                    action_verb=infer_verb(fn_name),
                    resource_sensitivity=infer_sensitivity(fn_name, fn_args),
                    risk_score=ctx.get("risk_score", 0.0),
                )
                rbac_decision = self._l4_rbac.evaluate(rbac_ctx)
                if rbac_decision.value == "deny":
                    rbac_result = ValidationResult(
                        is_safe=False,
                        layer="l4_rbac",
                        blocked_reason=f"L4 RBAC: role '{rbac_ctx.agent_role}' denied {rbac_ctx.action_verb} on {rbac_ctx.resource_sensitivity} resource via {fn_name}",
                    )
                    results.append(rbac_result)
                    return self._handle_tool_block(
                        results, rbac_result, "l4_rbac", start_time, fn_name,
                        span=parent_span, layer="l4_rbac",
                        l4_rbac_decision=rbac_decision.value,
                    )
                # ELEVATE → route into approval_workflow below (set flag in context)
                if rbac_decision.value == "elevate":
                    ctx = dict(ctx, _l4_elevate=True)

            # --- L4b: Behavioral Anomaly Detection ---
            if self._l4_behavioral:
                from agentguard.l4_rbac import extract_domain
                ba_meta = {
                    "domain": extract_domain(str(fn_args.get("url", ""))),
                    "resource": fn_args.get("path") or fn_args.get("table") or fn_args.get("query", ""),
                }
                ba_result = self._l4_behavioral.score(
                    task_id=ctx.get("task_id", "default"),
                    agent_role=ctx.get("agent_role", "default_agent"),
                    tool_name=fn_name,
                    meta=ba_meta,
                )
                if ba_result.action == "BLOCK":
                    block_reason = f"L4 Behavioral: {', '.join(s.name for s in ba_result.signals)} (score={ba_result.composite_score:.2f})"
                    ba_block = ValidationResult(
                        is_safe=False,
                        layer="l4_behavioral",
                        blocked_reason=block_reason,
                    )
                    results.append(ba_block)
                    return self._handle_tool_block(
                        results, ba_block, "l4_behavioral", start_time, fn_name,
                        span=parent_span, layer="l4_behavioral",
                        l4_signals=str([s.name for s in ba_result.signals]),
                        l4_composite=ba_result.composite_score,
                        l4_action=ba_result.action,
                    )
                if ba_result.action in ("WARN", "ELEVATE"):
                    logger.warning(
                        "L4 behavioral %s for '%s': score=%.2f signals=%s",
                        ba_result.action, fn_name, ba_result.composite_score,
                        [s.name for s in ba_result.signals],
                    )

            block = self._run_c3(fn_name, fn_args, results, start_time, parent_span)
            if block is not None:
                return block

            block = self._run_c1(fn_name, fn_args, results, start_time, parent_span)
            if block is not None:
                return block

            block = self._run_c4(fn_name, fn_args, ctx, results, start_time, parent_span)
            if block is not None:
                return block

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info("Tool call pre-checks passed for '%s' (%.1fms)", fn_name, elapsed_ms)
            self._notify_security_event(
                action="validate_tool_call", layer="tool_firewall",
                blocked_by="", reason=None,
                is_safe=True, start_time=start_time, span=parent_span,
            )

        return ToolCallValidationResult(is_safe=True, results=results, tool_name=fn_name)

    def _run_c3(
        self,
        fn_name: str,
        fn_args: dict,
        results: list,
        start_time: float,
        span=None,
    ) -> ToolCallValidationResult | None:
        """C3: Tool-Specific Guards (pure Python, zero latency). Returns None on pass."""
        if not self._tool_specific_guards:
            return None
        logger.info("Running Tool-Specific Guards for '%s'...", fn_name)
        with self._span("agentguard.check.tool_specific_guards"):
            c3_result = self._tool_specific_guards.check(fn_name, fn_args)
        results.append(c3_result)
        if not c3_result.is_safe:
            return self._handle_tool_block(
                results, c3_result, "tool_specific_guards", start_time, fn_name, span=span,
            )
        return None

    def _run_c1(
        self,
        fn_name: str,
        fn_args: dict,
        results: list,
        start_time: float,
        span=None,
    ) -> ToolCallValidationResult | None:
        """C1: Tool Input Analyzer (Azure entity recognition). Returns None on pass."""
        if not (self._tool_input_analyzer and self.config.tool_input_analysis_enabled):
            return None
        logger.info("Running Tool Input Analyzer for '%s'...", fn_name)
        with self._span("agentguard.check.tool_input_analyzer"):
            c1_result = self._tool_input_analyzer.analyze(
                fn_name, fn_args,
                blocked_categories_map=self.config.tool_input_blocked_categories,
            )
        results.append(c1_result)
        if not c1_result.is_safe:
            return self._handle_tool_block(
                results, c1_result, "tool_input_analyzer", start_time, fn_name, span=span,
            )
        return None

    def _run_c4(
        self,
        fn_name: str,
        fn_args: dict,
        ctx: dict,
        results: list,
        start_time: float,
        span=None,
    ) -> ToolCallValidationResult | None:
        """C4: Approval Workflow (HITL / AITL). Returns None on pass."""
        if not (self._approval_workflow and self.config.approval_workflow_enabled):
            return None
        logger.info("Running Approval Workflow for '%s'...", fn_name)
        with self._span("agentguard.check.approval_workflow"):
            c4_result = self._approval_workflow.check(fn_name, fn_args, ctx)
        results.append(c4_result)
        if not c4_result.is_safe:
            return self._handle_tool_block(
                results, c4_result, "approval_workflow", start_time, fn_name, span=span,
            )
        return None

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

        with self._span("agentguard.validate_tool_output") as parent_span:
            # --- C2: MELON Detector ---
            if self._melon_detector and self.config.melon_enabled and messages is not None:
                logger.info("Running MELON detection for tool '%s' output...", fn_name)
                # Ensure the tool result is in the messages list so MELON's
                # role check (messages[-1]["role"] == "tool") passes.
                melon_messages = list(messages)
                if not melon_messages or (
                    isinstance(melon_messages[-1], dict)
                    and melon_messages[-1].get("role") != "tool"
                ):
                    melon_messages = melon_messages + [
                        {"role": "tool", "content": tool_result, "tool_call_id": "agentguard_synthetic"}
                    ]
                with self._span("agentguard.check.melon_detector"):
                    c2_result = self._melon_detector.check_tool_output(
                        melon_messages, tool_schemas or []
                    )
                results.append(c2_result)

                if not c2_result.is_safe:
                    redacted = c2_result.details.get("redacted_output")
                    elapsed_ms = (time.time() - start_time) * 1000

                    if self.config.mode == GuardMode.MONITOR:
                        logger.warning(
                            "MONITOR mode: would block tool output (%s: %s) but allowing (%.1fms)",
                            "melon_detector", c2_result.blocked_reason, elapsed_ms,
                        )
                        self._notify_security_event(
                            action="validate_tool_output", layer="tool_firewall",
                            blocked_by="melon_detector",
                            reason="MONITOR: would block via melon_detector",
                            is_safe=True, start_time=start_time, span=parent_span,
                            metadata={"tool_name": fn_name, "elapsed_ms": elapsed_ms},
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
                    self._notify_security_event(
                        action="validate_tool_output", layer="tool_firewall",
                        blocked_by="melon_detector",
                        reason=c2_result.blocked_reason,
                        is_safe=False, start_time=start_time, span=parent_span,
                        metadata={"tool_name": fn_name, "elapsed_ms": elapsed_ms},
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
            self._notify_security_event(
                action="validate_tool_output", layer="tool_firewall",
                blocked_by="", reason=None,
                is_safe=True, start_time=start_time, span=parent_span,
            )

        return ToolCallValidationResult(is_safe=True, results=results, tool_name=fn_name)

    def reset_task(self, task_id: str) -> None:
        """Free L4 behavioral state for a completed task."""
        if self._l4_behavioral:
            self._l4_behavioral.reset_task(task_id)

    # ------------------------------------------------------------------
    # Telemetry helpers
    # ------------------------------------------------------------------

    def _span(self, name: str):
        """Return a context-manager span if tracer available, else a no-op."""
        if self._tracer is not None:
            return self._tracer.start_as_current_span(name)
        # Return a no-op context manager that yields None
        from contextlib import nullcontext
        return nullcontext(None)

    def _set_span_attrs(
        self,
        span,
        is_safe: bool,
        blocked_by: str | None = None,
        blocked_reason: str | None = None,
    ) -> None:
        """Set standard attributes on a span (no-op if span is None)."""
        if span is None:
            return
        try:
            span.set_attribute("agentguard.is_safe", is_safe)
            span.set_attribute("agentguard.mode", self.config.mode.value)
            if blocked_by:
                span.set_attribute("agentguard.blocked_by", blocked_by)
            if blocked_reason:
                span.set_attribute("agentguard.blocked_reason", blocked_reason)
        except Exception:
            pass  # Never let telemetry crash the guard

    def _record_metrics(
        self, layer: str, check: str, result: str, start_time: float
    ) -> None:
        """Increment validation counter and record duration histogram."""
        if self._meter is None:
            return
        try:
            elapsed_ms = (time.time() - start_time) * 1000
            attrs = {"layer": layer, "check": check, "result": result}
            self._meter.create_counter(
                "agentguard.validations",
                description="Number of AgentGuard validation decisions",
                unit="1",
            ).add(1, attributes=attrs)
            self._meter.create_histogram(
                "agentguard.validation.duration",
                description="Duration of AgentGuard validation checks",
                unit="ms",
            ).record(elapsed_ms, attributes={"layer": layer, "check": check})
        except Exception:
            pass  # Never let telemetry crash the guard

    # ------------------------------------------------------------------
    # Unified security event notification
    # ------------------------------------------------------------------

    def _notify_security_event(
        self,
        *,
        action: str,
        layer: str,
        blocked_by: str,
        reason: str | None,
        is_safe: bool,
        start_time: float,
        span=None,
        metadata: dict | None = None,
        l4_rbac_decision: str = "",
        l4_signals: str = "[]",
        l4_composite: float = 0.0,
        l4_action: str = "",
    ) -> None:
        """Single notification point for both OTel and SQLite audit log.

        OTel  → span attributes + metrics histogram (performance / SRE observability).
        Audit → structured SQLite record (compliance forensics, 100% local retention).

        This is the ONLY place that writes to both systems simultaneously, eliminating
        the scattered dual-write pattern where _set_span_attrs/_record_metrics and
        _audit.record were called at separate points in the code.
        """
        # OTel: span attributes
        self._set_span_attrs(
            span,
            is_safe=is_safe,
            blocked_by=blocked_by if not is_safe else None,
            blocked_reason=reason if not is_safe else None,
        )
        # OTel: metrics counter + latency histogram
        self._record_metrics(layer, blocked_by, "pass" if is_safe else "block", start_time)
        # Audit log: structured security compliance record
        if self._audit:
            self._audit.record(
                action, layer, is_safe=is_safe,
                reason=reason,
                metadata=metadata,
                l4_rbac_decision=l4_rbac_decision,
                l4_signals=l4_signals,
                l4_composite=l4_composite,
                l4_action=l4_action,
            )

    # ------------------------------------------------------------------
    # Block handlers (enforce vs monitor mode, per layer)
    # ------------------------------------------------------------------

    def _handle_block(
        self,
        results: list,
        blocking_result: ValidationResult,
        blocked_by: str,
        start_time: float,
        span=None,
    ) -> InputValidationResult:
        """Handle a blocked input — single _notify_security_event call covers OTel + audit."""
        elapsed_ms = (time.time() - start_time) * 1000

        if self.config.mode == GuardMode.MONITOR:
            logger.warning(
                "MONITOR mode: would block (%s: %s) but allowing through (%.1fms)",
                blocked_by, blocking_result.blocked_reason, elapsed_ms,
            )
            self._notify_security_event(
                action="validate_input", layer="l1_input",
                blocked_by=blocked_by,
                reason=f"MONITOR: would block via {blocked_by}",
                is_safe=True, start_time=start_time, span=span,
                metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
            )
            return InputValidationResult(is_safe=True, results=results, blocked_by=None, blocked_reason=None)

        # ENFORCE mode
        logger.warning(
            "ENFORCE mode: BLOCKING input (%s: %s) (%.1fms)",
            blocked_by, blocking_result.blocked_reason, elapsed_ms,
        )
        self._notify_security_event(
            action="validate_input", layer="l1_input",
            blocked_by=blocked_by,
            reason=blocking_result.blocked_reason,
            is_safe=False, start_time=start_time, span=span,
            metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
        )
        result = InputValidationResult(
            is_safe=False, results=results,
            blocked_by=blocked_by, blocked_reason=blocking_result.blocked_reason,
        )
        raise InputBlockedError(
            reason=blocking_result.blocked_reason,
            details={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms, "validation_result": result},
        )

    def _handle_tool_block(
        self,
        results: list,
        blocking_result: ValidationResult,
        blocked_by: str,
        start_time: float,
        tool_name: str,
        span=None,
        layer: str = "tool_firewall",
        **l4_kwargs,
    ) -> ToolCallValidationResult:
        """Handle a blocked tool call — single _notify_security_event call covers OTel + audit."""
        elapsed_ms = (time.time() - start_time) * 1000

        if self.config.mode == GuardMode.MONITOR:
            logger.warning(
                "MONITOR mode: would block tool call (%s: %s) but allowing (%.1fms)",
                blocked_by, blocking_result.blocked_reason, elapsed_ms,
            )
            self._notify_security_event(
                action="validate_tool_call", layer=layer,
                blocked_by=blocked_by,
                reason=f"MONITOR: would block via {blocked_by}",
                is_safe=True, start_time=start_time, span=span,
                metadata={"blocked_by": blocked_by, "tool_name": tool_name, "elapsed_ms": elapsed_ms},
                **l4_kwargs,
            )
            return ToolCallValidationResult(is_safe=True, results=results, tool_name=tool_name)

        # ENFORCE mode
        logger.warning(
            "ENFORCE mode: BLOCKING tool call (%s: %s) (%.1fms)",
            blocked_by, blocking_result.blocked_reason, elapsed_ms,
        )
        self._notify_security_event(
            action="validate_tool_call", layer=layer,
            blocked_by=blocked_by,
            reason=blocking_result.blocked_reason,
            is_safe=False, start_time=start_time, span=span,
            metadata={"blocked_by": blocked_by, "tool_name": tool_name, "elapsed_ms": elapsed_ms},
            **l4_kwargs,
        )
        result = ToolCallValidationResult(
            is_safe=False, results=results,
            blocked_by=blocked_by, blocked_reason=blocking_result.blocked_reason,
            tool_name=tool_name,
        )
        raise ToolCallBlockedError(
            reason=blocking_result.blocked_reason,
            details={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms, "validation_result": result},
        )

    def _handle_output_block(
        self,
        results: list,
        blocking_result: ValidationResult,
        blocked_by: str,
        start_time: float,
        redacted_text: str = None,
        span=None,
    ) -> OutputValidationResult:
        """Handle a blocked output — single _notify_security_event call covers OTel + audit."""
        elapsed_ms = (time.time() - start_time) * 1000

        if self.config.mode == GuardMode.MONITOR:
            logger.warning(
                "MONITOR mode: would block output (%s: %s) but allowing through (%.1fms)",
                blocked_by, blocking_result.blocked_reason, elapsed_ms,
            )
            self._notify_security_event(
                action="validate_output", layer="l2_output",
                blocked_by=blocked_by,
                reason=f"MONITOR: would block via {blocked_by}",
                is_safe=True, start_time=start_time, span=span,
                metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
            )
            return OutputValidationResult(is_safe=True, results=results, redacted_text=redacted_text)

        # ENFORCE mode
        logger.warning(
            "ENFORCE mode: BLOCKING output (%s: %s) (%.1fms)",
            blocked_by, blocking_result.blocked_reason, elapsed_ms,
        )
        self._notify_security_event(
            action="validate_output", layer="l2_output",
            blocked_by=blocked_by,
            reason=blocking_result.blocked_reason,
            is_safe=False, start_time=start_time, span=span,
            metadata={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms},
        )
        result = OutputValidationResult(
            is_safe=False, results=results,
            blocked_by=blocked_by, blocked_reason=blocking_result.blocked_reason,
            redacted_text=redacted_text,
        )
        raise OutputBlockedError(
            reason=blocking_result.blocked_reason,
            details={"blocked_by": blocked_by, "elapsed_ms": elapsed_ms, "validation_result": result},
        )
