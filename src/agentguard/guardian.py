"""
AgentGuard – Guardian facade (agentguard.guardian).

The main entry point for AgentGuard. Thin orchestration layer that
delegates validation logic to _pipeline/ modules:
  - _pipeline.notifier:    OTel + audit writes
  - _pipeline.handlers:    Mode-aware block handling (enforce/monitor)
  - _pipeline.wave_runner: Async parallel check execution
"""

import logging
import time

from agentguard._pipeline.handlers import handle_input_block, handle_output_block, handle_tool_block
from agentguard._pipeline.notifier import Notifier
from agentguard._pipeline.wave_runner import wave_parallel
from agentguard.config import load_config
from agentguard.exceptions import ToolCallBlockedError
from agentguard.l1_input.fast_injection_detect import fast_inject_detect
from agentguard.models import (
    GuardMode,
    InputValidationResult,
    OutputValidationResult,
    ToolCallValidationResult,
    ValidationResult,
    SENSITIVITY_THRESHOLDS,
)
from agentguard.observability.audit import AuditLog
from agentguard.observability.telemetry import init_telemetry

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

        # ── Telemetry ──
        tracer = None
        meter = None
        if self.config.telemetry_enabled:
            tracer, meter = init_telemetry(
                service_name=self.config.telemetry_service_name,
                otlp_endpoint=self.config.telemetry_endpoint,
            )
            logger.info(
                "OTel telemetry: ENABLED (service=%s, endpoint=%s)",
                self.config.telemetry_service_name,
                self.config.telemetry_endpoint or "console",
            )

        # ── Audit Log ──
        audit = None
        if self.config.audit_enabled:
            try:
                audit = AuditLog(self.config.audit_db_path)
                logger.info("Audit Log: ENABLED (%s)", self.config.audit_db_path)
            except Exception as e:
                logger.error("Failed to initialize Audit Log: %s", e)

        # ── Notifier (unified OTel + audit) ──
        self._notifier = Notifier(tracer, meter, audit, self.config.mode.value)

        # ── L1 Input modules ──
        self._prompt_shields = None
        self._content_filters = None
        self._blocklist_manager = None
        self._blocklist_names = []

        if self.config.prompt_shields_enabled:
            try:
                from agentguard.l1_input.prompt_shields import PromptShields

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
                from agentguard.l1_input.content_filters import ContentFilters

                self._content_filters = ContentFilters()
                logger.info("Content Filters module: ENABLED (text + image)")
            except ValueError as e:
                logger.error("Failed to initialize Content Filters: %s", e)

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

        # ── L2 Output modules ──
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

        # ── Tool Firewall modules ──
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
                    judge_model=self.config.melon_judge_model,
                    embedding_model=self.config.melon_embedding_model,
                    low_threshold=self.config.melon_low_threshold,
                    high_threshold=self.config.melon_high_threshold,
                    mode=self.config.melon_mode,
                )
                logger.info(
                    "MELON Detector module: ENABLED (mode=%s, judge=%s, embedding=%s)",
                    self.config.melon_mode,
                    self.config.melon_judge_model or "TFY_MODEL",
                    self.config.melon_embedding_model or "none",
                )
            except (ValueError, Exception) as e:
                logger.error("Failed to initialize MELON Detector: %s", e)

        # ── L4: RBAC + Behavioral Anomaly ──
        self._l4_rbac = None
        self._l4_behavioral = None

        if self.config.rbac_enabled:
            from agentguard.l4.rbac import L4RBACEngine

            self._l4_rbac = L4RBACEngine(self.config)
            logger.info("L4 RBAC Engine: ENABLED")

        if self.config.behavioral_monitoring_enabled:
            from agentguard.l4.behavioral import BehavioralAnomalyDetector

            self._l4_behavioral = BehavioralAnomalyDetector(self.config)
            logger.info("L4 Behavioral Anomaly Detector: ENABLED")

        # ── C4: Approval Workflow (HITL / AITL) ──
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

        # ── Sandbox Executor ──
        self._sandbox_executor = None
        if self.config.sandbox_enabled:
            try:
                from agentguard.sandbox.executor import SandboxedToolExecutor

                policy = self.config.sandbox_policy
                self._sandbox_executor = SandboxedToolExecutor(policy)
                logger.info(
                    "Sandbox Executor: ENABLED (mode=%s, timeout=%ds)",
                    policy.mode,
                    policy.timeout_seconds,
                )
            except Exception as e:
                logger.error("Failed to initialize Sandbox Executor: %s", e)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _setup_logging(self):
        """Configure logging based on config level."""
        level_map = {
            "minimal": logging.WARNING,
            "standard": logging.INFO,
            "detailed": logging.DEBUG,
        }
        log_level = level_map.get(self.config.log_level, logging.INFO)
        ag_logger = logging.getLogger("agentguard")
        if not ag_logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(
                logging.Formatter("[AgentGuard %(levelname)s] %(name)s - %(message)s")
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

    # ------------------------------------------------------------------
    # Delegation to _pipeline.notifier (telemetry + audit)
    # ------------------------------------------------------------------

    @property
    def _audit(self) -> AuditLog | None:
        return self._notifier.audit

    def _span(self, name: str):
        return self._notifier.span(name)

    def _set_span_attrs(self, span, is_safe, blocked_by=None, blocked_reason=None):
        self._notifier.set_span_attrs(span, is_safe, blocked_by, blocked_reason)

    def _record_metrics(self, layer, check, result, start_time):
        self._notifier.record_metrics(layer, check, result, start_time)

    def _notify_security_event(self, **kwargs):
        self._notifier.notify(**kwargs)

    def _handle_block(self, results, blocking_result, blocked_by, start_time, span=None):
        return handle_input_block(
            self.config.mode,
            self._notifier,
            results,
            blocking_result,
            blocked_by,
            start_time,
            span,
        )

    def _handle_tool_block(
        self,
        results,
        blocking_result,
        blocked_by,
        start_time,
        tool_name,
        span=None,
        layer="tool_firewall",
        **l4_kwargs,
    ):
        return handle_tool_block(
            self.config.mode,
            self._notifier,
            results,
            blocking_result,
            blocked_by,
            start_time,
            tool_name,
            span,
            layer,
            **l4_kwargs,
        )

    def _handle_output_block(
        self, results, blocking_result, blocked_by, start_time, redacted_text=None, span=None
    ):
        return handle_output_block(
            self.config.mode,
            self._notifier,
            results,
            blocking_result,
            blocked_by,
            start_time,
            redacted_text,
            span,
        )

    # ==================================================================
    # Sync validation methods
    # ==================================================================

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
        1. Fast offline injection pre-filter (~0ms)
        2. Prompt Shields — detect prompt injection attacks
        3. Content Filters — detect harmful content (hate, violence, etc.)
        4. Image Filters — detect harmful content in images

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
            # --- Wave 0: Fast offline pre-filter ---
            with self._span("agentguard.check.fast_inject_detect"):
                detected, matched_pattern = fast_inject_detect(user_input)
            if detected:
                logger.info("Fast inject pre-filter matched pattern: %s", matched_pattern)
                fake_result = ValidationResult(
                    is_safe=False,
                    layer="l1_input",
                    blocked_reason=f"Prompt injection pattern detected: {matched_pattern}",
                )
                results.append(fake_result)
                return self._handle_block(
                    results, fake_result, "fast_inject_detect", start_time, span=parent_span
                )

            # --- Wave 1: Prompt Shields ---
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
                        logger.warning("Prompt injection detected but blocking is disabled")

            # --- Wave 2: Content Filters + Blocklists ---
            if self._content_filters and (
                self._any_content_filter_enabled() or self._blocklist_names
            ):
                logger.info("Running Content Filters check...")
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

            # --- Wave 3: Image Content Filters ---
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
                action="validate_input",
                layer="l1_input",
                blocked_by="",
                reason=None,
                is_safe=True,
                start_time=start_time,
                span=parent_span,
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
        1. Output Toxicity — detect harmful content in LLM output
        2. PII Detection — detect and flag PII leakage
        3. Groundedness Detection — detect hallucinated content

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
            # --- Check 1: Output Toxicity ---
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
                        results,
                        tox_result,
                        "output_toxicity",
                        start_time,
                        redacted_text,
                        span=parent_span,
                    )

            # --- Check 2: PII Detection ---
            if self._pii_detector and self.config.pii_detection_enabled:
                with self._span("agentguard.check.pii_detector"):
                    pii_result = self._pii_detector.analyze(
                        text=model_output,
                        block_on_pii=self.config.pii_block_on_detection,
                        allowed_categories=self.config.pii_allowed_categories,
                    )
                results.append(pii_result)
                if pii_result.details.get("redacted_text"):
                    redacted_text = pii_result.details["redacted_text"]
                if not pii_result.is_safe:
                    return self._handle_output_block(
                        results,
                        pii_result,
                        "pii_detector",
                        start_time,
                        redacted_text,
                        span=parent_span,
                    )

            # --- Check 3: Groundedness Detection ---
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
                            results,
                            ground_result,
                            "groundedness_detector",
                            start_time,
                            redacted_text,
                        )

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info("All L2 checks passed (%.1fms)", elapsed_ms)
            self._notify_security_event(
                action="validate_output",
                layer="l2_output",
                blocked_by="",
                reason=None,
                is_safe=True,
                start_time=start_time,
                span=parent_span,
            )

        return OutputValidationResult(is_safe=True, results=results, redacted_text=redacted_text)

    def validate_tool_call(
        self,
        fn_name: str,
        fn_args: dict,
        context: dict = None,
    ) -> ToolCallValidationResult:
        """
        Pre-execution tool firewall: validate tool name + arguments.

        Runs L4 RBAC/behavioral first, then C3 (rule-based), C1 (entity), C4 (approval).

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
            # --- L4a: RBAC check ---
            if self._l4_rbac:
                from agentguard.l4.rbac import AccessContext, infer_verb, infer_sensitivity

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
                        results,
                        rbac_result,
                        "l4_rbac",
                        start_time,
                        fn_name,
                        span=parent_span,
                        layer="l4_rbac",
                        l4_rbac_decision=rbac_decision.value,
                    )
                if rbac_decision.value == "elevate":
                    ctx = dict(ctx, _l4_elevate=True)

            # --- L4b: Behavioral Anomaly Detection ---
            if self._l4_behavioral:
                from agentguard.l4.rbac import extract_domain

                ba_meta = {
                    "domain": extract_domain(str(fn_args.get("url", ""))),
                    "resource": fn_args.get("path")
                    or fn_args.get("table")
                    or fn_args.get("query", ""),
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
                        results,
                        ba_block,
                        "l4_behavioral",
                        start_time,
                        fn_name,
                        span=parent_span,
                        layer="l4_behavioral",
                        l4_signals=str([s.name for s in ba_result.signals]),
                        l4_composite=ba_result.composite_score,
                        l4_action=ba_result.action,
                    )
                if ba_result.action in ("WARN", "ELEVATE"):
                    logger.warning(
                        "L4 behavioral %s for '%s': score=%.2f signals=%s",
                        ba_result.action,
                        fn_name,
                        ba_result.composite_score,
                        [s.name for s in ba_result.signals],
                    )

            # --- C3: Tool-Specific Guards ---
            block = self._run_c3(fn_name, fn_args, results, start_time, parent_span)
            if block is not None:
                return block

            # --- C1: Tool Input Analyzer ---
            block = self._run_c1(fn_name, fn_args, results, start_time, parent_span)
            if block is not None:
                return block

            # --- C4: Approval Workflow ---
            block = self._run_c4(fn_name, fn_args, ctx, results, start_time, parent_span)
            if block is not None:
                return block

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info("Tool call pre-checks passed for '%s' (%.1fms)", fn_name, elapsed_ms)
            self._notify_security_event(
                action="validate_tool_call",
                layer="tool_firewall",
                blocked_by="",
                reason=None,
                is_safe=True,
                start_time=start_time,
                span=parent_span,
            )

        return ToolCallValidationResult(is_safe=True, results=results, tool_name=fn_name)

    def _run_c3(self, fn_name, fn_args, results, start_time, span=None):
        """C3: Tool-Specific Guards (pure Python, zero latency). Returns None on pass."""
        if not self._tool_specific_guards:
            return None
        logger.info("Running Tool-Specific Guards for '%s'...", fn_name)
        with self._span("agentguard.check.tool_specific_guards"):
            c3_result = self._tool_specific_guards.check(fn_name, fn_args)
        results.append(c3_result)
        if not c3_result.is_safe:
            return self._handle_tool_block(
                results, c3_result, "tool_specific_guards", start_time, fn_name, span=span
            )
        return None

    def _run_c1(self, fn_name, fn_args, results, start_time, span=None):
        """C1: Tool Input Analyzer (Azure entity recognition). Returns None on pass."""
        if not (self._tool_input_analyzer and self.config.tool_input_analysis_enabled):
            return None
        logger.info("Running Tool Input Analyzer for '%s'...", fn_name)
        with self._span("agentguard.check.tool_input_analyzer"):
            c1_result = self._tool_input_analyzer.analyze(
                fn_name,
                fn_args,
                blocked_categories_map=self.config.tool_input_blocked_categories,
            )
        results.append(c1_result)
        if not c1_result.is_safe:
            return self._handle_tool_block(
                results, c1_result, "tool_input_analyzer", start_time, fn_name, span=span
            )
        return None

    def _run_c4(self, fn_name, fn_args, ctx, results, start_time, span=None):
        """C4: Approval Workflow (HITL / AITL). Returns None on pass."""
        if not (self._approval_workflow and self.config.approval_workflow_enabled):
            return None
        logger.info("Running Approval Workflow for '%s'...", fn_name)
        with self._span("agentguard.check.approval_workflow"):
            c4_result = self._approval_workflow.check(fn_name, fn_args, ctx)
        results.append(c4_result)
        if not c4_result.is_safe:
            return self._handle_tool_block(
                results, c4_result, "approval_workflow", start_time, fn_name, span=span
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
                melon_messages = list(messages)
                if not melon_messages or (
                    isinstance(melon_messages[-1], dict)
                    and melon_messages[-1].get("role") != "tool"
                ):
                    melon_messages = melon_messages + [
                        {
                            "role": "tool",
                            "content": tool_result,
                            "tool_call_id": "agentguard_synthetic",
                        }
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
                            "melon_detector",
                            c2_result.blocked_reason,
                            elapsed_ms,
                        )
                        self._notify_security_event(
                            action="validate_tool_output",
                            layer="tool_firewall",
                            blocked_by="melon_detector",
                            reason="MONITOR: would block via melon_detector",
                            is_safe=True,
                            start_time=start_time,
                            span=parent_span,
                            metadata={"tool_name": fn_name, "elapsed_ms": elapsed_ms},
                        )
                        return ToolCallValidationResult(
                            is_safe=True,
                            results=results,
                            tool_name=fn_name,
                            redacted_output=redacted,
                        )

                    # ENFORCE mode
                    logger.warning(
                        "ENFORCE mode: BLOCKING tool output (%s: %s) (%.1fms)",
                        "melon_detector",
                        c2_result.blocked_reason,
                        elapsed_ms,
                    )
                    self._notify_security_event(
                        action="validate_tool_output",
                        layer="tool_firewall",
                        blocked_by="melon_detector",
                        reason=c2_result.blocked_reason,
                        is_safe=False,
                        start_time=start_time,
                        span=parent_span,
                        metadata={"tool_name": fn_name, "elapsed_ms": elapsed_ms},
                    )
                    tc_result = ToolCallValidationResult(
                        is_safe=False,
                        results=results,
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
                action="validate_tool_output",
                layer="tool_firewall",
                blocked_by="",
                reason=None,
                is_safe=True,
                start_time=start_time,
                span=parent_span,
            )

        return ToolCallValidationResult(is_safe=True, results=results, tool_name=fn_name)

    def reset_task(self, task_id: str) -> None:
        """Free L4 behavioral state for a completed task."""
        if self._l4_behavioral:
            self._l4_behavioral.reset_task(task_id)

    # ==================================================================
    # Async Tiered Pipeline — wave-based concurrent execution
    # ==================================================================

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close_async_clients()

    async def _close_async_clients(self):
        """Close all native async clients (httpx, Azure aio, AsyncOpenAI)."""
        for checker in [
            self._prompt_shields,
            self._content_filters,
            getattr(self, "_pii_detector", None),
            getattr(self, "_groundedness_detector", None),
            getattr(self, "_melon_detector", None),
            getattr(self, "_tool_input_analyzer", None),
            getattr(self, "_approval_workflow", None),
        ]:
            if checker and hasattr(checker, "aclose"):
                try:
                    await checker.aclose()
                except Exception:
                    pass

    async def avalidate_input(
        self,
        user_input: str,
        documents: list = None,
        images: list = None,
        context: dict = None,
    ) -> InputValidationResult:
        """
        Async tiered input validation.

        Wave 0: fast_inject_detect (offline, ~0ms)
        Wave 1: prompt_shields + content_filters + image_filters (parallel)
        """
        if self.config.mode == GuardMode.DRY_RUN:
            return InputValidationResult(is_safe=True, results=[])

        start_time = time.time()
        results = []

        with self._span("agentguard.validate_input") as parent_span:
            # --- Wave 0: Local pre-flight (sync, ~0ms) ---
            with self._span("agentguard.check.fast_inject_detect"):
                detected, matched_pattern = fast_inject_detect(user_input)
            if detected:
                logger.info("Fast inject pre-filter matched: %s", matched_pattern)
                fake_result = ValidationResult(
                    is_safe=False,
                    layer="l1_input",
                    blocked_reason=f"Prompt injection pattern detected: {matched_pattern}",
                )
                results.append(fake_result)
                self._set_span_attrs(
                    parent_span,
                    is_safe=False,
                    blocked_by="fast_inject",
                    blocked_reason=fake_result.blocked_reason,
                )
                self._record_metrics("l1_input", "fast_inject_detect", "block", start_time)
                if self._audit:
                    self._audit.record(
                        "validate_input",
                        "l1_input",
                        is_safe=False,
                        reason="Fast inject detect",
                        metadata={"blocked_by": "fast_inject", "pattern": matched_pattern},
                    )
                return self._handle_block(results, fake_result, "fast_inject", start_time)

            # --- Wave 1: Cheap API checks (async parallel) ---
            wave1 = []
            sensitivity = self.config.prompt_shields_sensitivity
            threshold = SENSITIVITY_THRESHOLDS.get(sensitivity, 0)

            if self._prompt_shields and self.config.prompt_shields_enabled:
                wave1.append(
                    (
                        "prompt_shields",
                        self._prompt_shields.aanalyze(user_input, documents),
                    )
                )

            if self._content_filters and (
                self._any_content_filter_enabled() or self._blocklist_names
            ):
                wave1.append(
                    (
                        "content_filters",
                        self._content_filters.aanalyze_text(
                            text=user_input,
                            block_toxicity=self.config.content_filters_block_toxicity,
                            block_violence=self.config.content_filters_block_violence,
                            block_self_harm=self.config.content_filters_block_self_harm,
                            severity_threshold=threshold,
                            blocklist_names=self._blocklist_names or None,
                            halt_on_blocklist_hit=self.config.halt_on_blocklist_hit,
                        ),
                    )
                )

            if self._content_filters and self.config.image_filters_enabled and images:
                for i, image_data in enumerate(images):
                    wave1.append(
                        (
                            f"image_filters_{i}",
                            self._content_filters.aanalyze_image(
                                image_data=image_data,
                                block_hate=self.config.image_filters_block_hate,
                                block_violence=self.config.image_filters_block_violence,
                                block_self_harm=self.config.image_filters_block_self_harm,
                                block_sexual=self.config.image_filters_block_sexual,
                                severity_threshold=threshold,
                            ),
                        )
                    )

            if wave1:
                w1_results, block = await wave_parallel(wave1)
                for name, result in w1_results:
                    results.append(result)
                if block:
                    name, result = block
                    self._set_span_attrs(
                        parent_span,
                        is_safe=False,
                        blocked_by=name,
                        blocked_reason=result.blocked_reason,
                    )
                    self._record_metrics("l1_input", name, "block", start_time)
                    return self._handle_block(results, result, name, start_time)

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info("All L1 checks passed (async, %.1fms)", elapsed_ms)
            self._set_span_attrs(parent_span, is_safe=True)
            self._record_metrics("l1_input", "validate_input", "pass", start_time)

        return InputValidationResult(is_safe=True, results=results)

    async def avalidate_output(
        self,
        model_output: str,
        user_query: str = None,
        grounding_sources: list = None,
    ) -> OutputValidationResult:
        """
        Async tiered output validation.

        Wave 1: output_toxicity + pii_detection (parallel, cheap)
        Wave 2: groundedness (expensive LLM, only if Wave 1 passes)
        """
        if self.config.mode == GuardMode.DRY_RUN:
            return OutputValidationResult(is_safe=True, results=[])

        start_time = time.time()
        results = []
        redacted_text = None

        with self._span("agentguard.validate_output") as parent_span:
            # --- Wave 1: Cheap checks (async parallel) ---
            wave1 = []
            if self._output_toxicity and self.config.output_toxicity_enabled:
                wave1.append(
                    (
                        "output_toxicity",
                        self._output_toxicity.aanalyze(
                            text=model_output,
                            block_toxicity=True,
                            block_violence=True,
                            block_self_harm=True,
                        ),
                    )
                )

            if self._pii_detector and self.config.pii_detection_enabled:
                wave1.append(
                    (
                        "pii_detector",
                        self._pii_detector.aanalyze(
                            text=model_output,
                            block_on_pii=self.config.pii_block_on_detection,
                            allowed_categories=self.config.pii_allowed_categories,
                        ),
                    )
                )

            if wave1:
                w1_results, block = await wave_parallel(wave1)
                for name, result in w1_results:
                    results.append(result)
                    if name == "pii_detector" and result.details:
                        redacted_text = result.details.get("redacted_text")
                if block:
                    name, result = block
                    self._set_span_attrs(
                        parent_span,
                        is_safe=False,
                        blocked_by=name,
                        blocked_reason=result.blocked_reason,
                    )
                    self._record_metrics("l2_output", name, "block", start_time)
                    return self._handle_output_block(
                        results, result, name, start_time, redacted_text
                    )

            # --- Wave 2: Expensive LLM checks ---
            wave2 = []
            if (
                self._groundedness_detector
                and self.config.groundedness_enabled
                and (user_query or grounding_sources)
            ):
                wave2.append(
                    (
                        "groundedness_detector",
                        self._groundedness_detector.aanalyze(
                            text=model_output,
                            user_query=user_query,
                            grounding_sources=grounding_sources,
                            confidence_threshold=self.config.groundedness_confidence_threshold,
                            block_on_high_confidence=self.config.groundedness_block_on_high_confidence,
                        ),
                    )
                )

            if wave2:
                w2_results, block = await wave_parallel(wave2)
                for name, result in w2_results:
                    results.append(result)
                if block:
                    name, result = block
                    self._set_span_attrs(
                        parent_span,
                        is_safe=False,
                        blocked_by=name,
                        blocked_reason=result.blocked_reason,
                    )
                    self._record_metrics("l2_output", name, "block", start_time)
                    return self._handle_output_block(
                        results, result, name, start_time, redacted_text
                    )

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info("All L2 checks passed (async, %.1fms)", elapsed_ms)
            self._set_span_attrs(parent_span, is_safe=True)
            self._record_metrics("l2_output", "validate_output", "pass", start_time)

        return OutputValidationResult(is_safe=True, results=results, redacted_text=redacted_text)

    async def avalidate_tool_call(
        self,
        fn_name: str,
        fn_args: dict,
        context: dict = None,
    ) -> ToolCallValidationResult:
        """
        Async tiered tool call validation.

        Wave 0: C3 rule-based guards (offline, ~1ms)
        Wave 1: C1 entity recognition + C4 approval workflow (parallel)
        """
        if self.config.mode == GuardMode.DRY_RUN:
            return ToolCallValidationResult(is_safe=True, tool_name=fn_name)

        start_time = time.time()
        results = []

        with self._span("agentguard.validate_tool_call") as parent_span:
            # --- Wave 0: C3 Rule-Based Guards (sync, ~1ms) ---
            if self._tool_specific_guards:
                with self._span("agentguard.check.tool_specific_guards"):
                    c3_result = self._tool_specific_guards.check(fn_name, fn_args)
                results.append(c3_result)
                if not c3_result.is_safe:
                    self._set_span_attrs(
                        parent_span,
                        is_safe=False,
                        blocked_by="tool_specific_guards",
                        blocked_reason=c3_result.blocked_reason,
                    )
                    self._record_metrics(
                        "tool_firewall", "tool_specific_guards", "block", start_time
                    )
                    return self._handle_tool_block(
                        results,
                        c3_result,
                        "tool_specific_guards",
                        start_time,
                        fn_name,
                    )

            # --- Wave 1: C1 + C4 (async parallel) ---
            wave1 = []
            if self._tool_input_analyzer and self.config.tool_input_analysis_enabled:
                wave1.append(
                    (
                        "tool_input_analyzer",
                        self._tool_input_analyzer.aanalyze(
                            fn_name,
                            fn_args,
                            blocked_categories_map=self.config.tool_input_blocked_categories,
                        ),
                    )
                )

            if self._approval_workflow and self.config.approval_workflow_enabled:
                wave1.append(
                    (
                        "approval_workflow",
                        self._approval_workflow.acheck(fn_name, fn_args, context),
                    )
                )

            if wave1:
                w1_results, block = await wave_parallel(wave1)
                for name, result in w1_results:
                    results.append(result)
                if block:
                    name, result = block
                    self._set_span_attrs(
                        parent_span,
                        is_safe=False,
                        blocked_by=name,
                        blocked_reason=result.blocked_reason,
                    )
                    self._record_metrics("tool_firewall", name, "block", start_time)
                    return self._handle_tool_block(
                        results,
                        result,
                        name,
                        start_time,
                        fn_name,
                    )

            elapsed_ms = (time.time() - start_time) * 1000
            logger.info(
                "Tool call pre-checks passed (async) for '%s' (%.1fms)", fn_name, elapsed_ms
            )
            self._set_span_attrs(parent_span, is_safe=True)
            self._record_metrics("tool_firewall", "validate_tool_call", "pass", start_time)

        return ToolCallValidationResult(is_safe=True, results=results, tool_name=fn_name)
