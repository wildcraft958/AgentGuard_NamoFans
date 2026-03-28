"""
AgentGuard -- C4 Approval Workflow (HITL / AITL).

Adds a human-in-the-loop or AI-in-the-loop approval gate for sensitive
tool calls. Only tools listed in ``tools_requiring_review`` are gated;
all others pass through immediately.

Modes:
  human  -- pauses execution, prints tool details, waits for terminal input
  ai     -- sends tool context to a supervisor LLM for approval/rejection
"""

import asyncio
import json
import logging
import os

from agentguard.models import ValidationResult

logger = logging.getLogger("agentguard.approval_workflow")

LAYER = "approval_workflow"


class ApprovalWorkflow:
    """Approval gate that sits after C3/C1, before tool execution."""

    def __init__(self, config):
        self.config = config
        self._ai_client = None  # lazy-init for AITL

    def check(self, fn_name: str, fn_args: dict, context: dict = None) -> ValidationResult:
        """Check whether a tool call requires and receives approval.

        Args:
            fn_name: Tool function name.
            fn_args: Tool function arguments dict.
            context: Optional context dict (may contain ``messages`` for AITL).

        Returns:
            ValidationResult -- is_safe=True if approved or not in review list.
        """
        review_list = self.config.approval_workflow_tools_requiring_review
        if fn_name not in review_list:
            return ValidationResult(is_safe=True, layer=LAYER)

        mode = self.config.approval_workflow_mode
        if mode == "human":
            return self._check_human(fn_name, fn_args)
        elif mode == "ai":
            return self._check_ai(fn_name, fn_args, context)
        else:
            logger.warning("Unknown approval_workflow mode '%s', blocking as fail-safe", mode)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=f"Unknown approval_workflow mode: {mode}",
            )

    # ------------------------------------------------------------------
    # HITL: Human-in-the-Loop
    # ------------------------------------------------------------------

    def _check_human(self, fn_name: str, fn_args: dict) -> ValidationResult:
        """Pause execution and ask a human reviewer via terminal input."""
        args_str = json.dumps(fn_args, indent=2, default=str)
        if len(args_str) > 500:
            args_str = args_str[:500] + "\n  ... (truncated)"

        print(f"\n{'=' * 60}")
        print("  [HITL REVIEW REQUIRED]")
        print(f"  Tool:      {fn_name}")
        print(f"  Arguments: {args_str}")
        print(f"{'=' * 60}")

        try:
            response = input("  Allow execution? (y/n): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            response = "n"

        if response in ("y", "yes"):
            logger.info("HITL APPROVED: %s", fn_name)
            return ValidationResult(
                is_safe=True,
                layer=LAYER,
                details={"mode": "human", "decision": "approved"},
            )
        else:
            reason = f"Human reviewer rejected tool call: {fn_name}"
            logger.warning("HITL REJECTED: %s", fn_name)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=reason,
                details={"mode": "human", "decision": "rejected"},
            )

    # ------------------------------------------------------------------
    # AITL: AI-in-the-Loop
    # ------------------------------------------------------------------

    def _get_ai_client(self):
        """Lazy-init the OpenAI-compatible client for AITL."""
        if self._ai_client is not None:
            return self._ai_client

        from openai import OpenAI

        ai_cfg = self.config.approval_workflow_ai_supervisor_config
        api_key_env = ai_cfg.get("api_key_env", "TFY_API_KEY")
        api_key = os.getenv(api_key_env, "")
        # base_url: prefer YAML config, fall back to base_url_env, then TFY_BASE_URL
        base_url = ai_cfg.get("base_url")
        if not base_url:
            base_url_env = ai_cfg.get("base_url_env", "TFY_BASE_URL")
            base_url = os.getenv(base_url_env)

        kwargs = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url

        self._ai_client = OpenAI(**kwargs)
        return self._ai_client

    def _extract_user_prompt(self, context: dict) -> str:
        """Extract the original user prompt from conversation messages."""
        if not context:
            return "(no user prompt available)"
        messages = context.get("messages", [])
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "user":
                return msg.get("content", "")
        return "(no user prompt available)"

    def _check_ai(self, fn_name: str, fn_args: dict, context: dict = None) -> ValidationResult:
        """Send tool context to a supervisor LLM for approval."""
        ai_cfg = self.config.approval_workflow_ai_supervisor_config
        model = ai_cfg.get("model", "deepseek-r1")
        system_prompt = ai_cfg.get(
            "system_prompt",
            "You are a strict cybersecurity auditor. Review the following "
            "tool execution context. Reply ONLY with APPROVE or REJECT:<reason>.",
        )

        user_prompt = self._extract_user_prompt(context)
        args_str = json.dumps(fn_args, indent=2, default=str)
        if len(args_str) > 1000:
            args_str = args_str[:1000] + "\n... (truncated)"

        master_prompt = (
            f"CONTEXT:\n"
            f'The user asked the agent to do the following: "{user_prompt}"\n\n'
            f"ACTION:\n"
            f"To fulfill this request, the agent is attempting to execute the following tool:\n"
            f"Tool Name: {fn_name}\n"
            f"Arguments: {args_str}\n\n"
            f"TASK:\n"
            f"Does this tool execution logically align with the user's request, "
            f"AND is it safe to execute?\n"
            f'Reply with exactly one word: "APPROVE" or "REJECT", '
            f"followed by a short reason."
        )

        try:
            client = self._get_ai_client()
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": master_prompt},
                ],
                max_tokens=200,
                temperature=0.0,
            )

            reply = response.choices[0].message.content.strip()
            logger.info("AITL supervisor response for '%s': %s", fn_name, reply)

            if "APPROVE" in reply.upper():
                return ValidationResult(
                    is_safe=True,
                    layer=LAYER,
                    details={"mode": "ai", "decision": "approved", "reason": reply},
                )
            else:
                # Extract reason after REJECT
                reason_text = reply
                if "REJECT" in reply.upper():
                    parts = reply.split(":", 1)
                    reason_text = parts[1].strip() if len(parts) > 1 else reply
                reason = f"AI supervisor rejected tool call '{fn_name}': {reason_text}"
                return ValidationResult(
                    is_safe=False,
                    layer=LAYER,
                    blocked_reason=reason,
                    details={"mode": "ai", "decision": "rejected", "reason": reply},
                )

        except Exception as e:
            logger.error("AITL supervisor error for '%s': %s", fn_name, e)
            reason = f"AI supervisor error (fail-safe block): {e}"
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=reason,
                details={"mode": "ai", "decision": "error", "error": str(e)},
            )

    # ------------------------------------------------------------------
    # Async variant
    # ------------------------------------------------------------------

    def _get_async_ai_client(self):
        """Lazy-init the AsyncOpenAI client for AITL."""
        if not hasattr(self, "_async_ai_client") or self._async_ai_client is None:
            from openai import AsyncOpenAI

            ai_cfg = self.config.approval_workflow_ai_supervisor_config
            api_key_env = ai_cfg.get("api_key_env", "TFY_API_KEY")
            api_key = os.getenv(api_key_env, "")
            base_url = ai_cfg.get("base_url")
            if not base_url:
                base_url_env = ai_cfg.get("base_url_env", "TFY_BASE_URL")
                base_url = os.getenv(base_url_env)

            kwargs = {"api_key": api_key}
            if base_url:
                kwargs["base_url"] = base_url

            self._async_ai_client = AsyncOpenAI(**kwargs)
        return self._async_ai_client

    async def acheck(self, fn_name: str, fn_args: dict, context: dict = None) -> ValidationResult:
        """Async version of check(). AITL uses AsyncOpenAI, HITL uses to_thread."""
        review_list = self.config.approval_workflow_tools_requiring_review
        if fn_name not in review_list:
            return ValidationResult(is_safe=True, layer=LAYER)

        mode = self.config.approval_workflow_mode
        if mode == "human":
            # Terminal input cannot be made async — use to_thread (legitimate use)
            return await asyncio.to_thread(self._check_human, fn_name, fn_args)
        elif mode == "ai":
            return await self._acheck_ai(fn_name, fn_args, context)
        else:
            logger.warning("Unknown approval_workflow mode '%s', blocking as fail-safe", mode)
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=f"Unknown approval_workflow mode: {mode}",
            )

    async def _acheck_ai(
        self, fn_name: str, fn_args: dict, context: dict = None
    ) -> ValidationResult:
        """Async AITL: send tool context to supervisor LLM via AsyncOpenAI."""
        ai_cfg = self.config.approval_workflow_ai_supervisor_config
        model = ai_cfg.get("model", "deepseek-r1")
        system_prompt = ai_cfg.get(
            "system_prompt",
            "You are a strict cybersecurity auditor. Review the following "
            "tool execution context. Reply ONLY with APPROVE or REJECT:<reason>.",
        )

        user_prompt = self._extract_user_prompt(context)
        args_str = json.dumps(fn_args, indent=2, default=str)
        if len(args_str) > 1000:
            args_str = args_str[:1000] + "\n... (truncated)"

        master_prompt = (
            f"CONTEXT:\n"
            f'The user asked the agent to do the following: "{user_prompt}"\n\n'
            f"ACTION:\n"
            f"To fulfill this request, the agent is attempting to execute the following tool:\n"
            f"Tool Name: {fn_name}\n"
            f"Arguments: {args_str}\n\n"
            f"TASK:\n"
            f"Does this tool execution logically align with the user's request, "
            f"AND is it safe to execute?\n"
            f'Reply with exactly one word: "APPROVE" or "REJECT", '
            f"followed by a short reason."
        )

        try:
            client = self._get_async_ai_client()
            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": master_prompt},
                ],
                max_tokens=200,
                temperature=0.0,
            )

            reply = response.choices[0].message.content.strip()
            logger.info("AITL supervisor response (async) for '%s': %s", fn_name, reply)

            if "APPROVE" in reply.upper():
                return ValidationResult(
                    is_safe=True,
                    layer=LAYER,
                    details={"mode": "ai", "decision": "approved", "reason": reply},
                )
            else:
                reason_text = reply
                if "REJECT" in reply.upper():
                    parts = reply.split(":", 1)
                    reason_text = parts[1].strip() if len(parts) > 1 else reply
                reason = f"AI supervisor rejected tool call '{fn_name}': {reason_text}"
                return ValidationResult(
                    is_safe=False,
                    layer=LAYER,
                    blocked_reason=reason,
                    details={"mode": "ai", "decision": "rejected", "reason": reply},
                )

        except Exception as e:
            logger.error("AITL supervisor error (async) for '%s': %s", fn_name, e)
            reason = f"AI supervisor error (fail-safe block): {e}"
            return ValidationResult(
                is_safe=False,
                layer=LAYER,
                blocked_reason=reason,
                details={"mode": "ai", "decision": "error", "error": str(e)},
            )

    async def aclose(self):
        """Close the async OpenAI client."""
        if hasattr(self, "_async_ai_client") and self._async_ai_client is not None:
            await self._async_ai_client.close()
            self._async_ai_client = None
