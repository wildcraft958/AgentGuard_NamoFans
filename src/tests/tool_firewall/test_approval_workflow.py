"""
Tests for C4 Approval Workflow (HITL / AITL).
"""

from unittest.mock import MagicMock, patch

from agentguard.tool_firewall.approval_workflow import ApprovalWorkflow


# ------------------------------------------------------------------
# Config helper
# ------------------------------------------------------------------

_DEFAULT_REVIEW_TOOLS = ["shell_execute", "escalate_to_root", "reboot_system"]


def _make_config(
    enabled=True,
    mode="human",
    tools_requiring_review=None,
    ai_supervisor=None,
):
    config = MagicMock()
    config.approval_workflow_enabled = enabled
    config.approval_workflow_mode = mode
    config.approval_workflow_tools_requiring_review = (
        tools_requiring_review if tools_requiring_review is not None
        else _DEFAULT_REVIEW_TOOLS
    )
    config.approval_workflow_ai_supervisor_config = ai_supervisor or {
        "model": "deepseek-r1",
        "base_url": None,
        "api_key_env": "TFY_API_KEY",
        "system_prompt": "You are a strict cybersecurity auditor. Reply ONLY with APPROVE or REJECT:<reason>.",
    }
    return config


# ------------------------------------------------------------------
# HITL Tests
# ------------------------------------------------------------------

class TestHITL:
    """Human-in-the-Loop approval tests."""

    def test_human_approve(self):
        config = _make_config(mode="human")
        workflow = ApprovalWorkflow(config)
        with patch("builtins.input", return_value="y"):
            result = workflow.check("shell_execute", {"command": "ls -la"})
        assert result.is_safe
        assert result.details["mode"] == "human"
        assert result.details["decision"] == "approved"

    def test_human_reject(self):
        config = _make_config(mode="human")
        workflow = ApprovalWorkflow(config)
        with patch("builtins.input", return_value="n"):
            result = workflow.check("shell_execute", {"command": "rm -rf /"})
        assert not result.is_safe
        assert "rejected" in result.blocked_reason.lower()
        assert result.details["decision"] == "rejected"

    def test_human_yes_full_word(self):
        config = _make_config(mode="human")
        workflow = ApprovalWorkflow(config)
        with patch("builtins.input", return_value="yes"):
            result = workflow.check("escalate_to_root", {"reason": "test"})
        assert result.is_safe

    def test_human_empty_rejects(self):
        config = _make_config(mode="human")
        workflow = ApprovalWorkflow(config)
        with patch("builtins.input", return_value=""):
            result = workflow.check("reboot_system", {"delay_seconds": 0})
        assert not result.is_safe

    def test_human_eof_rejects(self):
        config = _make_config(mode="human")
        workflow = ApprovalWorkflow(config)
        with patch("builtins.input", side_effect=EOFError):
            result = workflow.check("shell_execute", {"command": "id"})
        assert not result.is_safe

    def test_tool_not_in_list_passes(self):
        config = _make_config(mode="human")
        workflow = ApprovalWorkflow(config)
        # http_get is not in tools_requiring_review
        result = workflow.check("http_get", {"url": "https://example.com"})
        assert result.is_safe


# ------------------------------------------------------------------
# AITL Tests
# ------------------------------------------------------------------

class TestAITL:
    """AI-in-the-Loop approval tests."""

    def _mock_openai_response(self, content):
        """Create a mock OpenAI chat completion response."""
        mock_message = MagicMock()
        mock_message.content = content
        mock_choice = MagicMock()
        mock_choice.message = mock_message
        mock_response = MagicMock()
        mock_response.choices = [mock_choice]
        return mock_response

    def test_ai_approve(self):
        config = _make_config(mode="ai")
        workflow = ApprovalWorkflow(config)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._mock_openai_response(
            "APPROVE: This tool call aligns with the user's request and is safe."
        )
        workflow._ai_client = mock_client

        result = workflow.check("shell_execute", {"command": "ls"}, context={
            "messages": [{"role": "user", "content": "List files in current directory"}]
        })
        assert result.is_safe
        assert result.details["mode"] == "ai"
        assert result.details["decision"] == "approved"

    def test_ai_reject(self):
        config = _make_config(mode="ai")
        workflow = ApprovalWorkflow(config)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._mock_openai_response(
            "REJECT: This tool call attempts to escalate privileges without justification."
        )
        workflow._ai_client = mock_client

        result = workflow.check("escalate_to_root", {"reason": "maintenance"}, context={
            "messages": [{"role": "user", "content": "What tables are in the database?"}]
        })
        assert not result.is_safe
        assert "rejected" in result.blocked_reason.lower()
        assert "privileges" in result.details["reason"].lower()

    def test_ai_error_blocks(self):
        config = _make_config(mode="ai")
        workflow = ApprovalWorkflow(config)

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API timeout")
        workflow._ai_client = mock_client

        result = workflow.check("reboot_system", {"delay_seconds": 0}, context={})
        assert not result.is_safe
        assert "fail-safe" in result.blocked_reason.lower()
        assert result.details["decision"] == "error"

    def test_ai_context_includes_user_prompt(self):
        config = _make_config(mode="ai")
        workflow = ApprovalWorkflow(config)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._mock_openai_response("APPROVE: safe")
        workflow._ai_client = mock_client

        user_msg = "Please list all database tables"
        workflow.check("shell_execute", {"command": "ls"}, context={
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": user_msg},
            ]
        })

        # Verify the user prompt was included in the LLM call
        call_args = mock_client.chat.completions.create.call_args
        messages = call_args.kwargs.get("messages", call_args[1].get("messages", []))
        user_content = messages[1]["content"]  # master prompt is second message
        assert user_msg in user_content

    def test_ai_no_context_still_works(self):
        config = _make_config(mode="ai")
        workflow = ApprovalWorkflow(config)

        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = self._mock_openai_response("APPROVE: safe")
        workflow._ai_client = mock_client

        result = workflow.check("shell_execute", {"command": "ls"}, context=None)
        assert result.is_safe

    def test_tool_not_in_list_passes(self):
        config = _make_config(mode="ai")
        workflow = ApprovalWorkflow(config)
        result = workflow.check("http_get", {"url": "https://example.com"})
        assert result.is_safe


# ------------------------------------------------------------------
# Unknown mode / edge cases
# ------------------------------------------------------------------

class TestEdgeCases:
    """Edge case tests."""

    def test_unknown_mode_blocks(self):
        config = _make_config(mode="invalid_mode")
        workflow = ApprovalWorkflow(config)
        result = workflow.check("shell_execute", {"command": "ls"})
        assert not result.is_safe
        assert "unknown" in result.blocked_reason.lower()

    def test_disabled_workflow_not_called(self):
        """When disabled, Guardian should not even call check().
        This tests the ApprovalWorkflow itself still works if called directly."""
        config = _make_config(enabled=False, mode="human")
        workflow = ApprovalWorkflow(config)
        # Even if called directly, tools in the list still get checked
        with patch("builtins.input", return_value="n"):
            result = workflow.check("shell_execute", {"command": "ls"})
        assert not result.is_safe

    def test_empty_review_list_passes_all(self):
        config = _make_config(tools_requiring_review=[])
        workflow = ApprovalWorkflow(config)
        result = workflow.check("shell_execute", {"command": "rm -rf /"})
        assert result.is_safe  # not in review list
