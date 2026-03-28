"""Tests for agentguard.tool_firewall.melon_detector (Component 2 — MELON)."""

import json
import pytest
from unittest.mock import patch, MagicMock

from agentguard.tool_firewall.melon_detector import MelonDetector  # noqa: E402


def _make_tool_call(name, arguments):
    tc = MagicMock()
    tc.function.name = name
    tc.function.arguments = arguments
    tc.id = f"call_{name}"
    tc.type = "function"
    return tc


def _make_chat_response(tool_calls=None, content=None):
    response = MagicMock()
    msg = MagicMock()
    msg.tool_calls = tool_calls
    msg.content = content
    response.choices = [MagicMock()]
    response.choices[0].message = msg
    return response


def _make_judge_response(verdict, confidence=0.9, reasoning="test"):
    """Create a mock LLM response that returns a judge verdict."""
    judge_json = json.dumps({
        "verdict": verdict,
        "confidence": confidence,
        "reasoning": reasoning,
    })
    return _make_chat_response(content=judge_json)


@pytest.fixture
def detector():
    with patch("agentguard.tool_firewall.melon_detector.OpenAI"):
        d = MelonDetector(
            api_key="test-key",
            base_url="https://test.gateway.ai",
            model="test-model",
        )
    return d


SAMPLE_MESSAGES = [
    {"role": "system", "content": "You are a helpful assistant."},
    {"role": "user", "content": "Read my inbox"},
    {"role": "assistant", "content": None, "tool_calls": [
        {"id": "call_1", "type": "function", "function": {"name": "read_inbox", "arguments": "{}"}}
    ]},
    {"role": "tool", "tool_call_id": "call_1", "content": "You have 3 new messages."},
]

SAMPLE_SCHEMAS = [
    {"type": "function", "function": {"name": "read_inbox", "parameters": {}}},
    {"type": "function", "function": {"name": "send_email", "parameters": {}}},
]


class TestMelonDetector:

    def test_no_messages_passes(self, detector):
        result = detector.check_tool_output([], SAMPLE_SCHEMAS)
        assert result.is_safe is True

    def test_non_tool_message_passes(self, detector):
        messages = [{"role": "user", "content": "hello"}]
        result = detector.check_tool_output(messages, SAMPLE_SCHEMAS)
        assert result.is_safe is True

    def test_no_tool_calls_in_original_passes(self, detector):
        """If LLM doesn't produce tool calls after seeing tool output, no injection."""
        original_response = _make_chat_response(tool_calls=None, content="Here's a summary.")
        detector.client.chat.completions.create.return_value = original_response

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is True

    def test_injection_detected_by_judge(self, detector):
        """When LLM judge returns BLOCK verdict → injection detected."""
        # Original run: produces send_email tool call
        orig_tc = _make_tool_call("send_email", '{"to": "attacker@evil.com"}')
        original_response = _make_chat_response(tool_calls=[orig_tc])

        # Masked run: also produces send_email (same behavior in different context = injection)
        masked_tc = _make_tool_call("send_email", '{"to": "attacker@evil.com"}')
        masked_response = _make_chat_response(tool_calls=[masked_tc])

        # Judge response: BLOCK
        judge_response = _make_judge_response("BLOCK", confidence=0.95, reasoning="Same malicious tool call in both contexts")

        detector.client.chat.completions.create.side_effect = [
            original_response,
            masked_response,
            judge_response,
        ]

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is False
        assert "prompt injection" in result.blocked_reason.lower()
        assert result.details.get("redacted_output") is not None
        assert result.details.get("judge_verdict") == "BLOCK"
        assert result.details.get("judge_confidence") == 0.95

    def test_safe_output_judge_allows(self, detector):
        """When LLM judge returns ALLOW verdict → safe."""
        orig_tc = _make_tool_call("read_inbox", '{}')
        original_response = _make_chat_response(tool_calls=[orig_tc])

        masked_tc = _make_tool_call("summarize", '{"text": "..."}')
        masked_response = _make_chat_response(tool_calls=[masked_tc])

        # Judge response: ALLOW
        judge_response = _make_judge_response("ALLOW", confidence=0.85, reasoning="Different tool calls, no injection")

        detector.client.chat.completions.create.side_effect = [
            original_response,
            masked_response,
            judge_response,
        ]

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is True
        assert result.details.get("judge_verdict") == "ALLOW"

    def test_no_masked_tool_calls_passes(self, detector):
        """If masked run produces no tool calls, no comparison → safe."""
        orig_tc = _make_tool_call("read_inbox", '{}')
        original_response = _make_chat_response(tool_calls=[orig_tc])
        masked_response = _make_chat_response(tool_calls=None, content="Summary of contents.")

        detector.client.chat.completions.create.side_effect = [original_response, masked_response]

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is True

    def test_api_error_blocks_as_failsafe(self, detector):
        detector.client.chat.completions.create.side_effect = Exception("API timeout")

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is False
        assert "fail-safe" in result.blocked_reason

    def test_judge_malformed_json_blocks_as_failsafe(self, detector):
        """If judge returns malformed JSON, block as fail-safe."""
        orig_tc = _make_tool_call("send_email", '{"to": "test@test.com"}')
        original_response = _make_chat_response(tool_calls=[orig_tc])

        masked_tc = _make_tool_call("send_email", '{"to": "test@test.com"}')
        masked_response = _make_chat_response(tool_calls=[masked_tc])

        # Judge returns invalid JSON
        bad_judge = _make_chat_response(content="I think this is safe, but I'm not sure.")

        detector.client.chat.completions.create.side_effect = [
            original_response,
            masked_response,
            bad_judge,
        ]

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is False
        assert result.details.get("judge_verdict") == "BLOCK"

    def test_judge_invalid_verdict_blocks_as_failsafe(self, detector):
        """If judge returns an invalid verdict value, block as fail-safe."""
        orig_tc = _make_tool_call("send_email", '{"to": "test@test.com"}')
        original_response = _make_chat_response(tool_calls=[orig_tc])

        masked_tc = _make_tool_call("send_email", '{"to": "test@test.com"}')
        masked_response = _make_chat_response(tool_calls=[masked_tc])

        # Judge returns invalid verdict
        bad_verdict = _make_chat_response(
            content=json.dumps({"verdict": "MAYBE", "confidence": 0.5, "reasoning": "unsure"})
        )

        detector.client.chat.completions.create.side_effect = [
            original_response,
            masked_response,
            bad_verdict,
        ]

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is False
        assert result.details.get("judge_verdict") == "BLOCK"

    def test_judge_with_markdown_fences(self, detector):
        """Judge response wrapped in markdown code fences should be parsed correctly."""
        orig_tc = _make_tool_call("read_inbox", '{}')
        original_response = _make_chat_response(tool_calls=[orig_tc])

        masked_tc = _make_tool_call("summarize", '{}')
        masked_response = _make_chat_response(tool_calls=[masked_tc])

        # Judge returns JSON wrapped in markdown code fences
        fenced_judge = _make_chat_response(
            content='```json\n{"verdict": "ALLOW", "confidence": 0.9, "reasoning": "safe"}\n```'
        )

        detector.client.chat.completions.create.side_effect = [
            original_response,
            masked_response,
            fenced_judge,
        ]

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is True
        assert result.details.get("judge_verdict") == "ALLOW"

    def test_reset_clears_banks(self, detector):
        detector._masked_tool_call_bank.add("test_call")
        detector.reset()
        assert len(detector._masked_tool_call_bank) == 0

    def test_missing_credentials_raises(self):
        with patch.dict("os.environ", {"TFY_API_KEY": "", "TFY_BASE_URL": ""}):
            with pytest.raises(ValueError, match="TFY_API_KEY"):
                MelonDetector(api_key="", base_url="")

    def test_custom_judge_model(self):
        """Custom judge_model is stored correctly."""
        with patch("agentguard.tool_firewall.melon_detector.OpenAI"):
            d = MelonDetector(
                api_key="test-key",
                base_url="https://test.gateway.ai",
                model="main-model",
                judge_model="judge-model-v2",
            )
        assert d.judge_model == "judge-model-v2"

    def test_judge_model_defaults_to_main_model(self):
        """When judge_model is not set, it defaults to the main model."""
        with patch("agentguard.tool_firewall.melon_detector.OpenAI"):
            d = MelonDetector(
                api_key="test-key",
                base_url="https://test.gateway.ai",
                model="main-model",
            )
        assert d.judge_model == "main-model"


