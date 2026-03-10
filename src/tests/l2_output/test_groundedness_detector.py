"""Tests for L2 GroundednessDetector module (LLM-as-judge approach).

Extensive unit tests covering both grounding strategies:
  1. With-query mode — user query + context (grounding sources)
  2. Without-query mode — context only (summarization)

Also covers: threshold logic, LLM errors, score parsing,
initialization, prompt selection, and edge cases.
"""

from unittest.mock import MagicMock, patch
import pytest

from agentguard.l2_output.groundedness_detector import (
    GroundednessDetector,
    LAYER,
)


# ══════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════

def _make_llm_response(content: str):
    """Create a mock OpenAI chat completion response."""
    message = MagicMock()
    message.content = content
    choice = MagicMock()
    choice.message = message
    response = MagicMock()
    response.choices = [choice]
    return response


def _judge_output(score: int, explanation: str = "test explanation", thoughts: str = "test thoughts"):
    """Build a properly formatted judge output string."""
    return f"<S0>{thoughts}</S0>\n<S1>{explanation}</S1>\n<S2>{score}</S2>"


def _detector(mock_client=None, **kwargs):
    """Build a GroundednessDetector with test credentials and optional mock client."""
    defaults = {
        "api_key": "test-key",
        "base_url": "https://test.example.com/v1",
        "model": "test-model",
    }
    defaults.update(kwargs)
    with patch("agentguard.l2_output.groundedness_detector.OpenAI") as mock_cls:
        if mock_client:
            mock_cls.return_value = mock_client
        else:
            mock_cls.return_value = MagicMock()
        det = GroundednessDetector(**defaults)
    return det


# ══════════════════════════════════════════════════════════════════
# 1. Initialization Tests
# ══════════════════════════════════════════════════════════════════


class TestGroundednessDetectorInit:
    """Tests for GroundednessDetector initialization."""

    def test_init_with_explicit_credentials(self):
        det = _detector(api_key="my-key", base_url="https://api.example.com/v1", model="gpt-4")
        assert det.api_key == "my-key"
        assert det.base_url == "https://api.example.com/v1"
        assert det.model == "gpt-4"

    def test_init_from_openai_env_vars(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "env-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://env.example.com/v1")
        monkeypatch.setenv("OPENAI_MODEL", "env-model")
        det = _detector(api_key=None, base_url=None, model=None)
        assert det.api_key == "env-key"
        assert det.base_url == "https://env.example.com/v1"
        assert det.model == "env-model"

    def test_init_from_tfy_env_vars(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_MODEL", raising=False)
        monkeypatch.setenv("TFY_API_KEY", "tfy-key")
        monkeypatch.setenv("TFY_BASE_URL", "https://gateway.truefoundry.ai")
        monkeypatch.setenv("TFY_MODEL", "gemini-flash")
        det = _detector(api_key=None, base_url=None, model=None)
        assert det.api_key == "tfy-key"
        assert det.base_url == "https://gateway.truefoundry.ai/openai/v1"
        assert det.model == "gemini-flash"

    def test_init_missing_credentials_raises(self, monkeypatch):
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
        monkeypatch.delenv("OPENAI_MODEL", raising=False)
        monkeypatch.delenv("TFY_API_KEY", raising=False)
        monkeypatch.delenv("TFY_BASE_URL", raising=False)
        monkeypatch.delenv("TFY_MODEL", raising=False)
        with patch("agentguard.l2_output.groundedness_detector.OpenAI"):
            with pytest.raises(ValueError, match="Groundedness Detector requires LLM credentials"):
                GroundednessDetector()

    def test_init_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("OPENAI_API_KEY", "env-key")
        monkeypatch.setenv("OPENAI_BASE_URL", "https://env.example.com/v1")
        monkeypatch.setenv("OPENAI_MODEL", "env-model")
        det = _detector(api_key="override-key", base_url="https://override.com/v1", model="override-model")
        assert det.api_key == "override-key"
        assert det.base_url == "https://override.com/v1"
        assert det.model == "override-model"

    def test_timeout_conversion(self):
        det = _detector(timeout_ms=15000)
        assert det.timeout == 15.0

    def test_default_timeout(self):
        det = _detector()
        assert det.timeout == 10.0

    def test_openai_client_created(self):
        det = _detector()
        assert det._client is not None


# ══════════════════════════════════════════════════════════════════
# 2. With-Query Mode Tests (QnA)
# ══════════════════════════════════════════════════════════════════


class TestWithQueryMode:
    """Tests for groundedness evaluation with user query provided."""

    def test_grounded_response_passes(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Response is fully grounded in context")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="Paris is the capital of France.",
            user_query="What is the capital of France?",
            grounding_sources=["France is a country in Europe. Its capital is Paris."],
        )
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 5

    def test_ungrounded_response_blocked(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(1, "Response is completely unrelated")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The moon is made of cheese.",
            user_query="What is the capital of France?",
            grounding_sources=["France is a country in Europe. Its capital is Paris."],
            confidence_threshold=3.0,
        )
        assert result.is_safe is False
        assert "score: 1/5" in result.blocked_reason

    def test_query_only_no_docs_uses_relevance_prompt(self):
        """Query-only (no grounding sources) should use relevance prompt, not skip."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Response directly addresses the query")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The capital is Paris.",
            user_query="What is the capital of France?",
        )
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 5
        # Verify relevance prompt used (no CONTEXT field, just QUERY + RESPONSE)
        call_args = mock_client.chat.completions.create.call_args
        user_msg = call_args[1]["messages"][1]["content"]
        assert "QUERY:" in user_msg
        assert "RESPONSE:" in user_msg
        assert "CONTEXT:" not in user_msg
        assert "Relevance" in user_msg

    def test_with_query_prompt_contains_required_fields(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5)
        )
        det = _detector(mock_client=mock_client)
        det.analyze(text="answer text", user_query="the query", grounding_sources=["source doc"])
        call_args = mock_client.chat.completions.create.call_args
        user_msg = call_args[1]["messages"][1]["content"]
        assert "CONTEXT:" in user_msg
        assert "QUERY:" in user_msg
        assert "RESPONSE:" in user_msg

    def test_multiple_grounding_sources_concatenated(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5)
        )
        det = _detector(mock_client=mock_client)
        det.analyze(
            text="Combined info",
            user_query="Tell me about it",
            grounding_sources=["Doc one.", "Doc two.", "Doc three."],
        )
        call_args = mock_client.chat.completions.create.call_args
        user_msg = call_args[1]["messages"][1]["content"]
        assert "Doc one." in user_msg
        assert "Doc two." in user_msg
        assert "Doc three." in user_msg

    def test_query_with_empty_sources_list_uses_relevance(self):
        """Empty grounding sources list + query should use relevance prompt."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "On topic")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Some response", user_query="My question", grounding_sources=[])
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 5
        # Verify relevance prompt (no CONTEXT)
        call_args = mock_client.chat.completions.create.call_args
        user_msg = call_args[1]["messages"][1]["content"]
        assert "CONTEXT:" not in user_msg
        assert "Relevance" in user_msg


# ══════════════════════════════════════════════════════════════════
# 3. Without-Query Mode Tests (Summarization)
# ══════════════════════════════════════════════════════════════════


class TestWithoutQueryMode:
    """Tests for groundedness evaluation with documents only (no query)."""

    def test_docs_only_uses_summarization_prompt(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Fully grounded summary")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The company grew 20%.",
            grounding_sources=["The company's profits increased by 20% last quarter."],
        )
        assert result.is_safe is True
        call_args = mock_client.chat.completions.create.call_args
        user_msg = call_args[1]["messages"][1]["content"]
        assert "CONTEXT:" in user_msg
        assert "RESPONSE:" in user_msg
        assert "QUERY:" not in user_msg

    def test_docs_only_ungrounded_blocked(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(2, "Incorrect info in summary")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The company lost 50%.",
            grounding_sources=["The company's profits increased by 20%."],
            confidence_threshold=3.0,
        )
        assert result.is_safe is False

    def test_docs_only_grounded_passes(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Accurate summary")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="Profits rose 20% last quarter.",
            grounding_sources=["The company's profits increased by 20% in the last quarter."],
        )
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 5

    def test_multiple_docs_summarization(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(4)
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Combined summary", grounding_sources=["First source.", "Second source."])
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 4


# ══════════════════════════════════════════════════════════════════
# 3b. Query-Only Mode Tests (Relevance)
# ══════════════════════════════════════════════════════════════════


class TestQueryOnlyMode:
    """Tests for relevance evaluation with query only (no documents)."""

    def test_query_only_relevant_response_passes(self):
        """On-topic response to query should pass relevance check."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Response directly answers the question")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The database has users, orders, and secrets tables.",
            user_query="What tables are in the database?",
        )
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 5

    def test_query_only_off_topic_response_blocked(self):
        """Completely off-topic response should be blocked."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(1, "Response has nothing to do with the query")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The weather in Paris is sunny today.",
            user_query="What tables are in the database?",
            confidence_threshold=3.0,
        )
        assert result.is_safe is False
        assert "score: 1/5" in result.blocked_reason

    def test_query_only_prompt_has_no_context_field(self):
        """Relevance prompt should not have CONTEXT field."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5)
        )
        det = _detector(mock_client=mock_client)
        det.analyze(text="Some answer", user_query="Some question")
        call_args = mock_client.chat.completions.create.call_args
        user_msg = call_args[1]["messages"][1]["content"]
        assert "QUERY:" in user_msg
        assert "RESPONSE:" in user_msg
        assert "CONTEXT:" not in user_msg
        assert "Relevance" in user_msg

    def test_query_only_tool_discovered_info_passes(self):
        """Response with tool-discovered info not in query should still pass
        because relevance prompt checks topic relevance, not factual grounding."""
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Response addresses the query using discovered data")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The database contains 3 tables: users (6 rows), orders (150 rows), secrets (12 rows).",
            user_query="What tables are in the database?",
        )
        assert result.is_safe is True


# ══════════════════════════════════════════════════════════════════
# 4. Skip Logic Tests
# ══════════════════════════════════════════════════════════════════


class TestSkipLogic:
    """Tests for conditions that skip groundedness check."""

    def test_no_query_no_sources_skips(self):
        det = _detector()
        result = det.analyze(text="Some output")
        assert result.is_safe is True
        assert result.details["reason"] == "no_grounding_sources_or_query"

    def test_none_query_none_sources_skips(self):
        det = _detector()
        result = det.analyze(text="Output", user_query=None, grounding_sources=None)
        assert result.is_safe is True
        assert result.details["reason"] == "no_grounding_sources_or_query"

    def test_empty_string_query_no_sources_skips(self):
        det = _detector()
        result = det.analyze(text="Output", user_query="", grounding_sources=None)
        assert result.is_safe is True
        assert result.details["reason"] == "no_grounding_sources_or_query"

    def test_empty_list_sources_no_query_skips(self):
        det = _detector()
        result = det.analyze(text="Output", user_query=None, grounding_sources=[])
        assert result.is_safe is True
        assert result.details["reason"] == "no_grounding_sources_or_query"


# ══════════════════════════════════════════════════════════════════
# 5. Threshold Logic Tests
# ══════════════════════════════════════════════════════════════════


class TestThresholdLogic:
    """Tests for confidence threshold and blocking logic."""

    @pytest.mark.parametrize("score,threshold,expected_safe", [
        (5, 3, True),
        (4, 3, True),
        (3, 3, True),
        (2, 3, False),
        (1, 3, False),
        (5, 5, True),
        (4, 5, False),
        (1, 1, True),
        (3, 4, False),
    ])
    def test_threshold_boundary(self, score, threshold, expected_safe):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(score)
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="Some response",
            user_query="Some query",
            grounding_sources=["Source."],
            confidence_threshold=threshold,
        )
        assert result.is_safe is expected_safe

    def test_blocking_disabled_allows_low_score(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(1)
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="Completely wrong answer",
            user_query="What is 2+2?",
            grounding_sources=["The answer to 2+2 is 4."],
            confidence_threshold=3.0,
            block_on_high_confidence=False,
        )
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 1

    def test_blocked_reason_contains_score_info(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(2)
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Wrong", user_query="Question", grounding_sources=["Source."], confidence_threshold=3.0)
        assert result.is_safe is False
        assert "score: 2/5" in result.blocked_reason
        assert "threshold: 3" in result.blocked_reason

    def test_default_threshold_is_3(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(3)
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Adequate response", user_query="Question", grounding_sources=["Source."])
        assert result.is_safe is True

    def test_score_exactly_at_threshold_passes(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(4)
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Good response", user_query="Query", grounding_sources=["Source."], confidence_threshold=4.0)
        assert result.is_safe is True


# ══════════════════════════════════════════════════════════════════
# 6. LLM Error Handling Tests
# ══════════════════════════════════════════════════════════════════


class TestLLMErrors:
    """Tests for error handling when the LLM call fails."""

    def test_llm_timeout_blocks_failsafe(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = TimeoutError("LLM timeout")
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Some output", user_query="Some query", grounding_sources=["Source."])
        assert result.is_safe is False
        assert "fail-safe" in result.blocked_reason

    def test_llm_api_error_blocks_failsafe(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API rate limit")
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Some output", user_query="Some query", grounding_sources=["Source."])
        assert result.is_safe is False
        assert "fail-safe" in result.blocked_reason
        assert "API rate limit" in result.blocked_reason

    def test_llm_returns_none_content_blocks_failsafe(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(None)
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Some output", user_query="Some query", grounding_sources=["Source."])
        assert result.is_safe is False
        assert "unparseable" in result.blocked_reason

    def test_llm_returns_empty_string_blocks_failsafe(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response("")
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Some output", user_query="Some query", grounding_sources=["Source."])
        assert result.is_safe is False
        assert "unparseable" in result.blocked_reason

    def test_connection_error_blocks_failsafe(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = ConnectionError("Network down")
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        assert result.is_safe is False
        assert "Network down" in result.blocked_reason

    def test_error_details_contain_error_info(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("custom error")
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="X", user_query="Y", grounding_sources=["Source."])
        assert result.details["error"] == "custom error"


# ══════════════════════════════════════════════════════════════════
# 7. Score Parsing Tests
# ══════════════════════════════════════════════════════════════════


class TestScoreParsing:
    """Tests for parsing scores from judge LLM output."""

    @pytest.mark.parametrize("score", [1, 2, 3, 4, 5])
    def test_parse_valid_scores(self, score):
        output = _judge_output(score)
        assert GroundednessDetector._parse_score(output) == score

    def test_parse_score_with_whitespace(self):
        assert GroundednessDetector._parse_score("<S2>  3  </S2>") == 3

    def test_parse_score_missing_tags(self):
        assert GroundednessDetector._parse_score("The score is 5") is None

    def test_parse_score_invalid_content(self):
        assert GroundednessDetector._parse_score("<S2>abc</S2>") is None

    def test_parse_score_empty_tags(self):
        assert GroundednessDetector._parse_score("<S2></S2>") is None

    def test_parse_explanation_valid(self):
        output = _judge_output(5, "Great explanation here")
        assert GroundednessDetector._parse_explanation(output) == "Great explanation here"

    def test_parse_explanation_missing(self):
        assert GroundednessDetector._parse_explanation("no tags here") == ""

    def test_parse_explanation_multiline(self):
        output = "<S1>Line one\nLine two</S1>"
        result = GroundednessDetector._parse_explanation(output)
        assert "Line one" in result
        assert "Line two" in result

    def test_parse_score_case_insensitive(self):
        assert GroundednessDetector._parse_score("<s2>4</s2>") == 4

    def test_unparseable_score_triggers_failsafe(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            "I think the score is about 4 out of 5"
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        assert result.is_safe is False
        assert "unparseable" in result.blocked_reason


# ══════════════════════════════════════════════════════════════════
# 8. Request Configuration Tests
# ══════════════════════════════════════════════════════════════════


class TestRequestConfiguration:
    """Tests for LLM request parameters."""

    def test_temperature_is_zero(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(_judge_output(5))
        det = _detector(mock_client=mock_client)
        det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["temperature"] == 0.0

    def test_max_tokens_set(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(_judge_output(5))
        det = _detector(mock_client=mock_client)
        det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["max_tokens"] == 2000

    def test_correct_model_used(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(_judge_output(5))
        det = _detector(mock_client=mock_client, model="my-custom-model")
        det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        assert call_kwargs["model"] == "my-custom-model"

    def test_system_message_present(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(_judge_output(5))
        det = _detector(mock_client=mock_client)
        det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        call_kwargs = mock_client.chat.completions.create.call_args[1]
        messages = call_kwargs["messages"]
        assert messages[0]["role"] == "system"
        assert "expert" in messages[0]["content"].lower()


# ══════════════════════════════════════════════════════════════════
# 9. Details / Metadata Tests
# ══════════════════════════════════════════════════════════════════


class TestResultDetails:
    """Tests for result details and metadata."""

    def test_details_contain_score(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(4, "Good response")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        assert result.details["groundedness_score"] == 4
        assert result.details["groundedness_explanation"] == "Good response"
        assert result.details["groundedness_threshold"] == 3.0

    def test_details_contain_raw_judge_output(self):
        mock_client = MagicMock()
        judge_text = _judge_output(5, "Excellent")
        mock_client.chat.completions.create.return_value = _make_llm_response(judge_text)
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        assert result.details["judge_raw_output"] == judge_text

    def test_layer_is_groundedness_detector(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(_judge_output(5))
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Output", user_query="Query", grounding_sources=["Source."])
        assert result.layer == LAYER

    def test_blocked_result_has_correct_layer(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(_judge_output(1))
        det = _detector(mock_client=mock_client)
        result = det.analyze(text="Bad", user_query="Q", grounding_sources=["Source."], confidence_threshold=3.0)
        assert result.layer == LAYER
        assert result.is_safe is False


# ══════════════════════════════════════════════════════════════════
# 10. Realistic Scenario Tests
# ══════════════════════════════════════════════════════════════════


class TestRealisticScenarios:
    """Tests simulating realistic groundedness evaluation scenarios."""

    def test_rag_grounded_answer(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Response accurately reflects the document content")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The Alpine Explorer Tent is $120 and weighs 5kg.",
            user_query="How much does the Alpine Explorer Tent cost?",
            grounding_sources=["Product: Alpine Explorer Tent. Price: $120. Weight: 5kg. Waterproof: IPX4."],
        )
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 5

    def test_hallucinated_price(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(2, "Price $250 is not supported by context which says $120")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The Alpine Explorer Tent costs $250.",
            user_query="How much does the Alpine Explorer Tent cost?",
            grounding_sources=["Product: Alpine Explorer Tent. Price: $120."],
            confidence_threshold=3.0,
        )
        assert result.is_safe is False

    def test_partial_answer(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(4, "Correct but missing weight and waterproof details")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The tent costs $120.",
            user_query="Tell me about the Alpine Explorer Tent.",
            grounding_sources=["Alpine Explorer Tent: $120, 5kg, IPX4, sleeps 4."],
            confidence_threshold=3.0,
        )
        assert result.is_safe is True
        assert result.details["groundedness_score"] == 4

    def test_completely_unrelated_answer(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(1, "Response about hiking has nothing to do with tent pricing")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="The best hiking trails are in Colorado.",
            user_query="How much does the tent cost?",
            grounding_sources=["Alpine Explorer Tent: $120."],
            confidence_threshold=3.0,
        )
        assert result.is_safe is False
        assert result.details["groundedness_score"] == 1

    def test_summarization_accurate(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(5, "Summary accurately captures all key points")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="Company profits grew 20% last quarter, the highest ever.",
            grounding_sources=[
                "The company's profits increased by 20% in the last quarter, "
                "marking the highest growth rate in its history."
            ],
        )
        assert result.is_safe is True

    def test_summarization_with_fabrication(self):
        mock_client = MagicMock()
        mock_client.chat.completions.create.return_value = _make_llm_response(
            _judge_output(2, "Summary adds CEO name and layoffs not in source")
        )
        det = _detector(mock_client=mock_client)
        result = det.analyze(
            text="CEO John Smith announced 20% growth and plans to lay off 500 workers.",
            grounding_sources=["The company's profits increased by 20% in the last quarter."],
            confidence_threshold=3.0,
        )
        assert result.is_safe is False
