"""Tests for decorator → L1 → function → L2 groundedness flow.

Verifies that the @guard decorator correctly threads user_text and
documents from L1 input into L2 validate_output() for groundedness
checking.
"""

import asyncio
from unittest.mock import patch, MagicMock

import pytest

from agentguard.decorators import guard, guard_input, _guardian_cache
from agentguard.exceptions import OutputBlockedError
from agentguard.models import InputValidationResult, OutputValidationResult


@pytest.fixture(autouse=True)
def clear_cache():
    _guardian_cache.clear()
    yield
    _guardian_cache.clear()


def _mock_guardian(output_result=None):
    """Create a mock Guardian with safe L1 and configurable L2."""
    mock = MagicMock()
    mock.validate_input.return_value = InputValidationResult(is_safe=True, results=[])
    if output_result is None:
        mock.validate_output.return_value = OutputValidationResult(
            is_safe=True, results=[]
        )
    else:
        mock.validate_output.return_value = output_result
    return mock


def _mock_guardian_output_blocked(reason="Ungrounded content detected"):
    """Create a mock Guardian that blocks output."""
    mock = MagicMock()
    mock.validate_input.return_value = InputValidationResult(is_safe=True, results=[])
    mock.validate_output.side_effect = OutputBlockedError(reason=reason)
    return mock


# ── Document threading (L1 input → L2 output) ────────────────────

class TestDocumentThreading:

    @patch("agentguard.decorators._get_guardian")
    def test_guard_passes_documents_to_validate_output(self, mock_get):
        """@guard(docs_param='docs', output_field='response') should thread
        documents from L1 to validate_output(grounding_sources=docs)."""
        mock_guardian = _mock_guardian()
        mock_get.return_value = mock_guardian

        @guard(param="query", docs_param="docs", output_field="response")
        def search(query: str, docs: list = None):
            return {"response": "The answer is 42."}

        search(query="What is the answer?", docs=["The answer to everything is 42."])

        mock_guardian.validate_output.assert_called_once_with(
            "The answer is 42.",
            user_query="What is the answer?",
            grounding_sources=["The answer to everything is 42."],
        )

    @patch("agentguard.decorators._get_guardian")
    def test_guard_passes_user_text_to_validate_output(self, mock_get):
        """user_text from L1 should become user_query in validate_output."""
        mock_guardian = _mock_guardian()
        mock_get.return_value = mock_guardian

        @guard(param="message", output_field="response")
        def chat(message: str):
            return {"response": "Reply here."}

        chat(message="Hello world")

        mock_guardian.validate_output.assert_called_once_with(
            "Reply here.",
            user_query="Hello world",
            grounding_sources=None,
        )

    @patch("agentguard.decorators._get_guardian")
    def test_guard_passes_both_query_and_docs_to_validate_output(self, mock_get):
        """Both user_text and documents should flow into validate_output."""
        mock_guardian = _mock_guardian()
        mock_get.return_value = mock_guardian

        @guard(param="q", docs_param="sources", output_field="answer")
        def qa(q: str, sources: list = None):
            return {"answer": "Contoso sells camping gear."}

        qa(
            q="What does Contoso sell?",
            sources=["Contoso sells camping equipment.", "Contoso has 3 stores."],
        )

        mock_guardian.validate_output.assert_called_once_with(
            "Contoso sells camping gear.",
            user_query="What does Contoso sell?",
            grounding_sources=["Contoso sells camping equipment.", "Contoso has 3 stores."],
        )

    @patch("agentguard.decorators._get_guardian")
    def test_guard_no_docs_no_query_groundedness_skipped(self, mock_get):
        """When no param/docs_param, validate_output should get None for both."""
        mock_guardian = _mock_guardian()
        mock_get.return_value = mock_guardian

        @guard(output_field="out")
        def process(count: int):
            return {"out": "result"}

        process(5)

        # user_query=None because no string param found, grounding_sources=None
        mock_guardian.validate_output.assert_called_once_with(
            "result",
            user_query=None,
            grounding_sources=None,
        )


# ── Blocking behavior ────────────────────────────────────────────

class TestBlockingBehavior:

    @patch("agentguard.decorators._get_guardian")
    def test_guard_output_blocked_by_groundedness_raises(self, mock_get):
        """OutputBlockedError should propagate from validate_output."""
        mock_get.return_value = _mock_guardian_output_blocked(
            "Ungrounded content detected in output (85% ungrounded)"
        )

        @guard(param="msg", output_field="response")
        def chat(msg: str):
            return {"response": "Hallucinated output."}

        with pytest.raises(OutputBlockedError) as exc_info:
            chat(msg="Tell me about Contoso.")

        assert "ungrounded" in str(exc_info.value).lower()

    @patch("agentguard.decorators._get_guardian")
    def test_guard_async_output_blocked_by_groundedness(self, mock_get):
        """OutputBlockedError should propagate from async validate_output."""
        mock_get.return_value = _mock_guardian_output_blocked(
            "Ungrounded content detected"
        )

        @guard(param="msg", output_field="response")
        async def async_chat(msg: str):
            return {"response": "Hallucinated output."}

        with pytest.raises(OutputBlockedError):
            asyncio.run(async_chat(msg="Query"))


# ── Backward compatibility ───────────────────────────────────────

class TestBackwardCompatibility:

    @patch("agentguard.decorators._get_guardian")
    def test_guard_input_only_still_works(self, mock_get):
        """@guard_input() should still work — no L2 at all."""
        mock_guardian = _mock_guardian()
        mock_get.return_value = mock_guardian

        @guard_input(param="msg")
        def chat(msg: str):
            return f"Reply: {msg}"

        result = chat(msg="Hello")
        assert result == "Reply: Hello"
        mock_guardian.validate_input.assert_called_once()
        mock_guardian.validate_output.assert_not_called()

    @patch("agentguard.decorators._get_guardian")
    def test_guard_without_output_field_no_l2(self, mock_get):
        """@guard(param='msg') without output_field should skip validate_output."""
        mock_guardian = _mock_guardian()
        mock_get.return_value = mock_guardian

        @guard(param="msg")
        def chat(msg: str):
            return "Reply"

        chat(msg="Hello")
        mock_guardian.validate_output.assert_not_called()

    @patch("agentguard.decorators._get_guardian")
    def test_existing_validate_output_signature_compatible(self, mock_get):
        """guardian.validate_output('text') still works without new params
        (defaults to None)."""
        mock_guardian = _mock_guardian()
        mock_get.return_value = mock_guardian

        # Call validate_output directly with just text (backward compat)
        mock_guardian.validate_output("Some output")
        mock_guardian.validate_output.assert_called_once_with("Some output")
