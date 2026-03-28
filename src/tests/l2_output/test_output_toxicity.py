"""Tests for L2 OutputToxicity module."""

from unittest.mock import MagicMock
import pytest

from agentguard.l2_output.output_toxicity import OutputToxicity
from agentguard.models import ValidationResult


@pytest.fixture
def mock_content_filters():
    return MagicMock()


@pytest.fixture
def output_toxicity(mock_content_filters):
    return OutputToxicity(mock_content_filters)


class TestOutputToxicity:
    def test_safe_output(self, output_toxicity, mock_content_filters):
        mock_content_filters.analyze_text.return_value = ValidationResult(
            is_safe=True,
            layer="content_filters",
            details={"severities": {"hate": 0, "self_harm": 0, "sexual": 0, "violence": 0}},
        )
        result = output_toxicity.analyze("This is a helpful response about hiking.")
        assert result.is_safe is True
        assert result.layer == "output_toxicity"

    def test_toxic_output_blocked(self, output_toxicity, mock_content_filters):
        mock_content_filters.analyze_text.return_value = ValidationResult(
            is_safe=False,
            layer="content_filters",
            blocked_reason="Harmful content detected: Hate/Toxicity (severity=4)",
            details={"severities": {"hate": 4, "self_harm": 0, "sexual": 0, "violence": 0}},
        )
        result = output_toxicity.analyze("hateful content here")
        assert result.is_safe is False
        assert result.layer == "output_toxicity"
        assert "Hate" in result.blocked_reason

    def test_delegates_to_content_filters(self, output_toxicity, mock_content_filters):
        mock_content_filters.analyze_text.return_value = ValidationResult(
            is_safe=True,
            layer="content_filters",
            details={},
        )
        output_toxicity.analyze(
            text="test",
            block_toxicity=True,
            block_violence=False,
            block_self_harm=True,
            severity_threshold=2,
        )
        mock_content_filters.analyze_text.assert_called_once_with(
            text="test",
            block_toxicity=True,
            block_violence=False,
            block_self_harm=True,
            severity_threshold=2,
        )
