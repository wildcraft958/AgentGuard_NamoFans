"""Tests for agentguard.l1_input.content_filters module (text + image)."""

import pytest
from unittest.mock import patch, MagicMock

from agentguard.l1_input.content_filters import ContentFilters


def _make_category_item(category, severity):
    """Create a mock category analysis item."""
    item = MagicMock()
    item.category = category
    item.severity = severity
    return item


# ---------------------------------------------------------------
# Text Moderation Tests
# ---------------------------------------------------------------


class TestContentFiltersText:
    """Tests for ContentFilters.analyze_text() (text moderation)."""

    @pytest.fixture
    def filters(self):
        """Create a ContentFilters instance with mocked client."""
        with patch("agentguard.l1_input.content_filters.ContentSafetyClient"):
            cf = ContentFilters(
                endpoint="https://test.cognitiveservices.azure.com",
                key="test-key-123",
            )
        return cf

    def _mock_text_response(self, filters, hate=0, self_harm=0, sexual=0, violence=0):
        from azure.ai.contentsafety.models import TextCategory

        mock_result = MagicMock()
        mock_result.categories_analysis = [
            _make_category_item(TextCategory.HATE, hate),
            _make_category_item(TextCategory.SELF_HARM, self_harm),
            _make_category_item(TextCategory.SEXUAL, sexual),
            _make_category_item(TextCategory.VIOLENCE, violence),
        ]
        mock_result.blocklists_match = None
        filters.client.analyze_text.return_value = mock_result

    def test_safe_text(self, filters):
        self._mock_text_response(filters)
        result = filters.analyze_text("What camping gear do you recommend?")
        assert result.is_safe is True
        assert result.layer == "content_filters"
        assert result.details["severities"]["hate"] == 0

    def test_hate_detected(self, filters):
        self._mock_text_response(filters, hate=4)
        result = filters.analyze_text("Some hateful content")
        assert result.is_safe is False
        assert "Hate/Toxicity" in result.blocked_reason

    def test_violence_detected(self, filters):
        self._mock_text_response(filters, violence=6)
        result = filters.analyze_text("Some violent content")
        assert result.is_safe is False
        assert "Violence" in result.blocked_reason

    def test_self_harm_detected(self, filters):
        self._mock_text_response(filters, self_harm=2)
        result = filters.analyze_text("Some self-harm content")
        assert result.is_safe is False
        assert "Self-Harm" in result.blocked_reason

    def test_sexual_detected(self, filters):
        self._mock_text_response(filters, sexual=4)
        result = filters.analyze_text("Some sexual content")
        assert result.is_safe is False
        assert "Sexual" in result.blocked_reason

    def test_multiple_violations(self, filters):
        self._mock_text_response(filters, hate=4, violence=6)
        result = filters.analyze_text("Hateful and violent content")
        assert result.is_safe is False
        assert "Hate/Toxicity" in result.blocked_reason
        assert "Violence" in result.blocked_reason

    def test_severity_threshold(self, filters):
        self._mock_text_response(filters, hate=2)
        result = filters.analyze_text("Mildly concerning", severity_threshold=2)
        assert result.is_safe is True

    def test_toxicity_disabled(self, filters):
        self._mock_text_response(filters, hate=4)
        result = filters.analyze_text("Hateful content", block_toxicity=False)
        assert result.is_safe is True

    def test_violence_disabled(self, filters):
        self._mock_text_response(filters, violence=6)
        result = filters.analyze_text("Violent content", block_violence=False)
        assert result.is_safe is True

    def test_api_error_handled(self, filters):
        from azure.core.exceptions import HttpResponseError

        error = HttpResponseError(message="Service unavailable")
        error.error = MagicMock()
        error.error.code = "ServiceUnavailable"
        error.error.message = "Service is currently unavailable"
        filters.client.analyze_text.side_effect = error
        result = filters.analyze_text("test input")
        assert result.is_safe is False
        assert "API error" in result.blocked_reason

    def test_missing_credentials(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="CONTENT_SAFETY_ENDPOINT"):
                ContentFilters(endpoint="", key="")


# ---------------------------------------------------------------
# Image Moderation Tests
# ---------------------------------------------------------------


class TestContentFiltersImage:
    """Tests for ContentFilters.analyze_image() (image moderation)."""

    @pytest.fixture
    def filters(self):
        with patch("agentguard.l1_input.content_filters.ContentSafetyClient"):
            cf = ContentFilters(
                endpoint="https://test.cognitiveservices.azure.com",
                key="test-key-123",
            )
        return cf

    def _mock_image_response(self, filters, hate=0, self_harm=0, sexual=0, violence=0):
        from azure.ai.contentsafety.models import ImageCategory

        mock_result = MagicMock()
        mock_result.categories_analysis = [
            _make_category_item(ImageCategory.HATE, hate),
            _make_category_item(ImageCategory.SELF_HARM, self_harm),
            _make_category_item(ImageCategory.SEXUAL, sexual),
            _make_category_item(ImageCategory.VIOLENCE, violence),
        ]
        filters.client.analyze_image.return_value = mock_result

    def test_safe_image(self, filters):
        self._mock_image_response(filters)
        result = filters.analyze_image(b"\x89PNG\r\n\x1a\nfake")
        assert result.is_safe is True
        assert result.layer == "content_filters"
        assert result.details["severities"]["hate"] == 0

    def test_violence_detected(self, filters):
        self._mock_image_response(filters, violence=4)
        result = filters.analyze_image(b"fake")
        assert result.is_safe is False
        assert "Violence" in result.blocked_reason

    def test_hate_detected(self, filters):
        self._mock_image_response(filters, hate=4)
        result = filters.analyze_image(b"fake")
        assert result.is_safe is False
        assert "Hate" in result.blocked_reason

    def test_sexual_detected(self, filters):
        self._mock_image_response(filters, sexual=6)
        result = filters.analyze_image(b"fake")
        assert result.is_safe is False
        assert "Sexual" in result.blocked_reason

    def test_self_harm_detected(self, filters):
        self._mock_image_response(filters, self_harm=4)
        result = filters.analyze_image(b"fake")
        assert result.is_safe is False
        assert "Self-Harm" in result.blocked_reason

    def test_severity_threshold(self, filters):
        self._mock_image_response(filters, violence=2)
        result = filters.analyze_image(b"fake", severity_threshold=2)
        assert result.is_safe is True

    def test_category_disabled(self, filters):
        self._mock_image_response(filters, violence=4)
        result = filters.analyze_image(b"fake", block_violence=False)
        assert result.is_safe is True

    def test_api_error_handled(self, filters):
        from azure.core.exceptions import HttpResponseError

        error = HttpResponseError(message="Service error")
        error.error = None
        filters.client.analyze_image.side_effect = error
        result = filters.analyze_image(b"fake")
        assert result.is_safe is False
        assert "API error" in result.blocked_reason

    def test_multiple_violations(self, filters):
        self._mock_image_response(filters, hate=4, violence=6)
        result = filters.analyze_image(b"fake")
        assert result.is_safe is False
        assert "Hate" in result.blocked_reason
        assert "Violence" in result.blocked_reason
