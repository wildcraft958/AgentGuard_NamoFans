"""Tests for L2 PIIDetector module."""

from unittest.mock import MagicMock, patch
import pytest

from agentguard.l2_output.pii_detector import PIIDetector


def _make_mock_entity(text, category, subcategory=None, confidence=0.99):
    entity = MagicMock()
    entity.text = text
    entity.category = category
    entity.subcategory = subcategory
    entity.confidence_score = confidence
    return entity


def _make_mock_doc(redacted_text, entities, is_error=False, error_message=None):
    doc = MagicMock()
    doc.is_error = is_error
    doc.redacted_text = redacted_text
    doc.entities = entities
    if is_error:
        doc.error = MagicMock()
        doc.error.message = error_message
    return doc


class TestPIIDetector:
    @patch("agentguard.l2_output.pii_detector.TextAnalyticsClient")
    def test_no_pii_found(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client
        mock_client.recognize_pii_entities.return_value = [_make_mock_doc("Hello world", [])]

        detector = PIIDetector(endpoint="https://test.com", key="test-key")
        result = detector.analyze("Hello world")

        assert result.is_safe is True
        assert result.layer == "pii_detector"
        assert result.details["entity_count"] == 0

    @patch("agentguard.l2_output.pii_detector.TextAnalyticsClient")
    def test_pii_found_and_blocked(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client
        mock_client.recognize_pii_entities.return_value = [
            _make_mock_doc(
                "****** has SSN ***-**-****",
                [
                    _make_mock_entity("John Smith", "PersonName"),
                    _make_mock_entity("859-98-0987", "USSocialSecurityNumber"),
                ],
            )
        ]

        detector = PIIDetector(endpoint="https://test.com", key="test-key")
        result = detector.analyze("John Smith has SSN 859-98-0987")

        assert result.is_safe is False
        assert result.layer == "pii_detector"
        assert result.details["entity_count"] == 2
        assert result.details["redacted_text"] == "****** has SSN ***-**-****"
        assert "PersonName" in result.blocked_reason

    @patch("agentguard.l2_output.pii_detector.TextAnalyticsClient")
    def test_pii_found_not_blocked(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client
        mock_client.recognize_pii_entities.return_value = [
            _make_mock_doc(
                "****** works at ****",
                [_make_mock_entity("John", "PersonName")],
            )
        ]

        detector = PIIDetector(endpoint="https://test.com", key="test-key")
        result = detector.analyze("John works at Acme", block_on_pii=False)

        assert result.is_safe is True
        assert result.details["entity_count"] == 1

    @patch("agentguard.l2_output.pii_detector.TextAnalyticsClient")
    def test_allowed_categories_filtered(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client
        mock_client.recognize_pii_entities.return_value = [
            _make_mock_doc(
                "****** at ****",
                [
                    _make_mock_entity("John", "PersonName"),
                    _make_mock_entity("Acme Corp", "Organization"),
                ],
            )
        ]

        detector = PIIDetector(endpoint="https://test.com", key="test-key")
        result = detector.analyze(
            "John at Acme Corp",
            allowed_categories=["Organization"],
        )

        # Only PersonName should be flagged, Organization is allowed
        assert result.is_safe is False
        assert result.details["entity_count"] == 1
        assert result.details["entities"][0]["category"] == "PersonName"

    @patch("agentguard.l2_output.pii_detector.TextAnalyticsClient")
    def test_api_error_blocks_as_failsafe(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client
        mock_client.recognize_pii_entities.return_value = [
            _make_mock_doc("", [], is_error=True, error_message="Service unavailable")
        ]

        detector = PIIDetector(endpoint="https://test.com", key="test-key")
        result = detector.analyze("some text")

        assert result.is_safe is False
        assert "fail-safe" in result.blocked_reason

    def test_missing_credentials_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="AZURE_LANGUAGE_ENDPOINT"):
                PIIDetector()
