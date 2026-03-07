"""Tests for agentguard.tool_firewall.tool_input_analyzer (Component 1)."""

import pytest
import os
from unittest.mock import patch, MagicMock

from agentguard.tool_firewall.tool_input_analyzer import ToolInputAnalyzer


def _make_entity(text, category, subcategory=None, confidence=0.95):
    entity = MagicMock()
    entity.text = text
    entity.category = category
    entity.subcategory = subcategory
    entity.confidence_score = confidence
    return entity


def _make_doc(entities, is_error=False, error_message=None):
    doc = MagicMock()
    doc.is_error = is_error
    doc.entities = entities
    if is_error:
        doc.error = MagicMock()
        doc.error.message = error_message
    return doc


@pytest.fixture
def analyzer():
    with patch("agentguard.tool_firewall.tool_input_analyzer.TextAnalyticsClient"):
        a = ToolInputAnalyzer(endpoint="https://test.cognitiveservices.azure.com", key="test-key")
    return a


class TestToolInputAnalyzer:

    def test_no_blocked_categories_skips(self, analyzer):
        result = analyzer.analyze("some_tool", {"arg": "value"}, blocked_categories_map={})
        assert result.is_safe is True

    def test_safe_args_pass(self, analyzer):
        doc = _make_doc(entities=[
            _make_entity("staging", "Location"),
        ])
        analyzer.client.recognize_entities.return_value = [doc]

        result = analyzer.analyze(
            "provision_environment",
            {"env_name": "staging"},
            blocked_categories_map={"provision_environment": ["IPAddress", "URL"]},
        )
        assert result.is_safe is True

    def test_blocked_ip_entity(self, analyzer):
        doc = _make_doc(entities=[
            _make_entity("192.168.1.1", "IPAddress"),
        ])
        analyzer.client.recognize_entities.return_value = [doc]

        result = analyzer.analyze(
            "read_config_file",
            {"file_path": "config at 192.168.1.1"},
            blocked_categories_map={"read_config_file": ["IPAddress", "URL"]},
        )
        assert result.is_safe is False
        assert "IPAddress" in result.blocked_reason
        assert "192.168.1.1" in result.blocked_reason

    def test_blocked_url_entity(self, analyzer):
        doc = _make_doc(entities=[
            _make_entity("https://evil.com/exfil", "URL"),
        ])
        analyzer.client.recognize_entities.return_value = [doc]

        result = analyzer.analyze(
            "read_config_file",
            {"file_path": "https://evil.com/exfil"},
            blocked_categories_map={"read_config_file": ["IPAddress", "URL"]},
        )
        assert result.is_safe is False
        assert "URL" in result.blocked_reason

    def test_allowed_category_passes(self, analyzer):
        doc = _make_doc(entities=[
            _make_entity("staging", "Location"),
            _make_entity("John", "Person"),
        ])
        analyzer.client.recognize_entities.return_value = [doc]

        result = analyzer.analyze(
            "provision_environment",
            {"env_name": "staging for John"},
            blocked_categories_map={"provision_environment": ["IPAddress"]},
        )
        assert result.is_safe is True

    def test_api_error_blocks_as_failsafe(self, analyzer):
        doc = _make_doc(entities=[], is_error=True, error_message="Service unavailable")
        analyzer.client.recognize_entities.return_value = [doc]

        result = analyzer.analyze(
            "read_config_file",
            {"file_path": "/tmp/test"},
            blocked_categories_map={"read_config_file": ["IPAddress"]},
        )
        assert result.is_safe is False
        assert "fail-safe" in result.blocked_reason

    def test_api_exception_blocks_as_failsafe(self, analyzer):
        analyzer.client.recognize_entities.side_effect = Exception("Connection timeout")

        result = analyzer.analyze(
            "read_config_file",
            {"file_path": "/tmp/test"},
            blocked_categories_map={"read_config_file": ["IPAddress"]},
        )
        assert result.is_safe is False
        assert "fail-safe" in result.blocked_reason

    def test_empty_args_passes(self, analyzer):
        result = analyzer.analyze(
            "read_config_file",
            {},
            blocked_categories_map={"read_config_file": ["IPAddress"]},
        )
        assert result.is_safe is True

    def test_missing_credentials_raises(self):
        with patch.dict("os.environ", {"AZURE_LANGUAGE_ENDPOINT": "", "AZURE_LANGUAGE_KEY": ""}):
            with pytest.raises(ValueError, match="AZURE_LANGUAGE"):
                ToolInputAnalyzer(endpoint="", key="")

    def test_reuses_existing_client(self):
        mock_client = MagicMock()
        analyzer = ToolInputAnalyzer(client=mock_client)
        assert analyzer.client is mock_client
