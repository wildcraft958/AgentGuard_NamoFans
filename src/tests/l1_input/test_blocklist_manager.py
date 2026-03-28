"""Tests for L1 BlocklistManager module."""

from unittest.mock import MagicMock, patch
import pytest

from agentguard.l1_input.blocklist_manager import BlocklistManager


class TestBlocklistManager:
    @patch("agentguard.l1_input.blocklist_manager.BlocklistClient")
    def test_sync_creates_blocklists_and_adds_terms(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client

        manager = BlocklistManager(endpoint="https://test.com", key="test-key")
        config = [
            {
                "name": "test-list",
                "description": "Test blocklist",
                "terms": ["bad-word", "another-bad"],
            }
        ]

        result = manager.sync_blocklists(config)

        assert result == ["test-list"]
        mock_client.create_or_update_text_blocklist.assert_called_once()
        mock_client.add_or_update_blocklist_items.assert_called_once()

        # Verify terms were passed correctly
        call_args = mock_client.add_or_update_blocklist_items.call_args
        assert call_args[1]["blocklist_name"] == "test-list"
        items = call_args[1]["options"].blocklist_items
        assert len(items) == 2
        assert items[0].text == "bad-word"
        assert items[1].text == "another-bad"

    @patch("agentguard.l1_input.blocklist_manager.BlocklistClient")
    def test_sync_multiple_blocklists(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client

        manager = BlocklistManager(endpoint="https://test.com", key="test-key")
        config = [
            {"name": "list-a", "description": "A", "terms": ["term1"]},
            {"name": "list-b", "description": "B", "terms": ["term2"]},
        ]

        result = manager.sync_blocklists(config)

        assert result == ["list-a", "list-b"]
        assert mock_client.create_or_update_text_blocklist.call_count == 2
        assert mock_client.add_or_update_blocklist_items.call_count == 2

    @patch("agentguard.l1_input.blocklist_manager.BlocklistClient")
    def test_sync_empty_terms_skips_add(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client

        manager = BlocklistManager(endpoint="https://test.com", key="test-key")
        config = [{"name": "empty-list", "description": "Empty", "terms": []}]

        result = manager.sync_blocklists(config)

        assert result == ["empty-list"]
        mock_client.create_or_update_text_blocklist.assert_called_once()
        mock_client.add_or_update_blocklist_items.assert_not_called()

    @patch("agentguard.l1_input.blocklist_manager.BlocklistClient")
    def test_sync_skips_nameless_blocklist(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client

        manager = BlocklistManager(endpoint="https://test.com", key="test-key")
        config = [{"name": "", "description": "No name", "terms": ["x"]}]

        result = manager.sync_blocklists(config)

        assert result == []
        mock_client.create_or_update_text_blocklist.assert_not_called()

    @patch("agentguard.l1_input.blocklist_manager.BlocklistClient")
    def test_sync_empty_config(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client

        manager = BlocklistManager(endpoint="https://test.com", key="test-key")
        result = manager.sync_blocklists([])

        assert result == []

    @patch("agentguard.l1_input.blocklist_manager.BlocklistClient")
    def test_blocklist_names_property(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value = mock_client

        manager = BlocklistManager(endpoint="https://test.com", key="test-key")
        manager.sync_blocklists(
            [
                {"name": "bl1", "description": "", "terms": ["a"]},
            ]
        )

        assert manager.blocklist_names == ["bl1"]

    @patch("agentguard.l1_input.blocklist_manager.BlocklistClient")
    def test_api_error_continues_other_blocklists(self, MockClient):
        from azure.core.exceptions import HttpResponseError

        mock_client = MagicMock()
        MockClient.return_value = mock_client

        # First blocklist fails, second succeeds
        error = HttpResponseError(message="Service error")
        mock_client.create_or_update_text_blocklist.side_effect = [
            error,
            MagicMock(),
        ]

        manager = BlocklistManager(endpoint="https://test.com", key="test-key")
        result = manager.sync_blocklists(
            [
                {"name": "fail-list", "description": "", "terms": ["a"]},
                {"name": "ok-list", "description": "", "terms": ["b"]},
            ]
        )

        assert result == ["ok-list"]

    def test_missing_credentials_raises(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="CONTENT_SAFETY_ENDPOINT"):
                BlocklistManager()
