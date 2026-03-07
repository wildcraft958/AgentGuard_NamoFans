"""Tests for agentguard.tool_firewall.tool_specific_guards (Component 3).

Pure Python guards — no Azure API mocking needed.
"""

import pytest
from unittest.mock import MagicMock

from agentguard.tool_firewall.tool_specific_guards import ToolSpecificGuards


def _make_config(tools_config: dict):
    """Create a minimal mock config with get_tool_config support."""
    config = MagicMock()
    config.get_tool_config = lambda name: tools_config.get(name, {})
    return config


# ---------------------------------------------------------------
# HTTP POST Guards
# ---------------------------------------------------------------

class TestHttpPostGuard:

    def _guards(self, **overrides):
        cfg = {
            "enabled": True,
            "mode": "allowlist",
            "allowed_domains": ["api.mycompany.com", "hooks.slack.com"],
            "require_https": True,
            "block_private_ips": True,
            "max_payload_kb": 512,
            "rate_limit_per_minute": 20,
        }
        cfg.update(overrides)
        return ToolSpecificGuards(_make_config({"http_post": cfg}))

    def test_allowed_domain_passes(self):
        g = self._guards()
        result = g.check("http_post", {"url": "https://api.mycompany.com/v1/data"})
        assert result.is_safe is True

    def test_blocked_domain(self):
        g = self._guards()
        result = g.check("http_post", {"url": "https://evil.com/exfil"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_http_blocked_when_https_required(self):
        g = self._guards()
        result = g.check("http_post", {"url": "http://api.mycompany.com/v1/data"})
        assert result.is_safe is False
        assert "HTTPS required" in result.blocked_reason

    def test_https_not_required(self):
        g = self._guards(require_https=False)
        result = g.check("http_post", {"url": "http://api.mycompany.com/v1/data"})
        assert result.is_safe is True

    def test_private_ip_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("http_post", {"url": "https://192.168.1.1/admin"})
        assert result.is_safe is False
        assert "Private IP" in result.blocked_reason

    def test_private_ip_10_range(self):
        g = self._guards(mode="unrestricted")
        result = g.check("http_post", {"url": "https://10.0.0.5/internal"})
        assert result.is_safe is False
        assert "Private IP" in result.blocked_reason

    def test_loopback_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("http_post", {"url": "https://127.0.0.1/admin"})
        assert result.is_safe is False

    def test_payload_too_large(self):
        g = self._guards(mode="unrestricted", block_private_ips=False)
        big_body = "x" * (513 * 1024)  # 513 KB
        result = g.check("http_post", {"url": "https://example.com", "body": big_body})
        assert result.is_safe is False
        assert "Payload too large" in result.blocked_reason

    def test_payload_within_limit(self):
        g = self._guards(mode="unrestricted", block_private_ips=False)
        small_body = "x" * 100
        result = g.check("http_post", {"url": "https://example.com", "body": small_body})
        assert result.is_safe is True

    def test_rate_limit_exceeded(self):
        g = self._guards(mode="unrestricted", block_private_ips=False, rate_limit_per_minute=3)
        for _ in range(3):
            result = g.check("http_post", {"url": "https://example.com"})
            assert result.is_safe is True
        result = g.check("http_post", {"url": "https://example.com"})
        assert result.is_safe is False
        assert "Rate limit" in result.blocked_reason

    def test_subdomain_matches_allowlist(self):
        g = self._guards()
        result = g.check("http_post", {"url": "https://v2.api.mycompany.com/data"})
        assert result.is_safe is True


# ---------------------------------------------------------------
# HTTP GET Guards
# ---------------------------------------------------------------

class TestHttpGetGuard:

    def _guards(self, **overrides):
        cfg = {
            "enabled": True,
            "mode": "allowlist",
            "allowed_domains": ["wikipedia.org", "docs.mycompany.com"],
            "block_metadata_services": True,
        }
        cfg.update(overrides)
        return ToolSpecificGuards(_make_config({"http_get": cfg}))

    def test_allowed_domain_passes(self):
        g = self._guards()
        result = g.check("http_get", {"url": "https://wikipedia.org/wiki/Python"})
        assert result.is_safe is True

    def test_blocked_domain(self):
        g = self._guards()
        result = g.check("http_get", {"url": "https://evil.com/data"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_metadata_service_169_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("http_get", {"url": "http://169.254.169.254/latest/meta-data/"})
        assert result.is_safe is False
        assert "metadata service" in result.blocked_reason.lower()

    def test_metadata_google_internal_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("http_get", {"url": "http://metadata.google.internal/computeMetadata/v1/"})
        assert result.is_safe is False
        assert "metadata service" in result.blocked_reason.lower()

    def test_metadata_blocking_disabled(self):
        g = self._guards(mode="unrestricted", block_metadata_services=False)
        result = g.check("http_get", {"url": "http://169.254.169.254/latest/meta-data/"})
        assert result.is_safe is True


# ---------------------------------------------------------------
# SQL Query Guards
# ---------------------------------------------------------------

class TestSqlQueryGuard:

    def _guards(self, **overrides):
        cfg = {
            "enabled": True,
            "mode": "restricted",
            "allowed_statements": ["SELECT"],
            "denied_statements": ["DROP", "DELETE", "UPDATE"],
            "max_rows_returned": 1000,
        }
        cfg.update(overrides)
        return ToolSpecificGuards(_make_config({"sql_query": cfg}))

    def test_select_allowed(self):
        g = self._guards()
        result = g.check("sql_query", {"query": "SELECT * FROM users WHERE id = 1"})
        assert result.is_safe is True

    def test_drop_blocked(self):
        g = self._guards()
        result = g.check("sql_query", {"query": "DROP TABLE users"})
        assert result.is_safe is False
        assert "DROP" in result.blocked_reason

    def test_delete_blocked(self):
        g = self._guards()
        result = g.check("sql_query", {"query": "DELETE FROM users WHERE id = 1"})
        assert result.is_safe is False
        assert "DELETE" in result.blocked_reason

    def test_update_blocked(self):
        g = self._guards()
        result = g.check("sql_query", {"query": "UPDATE users SET admin = 1"})
        assert result.is_safe is False
        assert "UPDATE" in result.blocked_reason

    def test_insert_not_in_allowlist(self):
        g = self._guards()
        result = g.check("sql_query", {"query": "INSERT INTO users VALUES (1, 'test')"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_drop_in_subquery(self):
        g = self._guards()
        result = g.check("sql_query", {"query": "SELECT * FROM users; DROP TABLE users"})
        assert result.is_safe is False
        assert "DROP" in result.blocked_reason

    def test_case_insensitive(self):
        g = self._guards()
        result = g.check("sql_query", {"query": "select * from users"})
        assert result.is_safe is True

    def test_empty_query_passes(self):
        g = self._guards()
        result = g.check("sql_query", {"query": ""})
        assert result.is_safe is True


# ---------------------------------------------------------------
# File System Guards
# ---------------------------------------------------------------

class TestFileSystemGuard:

    def _guards(self, **overrides):
        cfg = {
            "enabled": True,
            "allowed_paths": ["/tmp/", "/app/safe_data/"],
            "deny_extensions": [".env", ".pem", ".key"],
        }
        cfg.update(overrides)
        return ToolSpecificGuards(_make_config({"file_system": cfg}))

    def test_allowed_path_passes(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": "/tmp/report.txt"})
        assert result.is_safe is True

    def test_path_outside_allowlist(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": "/etc/passwd"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_path_traversal_detected(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": "/tmp/../etc/passwd"})
        assert result.is_safe is False
        assert "traversal" in result.blocked_reason.lower()

    def test_denied_extension_env(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": "/tmp/secrets.env"})
        assert result.is_safe is False
        assert ".env" in result.blocked_reason

    def test_denied_extension_pem(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": "/tmp/server.pem"})
        assert result.is_safe is False
        assert ".pem" in result.blocked_reason

    def test_denied_extension_key(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": "/app/safe_data/private.key"})
        assert result.is_safe is False
        assert ".key" in result.blocked_reason

    def test_safe_extension_passes(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": "/app/safe_data/config.json"})
        assert result.is_safe is True

    def test_empty_path_passes(self):
        g = self._guards()
        result = g.check("file_system", {"file_path": ""})
        assert result.is_safe is True

    def test_path_param_alias(self):
        """file_system guard should also accept 'path' as arg name."""
        g = self._guards()
        result = g.check("file_system", {"path": "/etc/shadow"})
        assert result.is_safe is False


# ---------------------------------------------------------------
# Unconfigured tool — should pass
# ---------------------------------------------------------------

class TestUnconfiguredTool:

    def test_unknown_tool_passes(self):
        g = ToolSpecificGuards(_make_config({}))
        result = g.check("some_random_tool", {"arg": "value"})
        assert result.is_safe is True

    def test_disabled_tool_passes(self):
        g = ToolSpecificGuards(_make_config({"http_post": {"enabled": False}}))
        result = g.check("http_post", {"url": "https://evil.com"})
        assert result.is_safe is True
