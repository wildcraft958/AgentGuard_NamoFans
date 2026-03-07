"""Tests for agentguard.tool_firewall.tool_specific_guards (Component 3).

Tests the argument-aware guardrails that scan every tool call's arguments
for file paths, URLs, and SQL strings — regardless of tool name.

Pure Python guards — no Azure API mocking needed.
"""

import pytest
from unittest.mock import MagicMock

from agentguard.tool_firewall.tool_specific_guards import ToolSpecificGuards


def _make_config(
    file_system=None,
    sql_query=None,
    http_post=None,
    http_get=None,
    tools=None,
    default_policy="allow",
):
    """Create a mock config with guardrail configs under tool_firewall."""
    config = MagicMock()
    config.tool_firewall_file_system_config = file_system or {}
    config.tool_firewall_sql_query_config = sql_query or {}
    config.tool_firewall_http_post_config = http_post or {}
    config.tool_firewall_http_get_config = http_get or {}
    config.tool_firewall_default_policy = default_policy
    config.get_tool_config = lambda name: (tools or {}).get(name, {})
    return config


# Default guardrail configs for tests
_FS_CFG = {
    "enabled": True,
    "allowed_paths": ["/tmp/", "/app/safe_data/"],
    "deny_extensions": [".env", ".pem", ".key"],
}

_SQL_CFG = {
    "enabled": True,
    "allowed_statements": ["SELECT"],
    "denied_statements": ["DROP", "DELETE", "UPDATE"],
}

_HTTP_POST_CFG = {
    "enabled": True,
    "mode": "allowlist",
    "allowed_domains": ["api.mycompany.com", "hooks.slack.com"],
    "require_https": True,
    "block_private_ips": True,
    "max_payload_kb": 512,
    "rate_limit_per_minute": 20,
}

_HTTP_GET_CFG = {
    "enabled": True,
    "mode": "allowlist",
    "allowed_domains": ["wikipedia.org", "docs.mycompany.com"],
    "block_metadata_services": True,
}


# ---------------------------------------------------------------
# Generic argument scanning — any tool name triggers the right guardrail
# ---------------------------------------------------------------

class TestGenericScanning:
    """Guardrails run on ANY tool, not just hardcoded names."""

    def test_arbitrary_tool_path_blocked(self):
        """fs_read_file with a path arg → file_system guardrail."""
        g = ToolSpecificGuards(_make_config(file_system=_FS_CFG))
        result = g.check("fs_read_file", {"file_path": "/etc/shadow"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_arbitrary_tool_url_blocked(self):
        """custom_fetch with a URL arg → http_get guardrail."""
        g = ToolSpecificGuards(_make_config(http_get=_HTTP_GET_CFG))
        result = g.check("custom_fetch", {"url": "https://evil.com/data"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_arbitrary_tool_sql_blocked(self):
        """db_run with a SQL arg → sql_query guardrail."""
        g = ToolSpecificGuards(_make_config(sql_query=_SQL_CFG))
        result = g.check("db_run", {"query": "DROP TABLE users"})
        assert result.is_safe is False
        assert "DROP" in result.blocked_reason

    def test_safe_path_allowed(self):
        """Any tool with a safe path → allowed."""
        g = ToolSpecificGuards(_make_config(file_system=_FS_CFG))
        result = g.check("any_tool", {"path": "/tmp/data.json"})
        assert result.is_safe is True

    def test_safe_url_allowed(self):
        """Any tool with an allowed domain → allowed."""
        g = ToolSpecificGuards(_make_config(http_get=_HTTP_GET_CFG))
        result = g.check("any_tool", {"url": "https://wikipedia.org/wiki/Python"})
        assert result.is_safe is True

    def test_safe_sql_allowed(self):
        """Any tool with a safe SELECT → allowed."""
        g = ToolSpecificGuards(_make_config(sql_query=_SQL_CFG))
        result = g.check("any_tool", {"query": "SELECT * FROM users WHERE id = 1"})
        assert result.is_safe is True

    def test_no_guardrail_triggered(self):
        """Tool with non-path, non-URL, non-SQL args → no guardrail."""
        g = ToolSpecificGuards(_make_config(
            file_system=_FS_CFG, sql_query=_SQL_CFG,
            http_get=_HTTP_GET_CFG, http_post=_HTTP_POST_CFG,
        ))
        result = g.check("memory_store", {"key": "hello", "value": "world"})
        assert result.is_safe is True


# ---------------------------------------------------------------
# HTTP POST guardrail
# ---------------------------------------------------------------

class TestHttpPostGuardrail:

    def _guards(self, **overrides):
        cfg = {**_HTTP_POST_CFG, **overrides}
        return ToolSpecificGuards(_make_config(http_post=cfg))

    def test_allowed_domain_passes(self):
        g = self._guards()
        result = g.check("http_post_tool", {"url": "https://api.mycompany.com/v1/data"})
        assert result.is_safe is True

    def test_blocked_domain(self):
        g = self._guards()
        result = g.check("http_post_tool", {"url": "https://evil.com/exfil"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_http_blocked_when_https_required(self):
        g = self._guards()
        result = g.check("http_post_tool", {"url": "http://api.mycompany.com/v1/data"})
        assert result.is_safe is False
        assert "HTTPS required" in result.blocked_reason

    def test_https_not_required(self):
        g = self._guards(require_https=False)
        result = g.check("http_post_tool", {"url": "http://api.mycompany.com/v1/data"})
        assert result.is_safe is True

    def test_private_ip_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("http_post_tool", {"url": "https://192.168.1.1/admin"})
        assert result.is_safe is False
        assert "Private IP" in result.blocked_reason

    def test_private_ip_10_range(self):
        g = self._guards(mode="unrestricted")
        result = g.check("http_post_tool", {"url": "https://10.0.0.5/internal"})
        assert result.is_safe is False
        assert "Private IP" in result.blocked_reason

    def test_loopback_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("send_data", {"url": "https://127.0.0.1/admin"})
        assert result.is_safe is False

    def test_payload_too_large(self):
        g = self._guards(mode="unrestricted", block_private_ips=False)
        big_body = "x" * (513 * 1024)
        result = g.check("upload_file", {"url": "https://example.com", "body": big_body})
        assert result.is_safe is False
        assert "Payload too large" in result.blocked_reason

    def test_payload_within_limit(self):
        g = self._guards(mode="unrestricted", block_private_ips=False)
        small_body = "x" * 100
        result = g.check("upload_file", {"url": "https://example.com", "body": small_body})
        assert result.is_safe is True

    def test_rate_limit_exceeded(self):
        g = self._guards(mode="unrestricted", block_private_ips=False, rate_limit_per_minute=3)
        for _ in range(3):
            result = g.check("send_webhook", {"url": "https://example.com"})
            assert result.is_safe is True
        result = g.check("send_webhook", {"url": "https://example.com"})
        assert result.is_safe is False
        assert "Rate limit" in result.blocked_reason

    def test_subdomain_matches_allowlist(self):
        g = self._guards()
        result = g.check("http_post_tool", {"url": "https://v2.api.mycompany.com/data"})
        assert result.is_safe is True

    def test_post_context_by_tool_name(self):
        """Tool named 'send_*' or 'upload_*' → POST guardrail."""
        g = ToolSpecificGuards(_make_config(http_post=_HTTP_POST_CFG))
        result = g.check("send_notification", {"url": "https://evil.com/hook"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason


# ---------------------------------------------------------------
# HTTP GET guardrail
# ---------------------------------------------------------------

class TestHttpGetGuardrail:

    def _guards(self, **overrides):
        cfg = {**_HTTP_GET_CFG, **overrides}
        return ToolSpecificGuards(_make_config(http_get=cfg))

    def test_allowed_domain_passes(self):
        g = self._guards()
        result = g.check("fetch_page", {"url": "https://wikipedia.org/wiki/Python"})
        assert result.is_safe is True

    def test_blocked_domain(self):
        g = self._guards()
        result = g.check("fetch_page", {"url": "https://evil.com/data"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_metadata_service_169_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("fetch_page", {"url": "http://169.254.169.254/latest/meta-data/"})
        assert result.is_safe is False
        assert "metadata service" in result.blocked_reason.lower()

    def test_metadata_google_internal_blocked(self):
        g = self._guards(mode="unrestricted")
        result = g.check("fetch_page", {"url": "http://metadata.google.internal/computeMetadata/v1/"})
        assert result.is_safe is False
        assert "metadata service" in result.blocked_reason.lower()

    def test_metadata_blocking_disabled(self):
        g = self._guards(mode="unrestricted", block_metadata_services=False)
        result = g.check("fetch_page", {"url": "http://169.254.169.254/latest/meta-data/"})
        assert result.is_safe is True


# ---------------------------------------------------------------
# SQL Query guardrail
# ---------------------------------------------------------------

class TestSqlQueryGuardrail:

    def _guards(self, **overrides):
        cfg = {**_SQL_CFG, **overrides}
        return ToolSpecificGuards(_make_config(sql_query=cfg))

    def test_select_allowed(self):
        g = self._guards()
        result = g.check("db_select", {"query": "SELECT * FROM users WHERE id = 1"})
        assert result.is_safe is True

    def test_drop_blocked(self):
        g = self._guards()
        result = g.check("db_select", {"query": "DROP TABLE users"})
        assert result.is_safe is False
        assert "DROP" in result.blocked_reason

    def test_delete_blocked(self):
        g = self._guards()
        result = g.check("db_query", {"query": "DELETE FROM users WHERE id = 1"})
        assert result.is_safe is False
        assert "DELETE" in result.blocked_reason

    def test_update_blocked(self):
        g = self._guards()
        result = g.check("db_query", {"query": "UPDATE users SET admin = 1"})
        assert result.is_safe is False
        assert "UPDATE" in result.blocked_reason

    def test_insert_not_in_allowlist(self):
        g = self._guards()
        result = g.check("db_query", {"query": "INSERT INTO users VALUES (1, 'test')"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_drop_in_subquery(self):
        g = self._guards()
        result = g.check("db_query", {"query": "SELECT * FROM users; DROP TABLE users"})
        assert result.is_safe is False
        assert "DROP" in result.blocked_reason

    def test_case_insensitive(self):
        g = self._guards()
        result = g.check("db_query", {"query": "select * from users"})
        assert result.is_safe is True

    def test_empty_query_passes(self):
        g = self._guards()
        result = g.check("db_query", {"query": ""})
        assert result.is_safe is True


# ---------------------------------------------------------------
# File System guardrail
# ---------------------------------------------------------------

class TestFileSystemGuardrail:

    def _guards(self, **overrides):
        cfg = {**_FS_CFG, **overrides}
        return ToolSpecificGuards(_make_config(file_system=cfg))

    def test_allowed_path_passes(self):
        g = self._guards()
        result = g.check("fs_read_file", {"file_path": "/tmp/report.txt"})
        assert result.is_safe is True

    def test_path_outside_allowlist(self):
        g = self._guards()
        result = g.check("fs_read_file", {"file_path": "/etc/passwd"})
        assert result.is_safe is False
        assert "not in allowlist" in result.blocked_reason

    def test_path_traversal_detected(self):
        g = self._guards()
        result = g.check("fs_read_file", {"file_path": "/tmp/../etc/passwd"})
        assert result.is_safe is False
        assert "traversal" in result.blocked_reason.lower()

    def test_denied_extension_env(self):
        g = self._guards()
        result = g.check("fs_read_file", {"file_path": "/tmp/secrets.env"})
        assert result.is_safe is False
        assert ".env" in result.blocked_reason

    def test_denied_extension_pem(self):
        g = self._guards()
        result = g.check("fs_write_file", {"file_path": "/tmp/server.pem"})
        assert result.is_safe is False
        assert ".pem" in result.blocked_reason

    def test_denied_extension_key(self):
        g = self._guards()
        result = g.check("any_tool", {"file_path": "/app/safe_data/private.key"})
        assert result.is_safe is False
        assert ".key" in result.blocked_reason

    def test_safe_extension_passes(self):
        g = self._guards()
        result = g.check("any_tool", {"file_path": "/app/safe_data/config.json"})
        assert result.is_safe is True

    def test_empty_path_passes(self):
        g = self._guards()
        result = g.check("any_tool", {"file_path": ""})
        assert result.is_safe is True

    def test_path_param_alias(self):
        """file_system guardrail should detect paths in any arg name."""
        g = self._guards()
        result = g.check("any_tool", {"path": "/etc/shadow"})
        assert result.is_safe is False


# ---------------------------------------------------------------
# False positive resistance (critical for LLM contexts)
# ---------------------------------------------------------------

class TestFalsePositiveResistance:
    """Ensure English text and non-SQL/non-path strings don't trigger guardrails."""

    def _all_guards(self):
        return ToolSpecificGuards(_make_config(
            file_system=_FS_CFG, sql_query=_SQL_CFG,
            http_get=_HTTP_GET_CFG, http_post=_HTTP_POST_CFG,
        ))

    def test_english_update_not_sql(self):
        """'UPDATE: meeting canceled' is English, not SQL."""
        g = self._all_guards()
        result = g.check("send_message", {"body": "UPDATE: meeting canceled. DROP by my office."})
        assert result.is_safe is True

    def test_english_select_not_sql(self):
        """'SELECT the best option' is English, not SQL."""
        g = self._all_guards()
        result = g.check("send_message", {"body": "SELECT the best option for dinner"})
        assert result.is_safe is True

    def test_english_delete_not_sql(self):
        """'DELETE this email please' is English, not SQL."""
        g = self._all_guards()
        result = g.check("send_message", {"body": "DELETE this email please"})
        assert result.is_safe is True

    def test_date_not_path(self):
        """'2024/05/12' is a date, not a path."""
        g = self._all_guards()
        result = g.check("log_event", {"date": "2024/05/12"})
        assert result.is_safe is True

    def test_fraction_not_path(self):
        """'3/4' is a fraction, not a path."""
        g = self._all_guards()
        result = g.check("calculate", {"ratio": "3/4"})
        assert result.is_safe is True

    def test_json_arg_not_post(self):
        """Tool with 'json' arg name should NOT be classified as POST."""
        g = ToolSpecificGuards(_make_config(http_get=_HTTP_GET_CFG))
        # analyze_json_data is not a POST tool, URL should use GET guardrail
        result = g.check("analyze_json_data", {"url": "https://wikipedia.org/data"})
        assert result.is_safe is True

    def test_plain_text_no_trigger(self):
        """Plain text with no paths, URLs, or SQL."""
        g = self._all_guards()
        result = g.check("memory_store", {"key": "hello", "value": "world"})
        assert result.is_safe is True


# ---------------------------------------------------------------
# Evasion resistance
# ---------------------------------------------------------------

class TestEvasionResistance:
    """Ensure comment-based and multi-line SQL evasion is caught."""

    def _guards(self):
        return ToolSpecificGuards(_make_config(sql_query=_SQL_CFG))

    def test_sql_comment_evasion(self):
        """'-- evil\\nDROP TABLE users' should be caught by sqlparse."""
        g = self._guards()
        result = g.check("db_run", {"query": "-- evil\nDROP TABLE users"})
        assert result.is_safe is False

    def test_sql_block_comment_evasion(self):
        """'/* exec */ DROP TABLE users' should be caught by sqlparse."""
        g = self._guards()
        result = g.check("db_run", {"query": "/* exec */ DROP TABLE users"})
        assert result.is_safe is False

    def test_path_traversal_evasion(self):
        """'../../../etc/passwd' path traversal always caught."""
        g = ToolSpecificGuards(_make_config(file_system=_FS_CFG))
        result = g.check("any_tool", {"input": "../../../etc/passwd"})
        assert result.is_safe is False
        assert "traversal" in result.blocked_reason.lower()


# ---------------------------------------------------------------
# Policy enforcement: disabled tools + default_policy
# ---------------------------------------------------------------

class TestPolicyEnforcement:

    def test_disabled_tool_blocked(self):
        """Tool with enabled: false → blocked with reason."""
        g = ToolSpecificGuards(_make_config(
            tools={"fs_delete_file": {"enabled": False, "reason": "Irreversible"}}
        ))
        result = g.check("fs_delete_file", {"path": "/tmp/file.txt"})
        assert result.is_safe is False
        assert "Irreversible" in result.blocked_reason

    def test_disabled_tool_default_reason(self):
        """Tool with enabled: false but no reason → generic message."""
        g = ToolSpecificGuards(_make_config(
            tools={"dangerous_tool": {"enabled": False}}
        ))
        result = g.check("dangerous_tool", {"arg": "value"})
        assert result.is_safe is False
        assert "disabled" in result.blocked_reason.lower()

    def test_default_policy_deny_blocks_unknown(self):
        """Unknown tool blocked when default_policy is 'deny'."""
        g = ToolSpecificGuards(_make_config(default_policy="deny"))
        result = g.check("unknown_tool", {"arg": "value"})
        assert result.is_safe is False
        assert "default_policy" in result.blocked_reason

    def test_default_policy_allow_passes_unknown(self):
        """Unknown tool allowed when default_policy is 'allow' (default)."""
        g = ToolSpecificGuards(_make_config(default_policy="allow"))
        result = g.check("unknown_tool", {"arg": "value"})
        assert result.is_safe is True

    def test_enabled_tool_not_blocked(self):
        """Tool with enabled: true in tools: section → not blocked by policy."""
        g = ToolSpecificGuards(_make_config(
            tools={"safe_tool": {"enabled": True}},
            default_policy="deny",
        ))
        result = g.check("safe_tool", {"arg": "value"})
        assert result.is_safe is True
