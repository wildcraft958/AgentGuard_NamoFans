"""
Tests for agentguard.audit_log.AuditLog
"""

import pytest
from agentguard.audit_log import AuditLog, hash_params


# ---------------------------------------------------------------------------
# Fixture: in-memory database for isolation
# ---------------------------------------------------------------------------

@pytest.fixture
def log():
    with AuditLog(":memory:") as audit:
        yield audit


# ---------------------------------------------------------------------------
# Database initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_table(self, log):
        rows = log._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        ).fetchall()
        assert len(rows) == 1

    def test_creates_indexes(self, log):
        idx_rows = log._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'"
        ).fetchall()
        names = {r[0] for r in idx_rows}
        assert "idx_audit_ts" in names
        assert "idx_audit_action" in names

    def test_empty_on_start(self, log):
        assert log.recent() == []


# ---------------------------------------------------------------------------
# record()
# ---------------------------------------------------------------------------

class TestRecord:
    def test_record_blocked(self, log):
        row_id = log.record("validate_input", "l1_input", is_safe=False, reason="Injection")
        assert isinstance(row_id, int)
        assert row_id > 0

    def test_record_allowed(self, log):
        row_id = log.record("validate_output", "l2_output", is_safe=True)
        assert row_id > 0

    def test_record_with_metadata(self, log):
        log.record(
            "validate_tool_call", "tool_firewall", is_safe=False,
            reason="Domain blocked",
            metadata={"blocked_by": "http_post", "tool_name": "web_post"},
        )
        rows = log.recent(1)
        assert rows[0]["metadata"] is not None
        assert "blocked_by" in rows[0]["metadata"]

    def test_record_persists(self, log):
        log.record("validate_input", "l1_input", is_safe=False, reason="Test")
        rows = log.recent(10)
        assert len(rows) == 1
        assert rows[0]["action"] == "validate_input"
        assert rows[0]["layer"] == "l1_input"
        assert rows[0]["safe"] == 0
        assert rows[0]["reason"] == "Test"

    def test_record_safe_flag(self, log):
        log.record("validate_input", "l1_input", is_safe=True)
        rows = log.recent(1)
        assert rows[0]["safe"] == 1


# ---------------------------------------------------------------------------
# recent()
# ---------------------------------------------------------------------------

class TestRecent:
    def test_returns_newest_first(self, log):
        log.record("validate_input", "l1_input", is_safe=False, reason="First")
        log.record("validate_input", "l1_input", is_safe=False, reason="Second")
        rows = log.recent(2)
        assert rows[0]["reason"] == "Second"
        assert rows[1]["reason"] == "First"

    def test_limit_respected(self, log):
        for i in range(10):
            log.record("validate_input", "l1_input", is_safe=True)
        rows = log.recent(3)
        assert len(rows) == 3

    def test_returns_list_of_dicts(self, log):
        log.record("validate_input", "l1_input", is_safe=True)
        rows = log.recent()
        assert isinstance(rows, list)
        assert isinstance(rows[0], dict)


# ---------------------------------------------------------------------------
# blocked_count()
# ---------------------------------------------------------------------------

class TestBlockedCount:
    def test_counts_only_blocked(self, log):
        log.record("validate_input", "l1_input", is_safe=False)
        log.record("validate_input", "l1_input", is_safe=False)
        log.record("validate_input", "l1_input", is_safe=True)
        assert log.blocked_count() == 2

    def test_zero_when_all_safe(self, log):
        log.record("validate_input", "l1_input", is_safe=True)
        assert log.blocked_count() == 0

    def test_filter_by_action(self, log):
        log.record("validate_input", "l1_input", is_safe=False)
        log.record("validate_output", "l2_output", is_safe=False)
        assert log.blocked_count("validate_input") == 1
        assert log.blocked_count("validate_output") == 1
        assert log.blocked_count() == 2

    def test_zero_when_empty(self, log):
        assert log.blocked_count() == 0


# ---------------------------------------------------------------------------
# pass_rate()
# ---------------------------------------------------------------------------

class TestPassRate:
    def test_all_safe_returns_one(self, log):
        log.record("validate_input", "l1_input", is_safe=True)
        log.record("validate_input", "l1_input", is_safe=True)
        assert log.pass_rate() == 1.0

    def test_all_blocked_returns_zero(self, log):
        log.record("validate_input", "l1_input", is_safe=False)
        log.record("validate_input", "l1_input", is_safe=False)
        assert log.pass_rate() == 0.0

    def test_mixed(self, log):
        log.record("validate_input", "l1_input", is_safe=True)
        log.record("validate_input", "l1_input", is_safe=False)
        rate = log.pass_rate()
        assert rate == pytest.approx(0.5)

    def test_empty_returns_one(self, log):
        assert log.pass_rate() == 1.0


# ---------------------------------------------------------------------------
# hash_params()
# ---------------------------------------------------------------------------

class TestHashParams:
    def test_returns_string(self):
        h = hash_params({"key": "value"})
        assert isinstance(h, str)

    def test_deterministic(self):
        h1 = hash_params({"a": 1, "b": 2})
        h2 = hash_params({"b": 2, "a": 1})
        assert h1 == h2

    def test_different_inputs_differ(self):
        h1 = hash_params({"a": 1})
        h2 = hash_params({"a": 2})
        assert h1 != h2

    def test_length_16(self):
        h = hash_params({"x": "y"})
        assert len(h) == 16
