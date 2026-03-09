"""
Tests for agentguard.tool_firewall.rule_evaluator.eval_condition
"""

from agentguard.tool_firewall.rule_evaluator import eval_condition


class TestEquals:
    def test_equal_strings(self):
        assert eval_condition("hello", "equals", "hello") is True

    def test_unequal_strings(self):
        assert eval_condition("hello", "equals", "world") is False

    def test_numeric_coercion(self):
        assert eval_condition(42, "equals", "42") is True

    def test_case_sensitive(self):
        assert eval_condition("Hello", "equals", "hello") is False


class TestContains:
    def test_substring_present(self):
        assert eval_condition("/etc/passwd", "contains", "passwd") is True

    def test_substring_absent(self):
        assert eval_condition("/tmp/safe.txt", "contains", "passwd") is False

    def test_case_insensitive(self):
        assert eval_condition("/TMP/FILE.TXT", "contains", "file") is True


class TestNotContains:
    def test_substring_absent(self):
        assert eval_condition("/tmp/safe.txt", "not_contains", "passwd") is True

    def test_substring_present(self):
        assert eval_condition("/etc/passwd", "not_contains", "passwd") is False

    def test_case_insensitive(self):
        assert eval_condition("/TMP/FILE", "not_contains", "file") is False


class TestMatches:
    def test_regex_match(self):
        assert eval_condition("DROP TABLE users", "matches", r"DROP\s+TABLE") is True

    def test_regex_no_match(self):
        assert eval_condition("SELECT * FROM users", "matches", r"DROP\s+TABLE") is False

    def test_case_insensitive(self):
        assert eval_condition("drop table users", "matches", r"DROP\s+TABLE") is True


class TestStartswith:
    def test_prefix_match(self):
        assert eval_condition("/etc/passwd", "startswith", "/etc") is True

    def test_prefix_no_match(self):
        assert eval_condition("/tmp/file", "startswith", "/etc") is False


class TestEndswith:
    def test_suffix_match(self):
        assert eval_condition("config.env", "endswith", ".env") is True

    def test_suffix_no_match(self):
        assert eval_condition("config.yaml", "endswith", ".env") is False


class TestIn:
    def test_value_in_list(self):
        assert eval_condition("SELECT", "in", ["SELECT", "INSERT"]) is True

    def test_value_not_in_list(self):
        assert eval_condition("DROP", "in", ["SELECT", "INSERT"]) is False

    def test_single_value(self):
        assert eval_condition("SELECT", "in", "SELECT") is True

    def test_numeric_coercion(self):
        assert eval_condition(200, "in", ["200", "201"]) is True


class TestNotIn:
    def test_value_not_in_list(self):
        assert eval_condition("DROP", "not_in", ["SELECT", "INSERT"]) is True

    def test_value_in_list(self):
        assert eval_condition("SELECT", "not_in", ["SELECT", "INSERT"]) is False


class TestGt:
    def test_greater(self):
        assert eval_condition(1500, "gt", 1024) is True

    def test_equal_not_greater(self):
        assert eval_condition(1024, "gt", 1024) is False

    def test_less_not_greater(self):
        assert eval_condition(500, "gt", 1024) is False

    def test_string_numeric(self):
        assert eval_condition("2048", "gt", "1024") is True

    def test_non_numeric_returns_false(self):
        assert eval_condition("abc", "gt", 1) is False


class TestLt:
    def test_less(self):
        assert eval_condition(500, "lt", 1024) is True

    def test_equal_not_less(self):
        assert eval_condition(1024, "lt", 1024) is False

    def test_greater_not_less(self):
        assert eval_condition(2048, "lt", 1024) is False

    def test_non_numeric_returns_false(self):
        assert eval_condition("abc", "lt", 1) is False


class TestUnknownOperator:
    def test_unknown_returns_false(self):
        assert eval_condition("anything", "banana", "value") is False

    def test_empty_op_returns_false(self):
        assert eval_condition("anything", "", "value") is False
