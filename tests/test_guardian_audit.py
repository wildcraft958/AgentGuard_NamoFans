"""Tests that Guardian logs BOTH passing and blocked events to the audit log."""
from agentguard.guardian import Guardian


_MINIMAL_CONFIG = """\
mode: enforce
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
  image_filters:
    enabled: false
output_security:
  toxicity_detection:
    enabled: false
  pii_detection:
    enabled: false
tool_security:
  melon:
    enabled: false
l4:
  enabled: false
audit:
  enabled: true
  db_path: ":memory:"
observability:
  export_to: []
"""


def _make_guardian(tmp_path) -> Guardian:
    config_path = tmp_path / "agentguard.yaml"
    config_path.write_text(_MINIMAL_CONFIG)
    return Guardian(str(config_path))


def test_validate_input_pass_writes_safe_audit_record(tmp_path):
    g = _make_guardian(tmp_path)
    result = g.validate_input("hello world")
    assert result.is_safe

    rows = g._audit._conn.execute(
        "SELECT action, layer, safe FROM audit_log"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "validate_input"
    assert rows[0][1] == "l1_input"
    assert rows[0][2] == 1  # safe=True


def test_validate_output_pass_writes_safe_audit_record(tmp_path):
    g = _make_guardian(tmp_path)
    result = g.validate_output("Here is your answer.")
    assert result.is_safe

    rows = g._audit._conn.execute(
        "SELECT action, layer, safe FROM audit_log"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "validate_output"
    assert rows[0][1] == "l2_output"
    assert rows[0][2] == 1


def test_validate_tool_call_pass_writes_safe_audit_record(tmp_path):
    g = _make_guardian(tmp_path)
    result = g.validate_tool_call("get_weather", {"city": "London"})
    assert result.is_safe

    rows = g._audit._conn.execute(
        "SELECT action, layer, safe FROM audit_log"
    ).fetchall()
    assert len(rows) == 1
    assert rows[0][0] == "validate_tool_call"
    assert rows[0][1] == "tool_firewall"
    assert rows[0][2] == 1


def test_pass_rate_24h_reflects_passing_events(tmp_path):
    g = _make_guardian(tmp_path)
    g.validate_input("hello")
    g.validate_output("response")
    g.validate_tool_call("some_tool", {})

    pass_rate = g._audit.pass_rate(since_hours=24)
    assert pass_rate == 1.0
