"""Tests for agentguard.config module."""

import os
import tempfile
from unittest.mock import patch

import pytest

from agentguard.config import AgentGuardConfig, load_config
from agentguard.exceptions import ConfigurationError
from agentguard.models import GuardMode, Sensitivity


def _make_config(observability: dict | None = None) -> AgentGuardConfig:
    """Build a minimal raw config dict with optional observability section."""
    raw = {
        "global": {"mode": "enforce", "log_level": "standard"},
    }
    if observability is not None:
        raw["observability"] = observability
    return AgentGuardConfig(raw)


def _write_config(content: str) -> str:
    """Write a temp YAML config file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


class TestConfigLoader:
    """Tests for YAML config loading and validation."""

    def test_load_valid_config(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
  fail_safe: block
  max_validation_latency_ms: 200
input_security:
  prompt_shields:
    enabled: true
    sensitivity: high
    block_on_detected_injection: true
  content_filters:
    block_toxicity: true
    block_violence: true
    block_self_harm: true
""")
        config = load_config(path)
        assert config.mode == GuardMode.ENFORCE
        assert config.log_level == "standard"
        assert config.prompt_shields_enabled is True
        assert config.prompt_shields_sensitivity == Sensitivity.HIGH
        assert config.block_on_detected_injection is True
        assert config.content_filters_block_toxicity is True
        assert config.content_filters_block_violence is True
        assert config.content_filters_block_self_harm is True
        os.unlink(path)

    def test_load_monitor_mode(self):
        path = _write_config("""
global:
  mode: monitor
  log_level: minimal
""")
        config = load_config(path)
        assert config.mode == GuardMode.MONITOR
        assert config.log_level == "minimal"
        os.unlink(path)

    def test_load_dry_run_mode(self):
        path = _write_config("""
global:
  mode: dry-run
  log_level: detailed
""")
        config = load_config(path)
        assert config.mode == GuardMode.DRY_RUN
        os.unlink(path)

    def test_invalid_mode_raises(self):
        path = _write_config("""
global:
  mode: invalid_mode
""")
        with pytest.raises(ConfigurationError, match="Invalid global.mode"):
            load_config(path)
        os.unlink(path)

    def test_invalid_log_level_raises(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: verbose
""")
        with pytest.raises(ConfigurationError, match="Invalid global.log_level"):
            load_config(path)
        os.unlink(path)

    def test_missing_file_raises(self):
        with pytest.raises(ConfigurationError, match="Config file not found"):
            load_config("/nonexistent/path/config.yaml")

    def test_defaults_when_sections_missing(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
""")
        config = load_config(path)
        # Should use defaults
        assert config.prompt_shields_enabled is True
        assert config.content_filters_block_toxicity is True
        assert config.spotlighting_enabled is False
        os.unlink(path)

    def test_low_sensitivity(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
input_security:
  prompt_shields:
    enabled: true
    sensitivity: low
""")
        config = load_config(path)
        assert config.prompt_shields_sensitivity == Sensitivity.LOW
        os.unlink(path)


class TestTestingConfig:
    def test_testing_config_returns_dict_when_present(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
testing:
  purpose: "Test agent"
  plugins:
    - prompt-injection
  num_tests: 10
""")
        config = load_config(path)
        assert isinstance(config.testing_config, dict)
        assert config.testing_config["purpose"] == "Test agent"
        assert config.testing_config["num_tests"] == 10
        os.unlink(path)

    def test_testing_config_returns_empty_when_absent(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
""")
        config = load_config(path)
        assert config.testing_config == {}
        os.unlink(path)

    def test_agent_name_returns_value(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
agent_name: "MyBot"
""")
        config = load_config(path)
        assert config.agent_name == "MyBot"
        os.unlink(path)

    def test_agent_name_defaults_to_default(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
""")
        config = load_config(path)
        assert config.agent_name == "default"
        os.unlink(path)


class TestAuditConfig:
    def test_audit_enabled_default_true(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
""")
        config = load_config(path)
        assert config.audit_enabled is True
        os.unlink(path)

    def test_audit_enabled_explicit_false(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
audit:
  enabled: false
""")
        config = load_config(path)
        assert config.audit_enabled is False
        os.unlink(path)

    def test_audit_db_path_default(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
""")
        config = load_config(path)
        assert config.audit_db_path == "~/.agentguard/audit.db"
        os.unlink(path)

    def test_audit_db_path_custom(self):
        path = _write_config("""
global:
  mode: enforce
  log_level: standard
audit:
  enabled: true
  db_path: /tmp/test_audit.db
""")
        config = load_config(path)
        assert config.audit_db_path == "/tmp/test_audit.db"
        os.unlink(path)


class TestTelemetryEnabled:
    def test_telemetry_enabled_when_otel_in_export_to(self):
        cfg = _make_config({"export_to": ["otel"]})
        assert cfg.telemetry_enabled is True

    def test_telemetry_enabled_when_otel_among_multiple_exporters(self):
        cfg = _make_config({"export_to": ["azure_monitor", "otel"]})
        assert cfg.telemetry_enabled is True

    def test_telemetry_disabled_when_otel_not_in_export_to(self):
        cfg = _make_config({"export_to": ["azure_monitor"]})
        assert cfg.telemetry_enabled is False

    def test_telemetry_disabled_when_export_to_empty(self):
        cfg = _make_config({"export_to": []})
        assert cfg.telemetry_enabled is False

    def test_telemetry_disabled_when_no_observability_section(self):
        cfg = _make_config(observability=None)
        assert cfg.telemetry_enabled is False

    def test_telemetry_disabled_when_observability_has_no_export_to(self):
        cfg = _make_config({"log_all_decisions": True})
        assert cfg.telemetry_enabled is False


class TestTelemetryEndpoint:
    def test_endpoint_from_config(self):
        cfg = _make_config({"otel_endpoint": "http://my-collector:4317"})
        assert cfg.telemetry_endpoint == "http://my-collector:4317"

    def test_endpoint_none_when_not_set(self):
        cfg = _make_config({})
        with patch.dict(os.environ, {}, clear=True):
            assert cfg.telemetry_endpoint is None

    def test_endpoint_from_env_var_when_config_is_null(self):
        cfg = _make_config({"otel_endpoint": None})
        with patch.dict(os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://env-collector:4317"}):
            assert cfg.telemetry_endpoint == "http://env-collector:4317"

    def test_config_takes_precedence_over_env(self):
        cfg = _make_config({"otel_endpoint": "http://config-collector:4317"})
        with patch.dict(
            os.environ, {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://env-collector:4317"}
        ):
            assert cfg.telemetry_endpoint == "http://config-collector:4317"


class TestTelemetryServiceName:
    def test_service_name_from_config(self):
        cfg = _make_config({"service_name": "my-agent"})
        assert cfg.telemetry_service_name == "my-agent"

    def test_service_name_defaults_to_agentguard(self):
        cfg = _make_config({})
        assert cfg.telemetry_service_name == "agentguard"

    def test_service_name_default_when_no_observability_section(self):
        cfg = _make_config(observability=None)
        assert cfg.telemetry_service_name == "agentguard"
