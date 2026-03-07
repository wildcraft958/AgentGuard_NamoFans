"""Tests for agentguard.config module."""

import pytest
import os
import tempfile

from agentguard.config import load_config
from agentguard.exceptions import ConfigurationError
from agentguard.models import GuardMode, Sensitivity


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
