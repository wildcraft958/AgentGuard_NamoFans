"""
AgentGuard configuration loader.

Loads and validates agentguard.yaml configuration.
"""

import yaml
from agentguard.exceptions import ConfigurationError
from agentguard.models import GuardMode, Sensitivity


def _deep_get(d: dict, *keys, default=None):
    """Safely traverse nested dict keys."""
    for key in keys:
        if isinstance(d, dict):
            d = d.get(key, default)
        else:
            return default
    return d


class AgentGuardConfig:
    """Parsed and validated AgentGuard configuration."""

    def __init__(self, raw: dict):
        self._raw = raw
        self._validate()

    def _validate(self):
        """Validate required config sections and values."""
        if not isinstance(self._raw, dict):
            raise ConfigurationError("Config must be a YAML mapping")

        # Validate global section
        global_cfg = self._raw.get("global", {})
        mode_str = global_cfg.get("mode", "enforce")
        try:
            self.mode = GuardMode(mode_str)
        except ValueError:
            raise ConfigurationError(
                f"Invalid global.mode '{mode_str}'. Must be: enforce, monitor, dry-run"
            )

        self.log_level = global_cfg.get("log_level", "standard")
        if self.log_level not in ("minimal", "standard", "detailed"):
            raise ConfigurationError(
                f"Invalid global.log_level '{self.log_level}'. Must be: minimal, standard, detailed"
            )

        self.fail_safe = global_cfg.get("fail_safe", "block")
        self.max_validation_latency_ms = global_cfg.get("max_validation_latency_ms", 200)

    # ----- Input Security: Prompt Shields -----

    @property
    def prompt_shields_enabled(self) -> bool:
        return _deep_get(self._raw, "input_security", "prompt_shields", "enabled", default=True)

    @property
    def prompt_shields_sensitivity(self) -> Sensitivity:
        val = _deep_get(self._raw, "input_security", "prompt_shields", "sensitivity", default="high")
        try:
            return Sensitivity(val)
        except ValueError:
            raise ConfigurationError(f"Invalid prompt_shields.sensitivity '{val}'")

    @property
    def block_on_detected_injection(self) -> bool:
        return _deep_get(
            self._raw, "input_security", "prompt_shields",
            "block_on_detected_injection", default=True
        )

    # ----- Input Security: Content Filters -----

    @property
    def content_filters_block_toxicity(self) -> bool:
        return _deep_get(self._raw, "input_security", "content_filters", "block_toxicity", default=True)

    @property
    def content_filters_block_violence(self) -> bool:
        return _deep_get(self._raw, "input_security", "content_filters", "block_violence", default=True)

    @property
    def content_filters_block_self_harm(self) -> bool:
        return _deep_get(self._raw, "input_security", "content_filters", "block_self_harm", default=True)

    # ----- Input Security: Image Filters -----

    @property
    def image_filters_enabled(self) -> bool:
        return _deep_get(self._raw, "input_security", "image_filters", "enabled", default=False)

    @property
    def image_filters_block_hate(self) -> bool:
        return _deep_get(self._raw, "input_security", "image_filters", "block_hate", default=True)

    @property
    def image_filters_block_violence(self) -> bool:
        return _deep_get(self._raw, "input_security", "image_filters", "block_violence", default=True)

    @property
    def image_filters_block_self_harm(self) -> bool:
        return _deep_get(self._raw, "input_security", "image_filters", "block_self_harm", default=True)

    @property
    def image_filters_block_sexual(self) -> bool:
        return _deep_get(self._raw, "input_security", "image_filters", "block_sexual", default=True)

    # ----- Input Security: Spotlighting -----

    @property
    def spotlighting_enabled(self) -> bool:
        return _deep_get(self._raw, "input_security", "spotlighting", "enabled", default=False)


def load_config(config_path: str) -> AgentGuardConfig:
    """Load and validate an AgentGuard YAML config file.

    Args:
        config_path: Path to the agentguard.yaml file.

    Returns:
        Parsed AgentGuardConfig instance.

    Raises:
        ConfigurationError: If the file is missing or invalid.
    """
    try:
        with open(config_path, "r") as f:
            raw = yaml.safe_load(f)
    except FileNotFoundError:
        raise ConfigurationError(f"Config file not found: {config_path}")
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in config: {e}")

    return AgentGuardConfig(raw)
