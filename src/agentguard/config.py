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

    # ----- Output Security: Toxicity Detection -----

    @property
    def output_toxicity_enabled(self) -> bool:
        return _deep_get(self._raw, "output_security", "toxicity_detection", "enabled", default=False)

    @property
    def output_toxicity_block(self) -> bool:
        return _deep_get(
            self._raw, "output_security", "toxicity_detection",
            "block_on_detected_toxicity", default=True
        )

    # ----- Output Security: PII Detection -----

    @property
    def pii_detection_enabled(self) -> bool:
        return _deep_get(self._raw, "output_security", "pii_detection", "enabled", default=False)

    @property
    def pii_block_on_detection(self) -> bool:
        return _deep_get(
            self._raw, "output_security", "pii_detection",
            "block_on_pii_exfiltration", default=True
        )

    @property
    def pii_allowed_categories(self) -> list:
        return _deep_get(
            self._raw, "output_security", "pii_detection",
            "allowed_categories", default=[]
        )

    # ----- Pattern Detection: Custom Blocklists -----

    @property
    def pattern_detection_enabled(self) -> bool:
        return _deep_get(self._raw, "pattern_detection", "enabled", default=False)

    @property
    def blocklists_config(self) -> list:
        return _deep_get(self._raw, "pattern_detection", "blocklists", default=[])

    @property
    def block_on_blocklist_match(self) -> bool:
        return _deep_get(self._raw, "pattern_detection", "block_on_match", default=True)

    @property
    def halt_on_blocklist_hit(self) -> bool:
        return _deep_get(self._raw, "pattern_detection", "halt_on_blocklist_hit", default=True)

    # ----- Tool Firewall -----

    @property
    def tool_firewall_enabled(self) -> bool:
        """True if any guardrail in tool_firewall config is enabled."""
        tf = self._raw.get("tool_firewall", {})
        if not isinstance(tf, dict):
            return False
        # Check if any of the 4 guardrails are enabled
        guardrails = ["file_system", "sql_query", "http_post", "http_get"]
        for g in guardrails:
            cfg = tf.get(g)
            if isinstance(cfg, dict) and cfg.get("enabled", False):
                return True
        # Also consider enabled if there are disabled tools in tools: section
        tools = self._raw.get("tools", {})
        if isinstance(tools, dict) and tools:
            return True
        # Also enabled if default_policy is deny
        if tf.get("default_policy") == "deny":
            return True
        return False

    def get_tool_config(self, tool_name: str) -> dict:
        """Get the full config dict for a specific tool."""
        return _deep_get(self._raw, "tools", tool_name, default={})

    # ----- Tool Firewall: Input Analysis (C1) -----

    @property
    def tool_input_analysis_enabled(self) -> bool:
        return _deep_get(self._raw, "tool_firewall", "input_analysis", "enabled", default=False)

    @property
    def tool_input_blocked_categories(self) -> dict:
        return _deep_get(
            self._raw, "tool_firewall", "input_analysis",
            "blocked_entity_categories", default={}
        )

    # ----- Tool Firewall: MELON (C2) -----

    @property
    def melon_enabled(self) -> bool:
        return _deep_get(self._raw, "tool_firewall", "melon", "enabled", default=False)

    @property
    def melon_threshold(self) -> float:
        return _deep_get(self._raw, "tool_firewall", "melon", "threshold", default=0.8)

    @property
    def melon_embedding_model(self) -> str:
        return _deep_get(
            self._raw, "tool_firewall", "melon",
            "embedding_model", default="text-embedding-3-large"
        )

    @property
    def melon_raise_on_injection(self) -> bool:
        return _deep_get(self._raw, "tool_firewall", "melon", "raise_on_injection", default=True)

    @property
    def tool_firewall_default_policy(self) -> str:
        return _deep_get(self._raw, "tool_firewall", "default_policy", default="allow")

    @property
    def tool_firewall_file_system_config(self) -> dict:
        return _deep_get(self._raw, "tool_firewall", "file_system", default={})

    @property
    def tool_firewall_sql_query_config(self) -> dict:
        return _deep_get(self._raw, "tool_firewall", "sql_query", default={})

    @property
    def tool_firewall_http_post_config(self) -> dict:
        return _deep_get(self._raw, "tool_firewall", "http_post", default={})

    @property
    def tool_firewall_http_get_config(self) -> dict:
        return _deep_get(self._raw, "tool_firewall", "http_get", default={})


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
