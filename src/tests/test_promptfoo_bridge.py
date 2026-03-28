"""Tests for agentguard.promptfoo_bridge Promptfoo provider."""

import textwrap
import pytest

from agentguard.decorators import _AGENT_REGISTRY, _guardian_cache
from agentguard.exceptions import InputBlockedError


# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_state():
    _AGENT_REGISTRY.clear()
    _guardian_cache.clear()
    yield
    _AGENT_REGISTRY.clear()
    _guardian_cache.clear()


def _make_options(agent_module=None, function_name=None, config_path=None, agent_name=None):
    """Build a Promptfoo options dict."""
    opts = {}
    if agent_module:
        opts["AGENTGUARD_AGENT_MODULE"] = agent_module
    if function_name:
        opts["AGENTGUARD_FUNCTION"] = function_name
    if config_path:
        opts["AGENTGUARD_CONFIG"] = config_path
    if agent_name:
        opts["AGENTGUARD_AGENT_NAME"] = agent_name
    return opts


# ---------------------------------------------------------------
# TestCallApi
# ---------------------------------------------------------------


class TestCallApi:
    def test_returns_output_on_success(self):
        """Registry agent returns string output."""
        from agentguard.promptfoo_bridge import call_api

        def my_agent(msg):
            return "hello world"

        _AGENT_REGISTRY["TestAgent"] = (my_agent, "agentguard.yaml", "msg", None)

        result = call_api("hi", _make_options(agent_name="TestAgent"), {})
        assert result == {"output": "hello world"}

    def test_returns_blocked_on_guard_error(self):
        """When agent raises InputBlockedError, bridge returns [BLOCKED] output."""
        from agentguard.promptfoo_bridge import call_api

        def blocked_agent(msg):
            raise InputBlockedError(reason="Injection detected")

        _AGENT_REGISTRY["BlockedAgent"] = (blocked_agent, "agentguard.yaml", "msg", None)

        result = call_api("attack", _make_options(agent_name="BlockedAgent"), {})
        assert "BLOCKED" in result["output"]

    def test_returns_error_when_no_agent_found(self):
        """No registry match and no AGENTGUARD_FUNCTION → error output."""
        from agentguard.promptfoo_bridge import call_api

        result = call_api("test", _make_options(), {})
        assert "output" in result
        assert (
            "error" in result["output"].lower()
            or "BLOCKED" in result["output"]
            or result["output"].startswith("[")
        )

    def test_extracts_output_field_from_dict(self):
        """Agent returns dict; bridge extracts output_field."""
        from agentguard.promptfoo_bridge import call_api

        def dict_agent(msg):
            return {"response": "extracted value", "other": "ignored"}

        _AGENT_REGISTRY["DictAgent"] = (dict_agent, "agentguard.yaml", "msg", "response")

        result = call_api("test", _make_options(agent_name="DictAgent"), {})
        assert result["output"] == "extracted value"

    def test_handles_string_return(self):
        """Agent returns plain string — no output_field needed."""
        from agentguard.promptfoo_bridge import call_api

        def str_agent(msg):
            return "plain string result"

        _AGENT_REGISTRY["StrAgent"] = (str_agent, "agentguard.yaml", "msg", None)

        result = call_api("test", _make_options(agent_name="StrAgent"), {})
        assert result["output"] == "plain string result"

    def test_loads_agent_module_dynamically(self, tmp_path):
        """Bridge can load a .py module file and find function by AGENTGUARD_FUNCTION."""
        module_code = textwrap.dedent("""
            def my_func(prompt):
                return f"dynamic: {prompt}"
        """)
        agent_file = tmp_path / "dynamic_agent.py"
        agent_file.write_text(module_code)

        from agentguard.promptfoo_bridge import call_api

        opts = _make_options(
            agent_module=str(agent_file),
            function_name="my_func",
        )
        result = call_api("hello", opts, {})
        assert result["output"] == "dynamic: hello"

    def test_reads_agent_name_from_config(self, tmp_path):
        """Bridge reads agent_name from AGENTGUARD_CONFIG yaml."""
        config_content = (
            "version: 1\nagent_name: ConfigBot\nglobal:\n  mode: enforce\n  log_level: standard\n"
        )
        config_file = tmp_path / "test_agentguard.yaml"
        config_file.write_text(config_content)

        def config_agent(prompt):
            return "from config"

        _AGENT_REGISTRY["ConfigBot"] = (config_agent, str(config_file), None, None)

        from agentguard.promptfoo_bridge import call_api

        opts = {"AGENTGUARD_CONFIG": str(config_file)}
        result = call_api("test", opts, {})
        assert result["output"] == "from config"

    def test_fallback_to_function_flag(self, tmp_path):
        """No registry match → fall back to AGENTGUARD_FUNCTION in loaded module."""
        module_code = textwrap.dedent("""
            def run(prompt):
                return f"fallback: {prompt}"
        """)
        agent_file = tmp_path / "fallback_agent.py"
        agent_file.write_text(module_code)

        from agentguard.promptfoo_bridge import call_api

        opts = _make_options(agent_module=str(agent_file), function_name="run")
        result = call_api("test input", opts, {})
        assert result["output"] == "fallback: test input"

    def test_calls_unguarded_agent_via_function(self, tmp_path):
        """An unguarded agent called via --function with no @guard_agent."""
        module_code = textwrap.dedent("""
            def run(prompt):
                return "unguarded response"
        """)
        agent_file = tmp_path / "unguarded_agent.py"
        agent_file.write_text(module_code)

        from agentguard.promptfoo_bridge import call_api

        opts = _make_options(agent_module=str(agent_file), function_name="run")
        result = call_api("anything", opts, {})
        assert result["output"] == "unguarded response"

    def test_async_agent_function_resolved(self, tmp_path):
        """Async agent function is awaited; result is not a coroutine."""
        module_code = textwrap.dedent("""
            import asyncio

            async def run(prompt):
                await asyncio.sleep(0)
                return f"async result: {prompt}"
        """)
        agent_file = tmp_path / "async_agent.py"
        agent_file.write_text(module_code)

        from agentguard.promptfoo_bridge import call_api

        opts = _make_options(agent_module=str(agent_file), function_name="run")
        result = call_api("async test", opts, {})
        assert result["output"] == "async result: async test"
        assert "coroutine" not in result["output"]
