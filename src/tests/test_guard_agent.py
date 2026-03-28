"""Tests for @guard_agent decorator and _AGENT_REGISTRY."""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from agentguard.decorators import _AGENT_REGISTRY, _guardian_cache
from agentguard.exceptions import InputBlockedError
from agentguard.models import InputValidationResult


# ---------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------


@pytest.fixture(autouse=True)
def clear_state():
    """Clear registry and guardian cache before each test."""
    _AGENT_REGISTRY.clear()
    _guardian_cache.clear()
    yield
    _AGENT_REGISTRY.clear()
    _guardian_cache.clear()


def _mock_guardian_safe():
    mock = MagicMock()
    mock.validate_input.return_value = InputValidationResult(is_safe=True, results=[])
    mock.validate_output.return_value = MagicMock(redacted_output=None)
    # Async variants
    mock.avalidate_input = AsyncMock(return_value=InputValidationResult(is_safe=True, results=[]))
    mock.avalidate_output = AsyncMock(return_value=MagicMock(redacted_output=None))
    return mock


def _mock_guardian_blocked():
    mock = MagicMock()
    mock.validate_input.side_effect = InputBlockedError(reason="Injection detected")
    mock.avalidate_input = AsyncMock(side_effect=InputBlockedError(reason="Injection detected"))
    return mock


# ---------------------------------------------------------------
# TestAgentRegistry
# ---------------------------------------------------------------


class TestAgentRegistry:
    def test_registry_starts_empty(self):
        from agentguard.decorators import _AGENT_REGISTRY

        assert len(_AGENT_REGISTRY) == 0

    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_registers_function(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent, _AGENT_REGISTRY

        @guard_agent(agent_name="TestBot")
        def my_agent(msg: str) -> str:
            return f"reply: {msg}"

        assert "TestBot" in _AGENT_REGISTRY

    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_stores_config_path(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent, _AGENT_REGISTRY

        @guard_agent(agent_name="BotA", config="my_config.yaml")
        def my_agent(msg: str) -> str:
            return msg

        _func, config_path, _param, _output = _AGENT_REGISTRY["BotA"]
        assert config_path == "my_config.yaml"

    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_stores_param_and_output_field(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent, _AGENT_REGISTRY

        @guard_agent(agent_name="BotB", param="message", output_field="response")
        def my_agent(message: str) -> dict:
            return {"response": message}

        _func, _config, param, output_field = _AGENT_REGISTRY["BotB"]
        assert param == "message"
        assert output_field == "response"

    @patch("agentguard.decorators._get_guardian")
    def test_get_registered_agent_returns_tuple(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent, get_registered_agent

        @guard_agent(agent_name="BotC")
        def my_agent(msg: str) -> str:
            return msg

        result = get_registered_agent("BotC")
        assert result is not None
        assert isinstance(result, tuple)
        assert len(result) == 4

    def test_get_registered_agent_unknown_returns_none(self):
        from agentguard.decorators import get_registered_agent

        assert get_registered_agent("NonExistent") is None

    @patch("agentguard.decorators._get_guardian")
    def test_multiple_agents_registered(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent, _AGENT_REGISTRY

        @guard_agent(agent_name="Alpha")
        def alpha(msg: str) -> str:
            return msg

        @guard_agent(agent_name="Beta")
        def beta(msg: str) -> str:
            return msg

        assert "Alpha" in _AGENT_REGISTRY
        assert "Beta" in _AGENT_REGISTRY


# ---------------------------------------------------------------
# TestGuardAgentDecorator
# ---------------------------------------------------------------


class TestGuardAgentDecorator:
    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_applies_guard_security(self, mock_get):
        mock = _mock_guardian_safe()
        mock_get.return_value = mock
        from agentguard.decorators import guard_agent

        @guard_agent(agent_name="SafeBot", param="msg")
        def my_agent(msg: str) -> str:
            return f"ok: {msg}"

        result = my_agent(msg="hello")
        assert result == "ok: hello"
        mock.avalidate_input.assert_called_once()

    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_blocks_unsafe_input(self, mock_get):
        mock_get.return_value = _mock_guardian_blocked()
        from agentguard.decorators import guard_agent

        @guard_agent(agent_name="BlockBot", param="msg")
        def my_agent(msg: str) -> str:
            return msg

        with pytest.raises(InputBlockedError):
            my_agent(msg="DROP TABLE users")

    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_preserves_function_metadata(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent

        @guard_agent(agent_name="MetaBot")
        def documented_agent(msg: str) -> str:
            """This is my agent docstring."""
            return msg

        assert documented_agent.__name__ == "documented_agent"
        assert documented_agent.__doc__ == "This is my agent docstring."

    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_works_with_async(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent

        @guard_agent(agent_name="AsyncBot", param="msg")
        async def async_agent(msg: str) -> str:
            return f"async: {msg}"

        result = asyncio.run(async_agent(msg="hi"))
        assert result == "async: hi"

    @patch("agentguard.decorators._get_guardian")
    def test_guard_agent_default_agent_name(self, mock_get):
        mock_get.return_value = _mock_guardian_safe()
        from agentguard.decorators import guard_agent, _AGENT_REGISTRY

        @guard_agent()
        def default_named(msg: str) -> str:
            return msg

        assert "default" in _AGENT_REGISTRY
