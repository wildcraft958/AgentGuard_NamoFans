"""Tests for agentguard.owasp_scanner — OWASPScanResult, _build_callback, scan_agent."""

import os
import pytest
from unittest.mock import MagicMock, patch


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_vulnerability_result(vulnerability="LLM01", passing=8, failing=2):
    r = MagicMock()
    r.vulnerability = vulnerability
    r.vulnerability_type = MagicMock(value="Prompt Injection")
    r.passing = passing
    r.failing = failing
    total = passing + failing
    r.pass_rate = (passing / total) if total > 0 else 0.0
    return r


def _make_assessment(vuln_results=None):
    """Build a fake DeepTeam RiskAssessment."""
    if vuln_results is None:
        vuln_results = [_make_vulnerability_result()]
    assessment = MagicMock()
    assessment.overview.vulnerability_type_results = vuln_results
    assessment.overview.errored = 0
    assessment.overview.run_duration = 3.5
    return assessment


# ---------------------------------------------------------------------------
# OWASPScanResult
# ---------------------------------------------------------------------------


class TestOWASPScanResult:
    def test_overall_pass_rate_both(self):
        from agentguard.owasp_scanner import OWASPScanResult

        llm = _make_assessment([_make_vulnerability_result(passing=8, failing=2)])
        agentic = _make_assessment([_make_vulnerability_result(passing=6, failing=4)])
        result = OWASPScanResult(llm_assessment=llm, agentic_assessment=agentic)

        # (8+6) / (10+10) = 0.70
        assert abs(result.overall_pass_rate - 0.70) < 0.001

    def test_overall_pass_rate_llm_only(self):
        from agentguard.owasp_scanner import OWASPScanResult

        llm = _make_assessment([_make_vulnerability_result(passing=9, failing=1)])
        result = OWASPScanResult(llm_assessment=llm, agentic_assessment=None)

        assert abs(result.overall_pass_rate - 0.90) < 0.001

    def test_overall_pass_rate_agentic_only(self):
        from agentguard.owasp_scanner import OWASPScanResult

        agentic = _make_assessment([_make_vulnerability_result(passing=5, failing=5)])
        result = OWASPScanResult(llm_assessment=None, agentic_assessment=agentic)

        assert abs(result.overall_pass_rate - 0.50) < 0.001

    def test_overall_pass_rate_no_assessments(self):
        from agentguard.owasp_scanner import OWASPScanResult

        result = OWASPScanResult()
        assert result.overall_pass_rate == 0.0

    def test_overall_pass_rate_zero_tests(self):
        from agentguard.owasp_scanner import OWASPScanResult

        assessment = _make_assessment([_make_vulnerability_result(passing=0, failing=0)])
        result = OWASPScanResult(llm_assessment=assessment)
        assert result.overall_pass_rate == 0.0

    def test_repr_contains_pass_rate(self):
        from agentguard.owasp_scanner import OWASPScanResult

        result = OWASPScanResult()
        r = repr(result)
        assert "OWASPScanResult" in r
        assert "overall_pass_rate" in r

    def test_repr_shows_llm_yes(self):
        from agentguard.owasp_scanner import OWASPScanResult

        result = OWASPScanResult(llm_assessment=_make_assessment(), agentic_assessment=None)
        assert "llm=yes" in repr(result)
        assert "agentic=no" in repr(result)

    def test_aggregates_multiple_vuln_results(self):
        from agentguard.owasp_scanner import OWASPScanResult

        vulns = [
            _make_vulnerability_result(passing=10, failing=0),
            _make_vulnerability_result(passing=5, failing=5),
        ]
        result = OWASPScanResult(llm_assessment=_make_assessment(vulns))
        # (10+5)/(10+10) = 15/20 = 0.75
        assert abs(result.overall_pass_rate - 0.75) < 0.001


# ---------------------------------------------------------------------------
# _build_callback
# ---------------------------------------------------------------------------


class TestBuildCallback:
    def test_returns_rtturn_with_response(self):
        from agentguard.owasp_scanner import _build_callback

        agent = lambda p: "safe response"  # noqa: E731
        cb = _build_callback(agent)

        try:
            from deepteam.test_case import RTTurn

            result = cb("hello")
            assert isinstance(result, RTTurn)
            assert result.role == "assistant"
            assert result.content == "safe response"
        except ImportError:
            pytest.skip("deepteam not installed")

    def test_catches_agent_exception(self):
        from agentguard.owasp_scanner import _build_callback

        def failing_agent(p):
            raise ValueError("agent crashed")

        cb = _build_callback(failing_agent)
        try:
            from deepteam.test_case import RTTurn

            result = cb("probe")
            assert isinstance(result, RTTurn)
            assert "agent error" in result.content
            assert "agent crashed" in result.content
        except ImportError:
            pytest.skip("deepteam not installed")

    def test_callback_passes_prompt_to_agent(self):
        from agentguard.owasp_scanner import _build_callback

        received = []

        def recording_agent(prompt):
            received.append(prompt)
            return "ok"

        cb = _build_callback(recording_agent)
        try:
            cb("my test prompt")
            assert received == ["my test prompt"]
        except Exception:
            # If RTTurn import fails, we still verify prompt was passed
            assert received == ["my test prompt"]


# ---------------------------------------------------------------------------
# scan_agent — validation
# ---------------------------------------------------------------------------


class TestScanAgentValidation:
    def test_raises_type_error_for_non_callable(self):
        from agentguard.owasp_scanner import scan_agent

        with pytest.raises(TypeError, match="callable agent"):
            scan_agent("not a function")  # type: ignore[arg-type]

    def test_raises_type_error_for_int(self):
        from agentguard.owasp_scanner import scan_agent

        with pytest.raises(TypeError):
            scan_agent(42)  # type: ignore[arg-type]

    def test_raises_value_error_for_invalid_target(self):
        from agentguard.owasp_scanner import scan_agent

        with pytest.raises(ValueError, match="Invalid target"):
            scan_agent(lambda p: p, target="invalid")  # type: ignore[arg-type]

    def test_raises_value_error_for_all_target(self):
        from agentguard.owasp_scanner import scan_agent

        with pytest.raises(ValueError, match="Invalid target"):
            scan_agent(lambda p: p, target="all")  # type: ignore[arg-type]

    def test_raises_environment_error_when_no_api_key(self, monkeypatch):
        from agentguard.owasp_scanner import scan_agent

        monkeypatch.delenv("OPENAI_API_KEY", raising=False)

        with pytest.raises(EnvironmentError, match="OPENAI_API_KEY"):
            scan_agent(lambda p: p)


# ---------------------------------------------------------------------------
# scan_agent — integration with mocked DeepTeam
# ---------------------------------------------------------------------------


class TestScanAgentWithMockedDeepTeam:
    def setup_method(self):
        os.environ.setdefault("OPENAI_API_KEY", "sk-test-key")

    def _make_mock_teamer(self, assessment):
        teamer = MagicMock()
        teamer.red_team.return_value = assessment
        return teamer

    @patch("agentguard.owasp_scanner._print_header")
    @patch("agentguard.owasp_scanner._print_framework_results")
    @patch("agentguard.owasp_scanner._build_callback")
    def test_llm_target_calls_owasp_top10(self, mock_cb, mock_print_fw, mock_print_hdr):
        from agentguard.owasp_scanner import scan_agent

        assessment = _make_assessment()
        mock_teamer = self._make_mock_teamer(assessment)
        mock_cb.return_value = MagicMock()

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("deepteam.red_teamer.RedTeamer", return_value=mock_teamer):
                with patch("deepteam.frameworks.OWASPTop10", return_value=MagicMock()):
                    with patch("deepteam.frameworks.OWASP_ASI_2026", return_value=MagicMock()):
                        result = scan_agent(lambda p: p, target="llms")

        assert result.llm_assessment is assessment
        assert result.agentic_assessment is None
        mock_teamer.red_team.assert_called_once()

    @patch("agentguard.owasp_scanner._print_header")
    @patch("agentguard.owasp_scanner._print_framework_results")
    @patch("agentguard.owasp_scanner._build_callback")
    def test_agentic_target_calls_owasp_asi(self, mock_cb, mock_print_fw, mock_print_hdr):
        from agentguard.owasp_scanner import scan_agent

        assessment = _make_assessment()
        mock_teamer = self._make_mock_teamer(assessment)
        mock_cb.return_value = MagicMock()

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("deepteam.red_teamer.RedTeamer", return_value=mock_teamer):
                with patch("deepteam.frameworks.OWASPTop10", return_value=MagicMock()):
                    with patch("deepteam.frameworks.OWASP_ASI_2026", return_value=MagicMock()):
                        result = scan_agent(lambda p: p, target="agentic")

        assert result.agentic_assessment is assessment
        assert result.llm_assessment is None
        mock_teamer.red_team.assert_called_once()

    @patch("agentguard.owasp_scanner._print_header")
    @patch("agentguard.owasp_scanner._print_framework_results")
    @patch("agentguard.owasp_scanner._build_callback")
    def test_both_target_calls_both_frameworks(self, mock_cb, mock_print_fw, mock_print_hdr):
        from agentguard.owasp_scanner import scan_agent

        llm_assessment = _make_assessment([_make_vulnerability_result(passing=8, failing=2)])
        agentic_assessment = _make_assessment([_make_vulnerability_result(passing=6, failing=4)])

        mock_teamer = MagicMock()
        mock_teamer.red_team.side_effect = [llm_assessment, agentic_assessment]
        mock_cb.return_value = MagicMock()

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("deepteam.red_teamer.RedTeamer", return_value=mock_teamer):
                with patch("deepteam.frameworks.OWASPTop10", return_value=MagicMock()):
                    with patch("deepteam.frameworks.OWASP_ASI_2026", return_value=MagicMock()):
                        result = scan_agent(lambda p: p, target="both")

        assert result.llm_assessment is llm_assessment
        assert result.agentic_assessment is agentic_assessment
        assert mock_teamer.red_team.call_count == 2

    @patch("agentguard.owasp_scanner._print_header")
    @patch("agentguard.owasp_scanner._print_framework_results")
    @patch("agentguard.owasp_scanner._build_callback")
    def test_returns_owaspscanresult_instance(self, mock_cb, mock_print_fw, mock_print_hdr):
        from agentguard.owasp_scanner import scan_agent, OWASPScanResult

        assessment = _make_assessment()
        mock_teamer = self._make_mock_teamer(assessment)
        mock_cb.return_value = MagicMock()

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("deepteam.red_teamer.RedTeamer", return_value=mock_teamer):
                with patch("deepteam.frameworks.OWASPTop10", return_value=MagicMock()):
                    with patch("deepteam.frameworks.OWASP_ASI_2026", return_value=MagicMock()):
                        result = scan_agent(lambda p: p, target="llms")

        assert isinstance(result, OWASPScanResult)

    @patch("agentguard.owasp_scanner._print_header")
    @patch("agentguard.owasp_scanner._print_framework_results")
    @patch("agentguard.owasp_scanner._build_callback")
    def test_passes_target_purpose_to_red_team(self, mock_cb, mock_print_fw, mock_print_hdr):
        from agentguard.owasp_scanner import scan_agent

        mock_teamer = self._make_mock_teamer(_make_assessment())
        mock_cb.return_value = MagicMock()

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("deepteam.red_teamer.RedTeamer", return_value=mock_teamer):
                with patch("deepteam.frameworks.OWASPTop10", return_value=MagicMock()):
                    with patch("deepteam.frameworks.OWASP_ASI_2026", return_value=MagicMock()):
                        scan_agent(
                            lambda p: p,
                            target="llms",
                            target_purpose="A DevOps assistant",
                        )

        call_kwargs = mock_teamer.red_team.call_args.kwargs
        assert call_kwargs["target_purpose"] == "A DevOps assistant"

    @patch("agentguard.owasp_scanner._print_header")
    @patch("agentguard.owasp_scanner._print_framework_results")
    @patch("agentguard.owasp_scanner._build_callback")
    def test_scan_errors_handled_gracefully(self, mock_cb, mock_print_fw, mock_print_hdr, capsys):
        from agentguard.owasp_scanner import scan_agent

        mock_teamer = MagicMock()
        mock_teamer.red_team.side_effect = RuntimeError("network timeout")
        mock_cb.return_value = MagicMock()

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("deepteam.red_teamer.RedTeamer", return_value=mock_teamer):
                with patch("deepteam.frameworks.OWASPTop10", return_value=MagicMock()):
                    with patch("deepteam.frameworks.OWASP_ASI_2026", return_value=MagicMock()):
                        # Should NOT raise; error is caught internally
                        result = scan_agent(lambda p: p, target="llms")

        assert result.llm_assessment is None
        assert result.overall_pass_rate == 0.0


# ---------------------------------------------------------------------------
# Formatting helpers (smoke tests — no assertions on colour codes)
# ---------------------------------------------------------------------------


class TestFormattingHelpers:
    def test_pass_rate_bar_full(self):
        from agentguard.owasp_scanner import _pass_rate_bar

        bar = _pass_rate_bar(1.0)
        assert "█" in bar

    def test_pass_rate_bar_empty(self):
        from agentguard.owasp_scanner import _pass_rate_bar

        bar = _pass_rate_bar(0.0)
        assert "░" in bar

    def test_severity_label_low(self):
        from agentguard.owasp_scanner import _severity_label

        assert "LOW" in _severity_label(0.9)

    def test_severity_label_medium(self):
        from agentguard.owasp_scanner import _severity_label

        assert "MEDIUM" in _severity_label(0.6)

    def test_severity_label_high(self):
        from agentguard.owasp_scanner import _severity_label

        assert "HIGH" in _severity_label(0.3)

    def test_overall_badge_good(self):
        from agentguard.owasp_scanner import _overall_badge

        assert "GOOD" in _overall_badge(0.9)

    def test_overall_badge_fair(self):
        from agentguard.owasp_scanner import _overall_badge

        assert "FAIR" in _overall_badge(0.6)

    def test_overall_badge_poor(self):
        from agentguard.owasp_scanner import _overall_badge

        assert "POOR" in _overall_badge(0.2)
