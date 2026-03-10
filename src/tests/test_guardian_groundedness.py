"""Tests for Guardian L2 pipeline with groundedness detection.

Integration tests verifying the full L2 orchestration:
ordering (toxicity → PII → groundedness), mode handling,
config integration, audit logging, and OTel spans.
"""

import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from agentguard.exceptions import OutputBlockedError
from agentguard.guardian import Guardian
from agentguard.models import ValidationResult


def _write_config(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w") as f:
        f.write(content)
    return path


# ── Config templates ──────────────────────────────────────────────

ENFORCE_GROUNDEDNESS_CONFIG = """
global:
  mode: enforce
  log_level: minimal
  max_validation_latency_ms: 5000
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
output_security:
  toxicity_detection:
    enabled: true
    block_on_detected_toxicity: true
  pii_detection:
    enabled: true
    block_on_pii_exfiltration: true
  hallucination_detection:
    enabled: true
    block_on_high_confidence: true
    confidence_threshold: 0.8
"""

MONITOR_GROUNDEDNESS_CONFIG = """
global:
  mode: monitor
  log_level: minimal
  max_validation_latency_ms: 5000
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
output_security:
  hallucination_detection:
    enabled: true
    block_on_high_confidence: true
    confidence_threshold: 0.8
"""

DRY_RUN_GROUNDEDNESS_CONFIG = """
global:
  mode: dry-run
  log_level: minimal
output_security:
  hallucination_detection:
    enabled: true
"""

DISABLED_GROUNDEDNESS_CONFIG = """
global:
  mode: enforce
  log_level: minimal
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
output_security:
  hallucination_detection:
    enabled: false
"""

GROUNDEDNESS_ONLY_CONFIG = """
global:
  mode: enforce
  log_level: minimal
  max_validation_latency_ms: 5000
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
output_security:
  hallucination_detection:
    enabled: true
    block_on_high_confidence: true
    confidence_threshold: 0.7
"""

TELEMETRY_GROUNDEDNESS_CONFIG = """
global:
  mode: enforce
  log_level: minimal
  max_validation_latency_ms: 5000
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
output_security:
  hallucination_detection:
    enabled: true
    block_on_high_confidence: true
    confidence_threshold: 0.8
observability:
  export_to:
    - otel
  service_name: agentguard
"""


# ── Helpers ───────────────────────────────────────────────────────

def _safe_result(layer: str) -> ValidationResult:
    return ValidationResult(is_safe=True, layer=layer, details={})


def _unsafe_result(layer: str, reason: str) -> ValidationResult:
    return ValidationResult(
        is_safe=False, layer=layer, blocked_reason=reason, details={}
    )


GROUNDED_RESULT = ValidationResult(
    is_safe=True,
    layer="groundedness_detector",
    details={
        "ungroundedDetected": False,
        "ungroundedPercentage": 0.0,
        "ungroundedDetails": [],
    },
)

UNGROUNDED_RESULT = ValidationResult(
    is_safe=False,
    layer="groundedness_detector",
    blocked_reason="Ungrounded content detected in output (85% ungrounded, threshold: 80%)",
    details={
        "ungroundedDetected": True,
        "ungroundedPercentage": 0.85,
        "ungroundedDetails": [{"text": "hallucinated claim"}],
    },
)


def _make_in_memory_tracer_provider():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return provider, exporter


# ── Orchestration Tests ───────────────────────────────────────────

class TestGroundednessOrchestration:
    """Tests verifying L2 check ordering and mode behavior."""

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    @patch("agentguard.l2_output.pii_detector.PIIDetector.__init__", return_value=None)
    @patch("agentguard.l2_output.pii_detector.PIIDetector.analyze")
    @patch("agentguard.guardian.ContentFilters")
    def test_groundedness_runs_after_toxicity_and_pii(
        self, MockCF, mock_pii_analyze, mock_pii_init, mock_ground_post
    ):
        """All 3 L2 checks should run in order: toxicity → PII → groundedness."""
        # Content filters (used by output toxicity)
        mock_cf = MagicMock()
        mock_cf.analyze_text.return_value = _safe_result("content_filters")
        MockCF.return_value = mock_cf

        # PII: safe
        mock_pii_analyze.return_value = _safe_result("pii_detector")

        # Groundedness: grounded (safe)
        mock_ground_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ungroundedDetected": False,
                "ungroundedPercentage": 0.0,
                "ungroundedDetails": [],
            }),
        )

        path = _write_config(ENFORCE_GROUNDEDNESS_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
            "AZURE_LANGUAGE_ENDPOINT": "https://lang.cognitiveservices.azure.com",
            "AZURE_LANGUAGE_KEY": "test-key",
        }):
            guardian = Guardian(path)
            result = guardian.validate_output(
                "Contoso sells camping gear.",
                user_query="What does Contoso sell?",
                grounding_sources=["Contoso Camping Store sells camping equipment."],
            )

        assert result.is_safe is True
        assert len(result.results) == 3  # toxicity + PII + groundedness
        os.unlink(path)

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    def test_groundedness_blocks_in_enforce_mode(self, mock_post):
        """Ungrounded output should raise OutputBlockedError in enforce mode."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ungroundedDetected": True,
                "ungroundedPercentage": 0.85,
                "ungroundedDetails": [{"text": "hallucinated"}],
            }),
        )

        path = _write_config(GROUNDEDNESS_ONLY_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
        }):
            guardian = Guardian(path)

            with pytest.raises(OutputBlockedError) as exc_info:
                guardian.validate_output(
                    "The store has 500 locations.",
                    user_query="Tell me about Contoso.",
                    grounding_sources=["Contoso has 3 locations."],
                )

        assert "ungrounded" in str(exc_info.value).lower()
        os.unlink(path)

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    def test_groundedness_allows_in_monitor_mode(self, mock_post):
        """Monitor mode should log but NOT block ungrounded output."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ungroundedDetected": True,
                "ungroundedPercentage": 0.85,
                "ungroundedDetails": [{"text": "hallucinated"}],
            }),
        )

        path = _write_config(MONITOR_GROUNDEDNESS_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
        }):
            guardian = Guardian(path)
            result = guardian.validate_output(
                "Hallucinated text.",
                user_query="Query.",
                grounding_sources=["Source."],
            )

        assert result.is_safe is True
        os.unlink(path)

    def test_groundedness_skipped_in_dry_run(self):
        """Dry-run mode should skip all L2 checks including groundedness."""
        path = _write_config(DRY_RUN_GROUNDEDNESS_CONFIG)
        # No env vars needed — dry-run skips everything
        guardian = Guardian(path)
        result = guardian.validate_output(
            "Any output",
            user_query="Any query",
            grounding_sources=["Any source"],
        )

        assert result.is_safe is True
        assert len(result.results) == 0
        os.unlink(path)

    def test_groundedness_skipped_when_disabled(self):
        """When hallucination_detection.enabled=false, detector should not init."""
        path = _write_config(DISABLED_GROUNDEDNESS_CONFIG)
        guardian = Guardian(path)

        assert guardian._groundedness_detector is None
        result = guardian.validate_output(
            "Any output",
            user_query="Any query",
            grounding_sources=["Any source"],
        )
        assert result.is_safe is True
        os.unlink(path)

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    def test_groundedness_skipped_when_no_sources(self, mock_post):
        """When no user_query or grounding_sources provided, groundedness check is skipped."""
        path = _write_config(GROUNDEDNESS_ONLY_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
        }):
            guardian = Guardian(path)
            result = guardian.validate_output("Some output")

        assert result.is_safe is True
        mock_post.assert_not_called()
        os.unlink(path)

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    @patch("agentguard.guardian.ContentFilters")
    def test_toxicity_blocks_before_groundedness_runs(self, MockCF, mock_ground_post):
        """If toxicity blocks, groundedness should never be called."""
        # Output toxicity: BLOCKS
        mock_cf = MagicMock()
        mock_cf.analyze_text.return_value = _unsafe_result(
            "content_filters", "Harmful content: Hate (severity=6)"
        )
        MockCF.return_value = mock_cf

        path = _write_config(ENFORCE_GROUNDEDNESS_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
            "AZURE_LANGUAGE_ENDPOINT": "https://lang.cognitiveservices.azure.com",
            "AZURE_LANGUAGE_KEY": "test-key",
        }):
            guardian = Guardian(path)

            with pytest.raises(OutputBlockedError):
                guardian.validate_output(
                    "Toxic output",
                    user_query="Query",
                    grounding_sources=["Source"],
                )

        mock_ground_post.assert_not_called()
        os.unlink(path)

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    @patch("agentguard.l2_output.pii_detector.PIIDetector.__init__", return_value=None)
    @patch("agentguard.l2_output.pii_detector.PIIDetector.analyze")
    @patch("agentguard.guardian.ContentFilters")
    def test_pii_blocks_before_groundedness_runs(
        self, MockCF, mock_pii_analyze, mock_pii_init, mock_ground_post
    ):
        """If PII blocks, groundedness should never be called."""
        mock_cf = MagicMock()
        mock_cf.analyze_text.return_value = _safe_result("content_filters")
        MockCF.return_value = mock_cf

        # PII: BLOCKS
        mock_pii_analyze.return_value = _unsafe_result(
            "pii_detector", "PII detected: SSN"
        )

        path = _write_config(ENFORCE_GROUNDEDNESS_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
            "AZURE_LANGUAGE_ENDPOINT": "https://lang.cognitiveservices.azure.com",
            "AZURE_LANGUAGE_KEY": "test-key",
        }):
            guardian = Guardian(path)

            with pytest.raises(OutputBlockedError):
                guardian.validate_output(
                    "My SSN is 123-45-6789",
                    user_query="Query",
                    grounding_sources=["Source"],
                )

        mock_ground_post.assert_not_called()
        os.unlink(path)


# ── Config Integration Tests ─────────────────────────────────────

class TestGroundednessConfig:
    """Tests verifying config values flow into the detector correctly."""

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    def test_confidence_threshold_from_config(self, mock_post):
        """Config threshold (0.7) should be passed to detector.analyze()."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ungroundedDetected": True,
                "ungroundedPercentage": 0.75,
                "ungroundedDetails": [],
            }),
        )

        # Config has threshold=0.7, so 0.75 >= 0.7 → should block
        path = _write_config(GROUNDEDNESS_ONLY_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
        }):
            guardian = Guardian(path)

            with pytest.raises(OutputBlockedError):
                guardian.validate_output(
                    "Hallucinated text.",
                    user_query="Query.",
                    grounding_sources=["Source."],
                )
        os.unlink(path)

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    def test_block_on_high_confidence_false_allows(self, mock_post):
        """When block_on_high_confidence=false, ungrounded output passes."""
        config = """
global:
  mode: enforce
  log_level: minimal
  max_validation_latency_ms: 5000
input_security:
  prompt_shields:
    enabled: false
  content_filters:
    block_toxicity: false
    block_violence: false
    block_self_harm: false
output_security:
  hallucination_detection:
    enabled: true
    block_on_high_confidence: false
    confidence_threshold: 0.5
"""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ungroundedDetected": True,
                "ungroundedPercentage": 0.85,
                "ungroundedDetails": [],
            }),
        )

        path = _write_config(config)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
        }):
            guardian = Guardian(path)
            result = guardian.validate_output(
                "Hallucinated text.",
                user_query="Query.",
                grounding_sources=["Source."],
            )

        assert result.is_safe is True
        os.unlink(path)


# ── Audit Log Tests ──────────────────────────────────────────────

class TestGroundednessAudit:
    """Tests verifying audit log recording on groundedness block."""

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    def test_groundedness_block_recorded_in_audit_log(self, mock_post):
        """Audit record() should be called when groundedness blocks output."""
        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ungroundedDetected": True,
                "ungroundedPercentage": 0.85,
                "ungroundedDetails": [{"text": "hallucinated"}],
            }),
        )

        path = _write_config(GROUNDEDNESS_ONLY_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
        }):
            guardian = Guardian(path)
            # Inject a mock audit log
            mock_audit = MagicMock()
            guardian._audit = mock_audit

            with pytest.raises(OutputBlockedError):
                guardian.validate_output(
                    "Hallucinated output.",
                    user_query="Query.",
                    grounding_sources=["Source."],
                )

        # Verify audit was called
        mock_audit.record.assert_called_once()
        call_args = mock_audit.record.call_args
        assert call_args[0][0] == "validate_output"
        assert call_args[0][1] == "l2_output"
        assert call_args[1]["is_safe"] is False
        assert "groundedness_detector" in call_args[1]["metadata"]["blocked_by"]
        os.unlink(path)


# ── Telemetry Span Tests ─────────────────────────────────────────

class TestGroundednessSpans:
    """Tests verifying OTel spans emitted for groundedness checks."""

    @patch("agentguard.l2_output.groundedness_detector.requests.post")
    def test_groundedness_emits_otel_span(self, mock_post):
        """Groundedness check should emit 'agentguard.check.groundedness_detector' span."""
        provider, exporter = _make_in_memory_tracer_provider()

        mock_post.return_value = MagicMock(
            status_code=200,
            json=MagicMock(return_value={
                "ungroundedDetected": False,
                "ungroundedPercentage": 0.0,
                "ungroundedDetails": [],
            }),
        )

        path = _write_config(TELEMETRY_GROUNDEDNESS_CONFIG)
        with patch.dict(os.environ, {
            "CONTENT_SAFETY_ENDPOINT": "https://test.cognitiveservices.azure.com",
            "CONTENT_SAFETY_KEY": "test-key",
        }):
            with patch("agentguard.telemetry.trace") as mock_trace_mod:
                mock_trace_mod.get_tracer.return_value = provider.get_tracer("agentguard")
                mock_trace_mod.set_tracer_provider = MagicMock()

                guardian = Guardian(path)
                guardian._tracer = provider.get_tracer("agentguard")

                guardian.validate_output(
                    "Grounded output.",
                    user_query="Query.",
                    grounding_sources=["Source."],
                )

        spans = exporter.get_finished_spans()
        span_names = [s.name for s in spans]
        assert "agentguard.check.groundedness_detector" in span_names
        assert "agentguard.validate_output" in span_names
        os.unlink(path)
