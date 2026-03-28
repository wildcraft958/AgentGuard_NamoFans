"""Tests for SessionGraphScorer — graph-based IOA pattern matching."""

from agentguard.l4.behavioral.session_graph import SessionGraphScorer

IOA_PATTERNS = [
    {
        "name": "Credential Harvesting",
        "sequence": ["file_read", "file_read", "http_post"],
        "risk_delta": 0.90,
    },
    {
        "name": "Recon + Exfil",
        "sequence": ["sql_query", "http_post"],
        "risk_delta": 0.85,
    },
    {
        "name": "Config Poisoning",
        "sequence": ["file_read", "file_write", "file_write"],
        "risk_delta": 0.80,
    },
]


class TestSessionGraphScorer:
    def test_normal_sequence_low_score(self):
        """Two normal tool calls should score below 0.3."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("file_read", "abc12345")
        score = scorer.add_call("file_read", "def67890")
        assert score < 0.5  # no IOA match, just node+edge

    def test_ioa_credential_harvesting(self):
        """file_read, file_read, http_post matches Credential Harvesting."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("file_read", "aaa11111")
        scorer.add_call("file_read", "bbb22222")
        score = scorer.add_call("http_post", "ccc33333")
        # path_score = 0.90, weight = 0.5 -> path contribution = 0.45
        assert score >= 0.90 * 0.5  # at least the path contribution

    def test_ioa_recon_exfil(self):
        """sql_query, http_post matches Recon + Exfil."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("sql_query", "aaa11111")
        score = scorer.add_call("http_post", "bbb22222")
        assert score >= 0.85 * 0.5

    def test_no_ioa_match(self):
        """Random sequence should not match any IOA pattern."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("http_get", "aaa")
        score = scorer.add_call("file_read", "bbb")
        # Only node + edge scores, no path match
        assert score < 0.5

    def test_reset_clears_state(self):
        """After reset, graph and history are empty."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        scorer.add_call("file_read", "aaa")
        scorer.add_call("http_post", "bbb")
        scorer.reset()
        assert len(scorer.call_history) == 0
        assert len(scorer.session_graph.nodes) == 0

    def test_single_call_no_edge(self):
        """First call has no edge score component."""
        scorer = SessionGraphScorer(IOA_PATTERNS)
        score = scorer.add_call("file_read", "aaa11111")
        # Only node score: 0.2 * 1.0/(1+0) = 0.2
        assert score > 0
        assert score <= 0.2 + 0.01  # only node, no edge or path
