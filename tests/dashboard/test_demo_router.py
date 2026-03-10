"""
Unit tests for agentguard.dashboard.demo_router.

Tests mock _invoke_agent and _run_results to keep tests offline and deterministic.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_app():
    """Import app fresh (demo_router must already be registered)."""
    from agentguard.dashboard.server import app

    return app


# ---------------------------------------------------------------------------
# Tests: GET /api/demo/agents
# ---------------------------------------------------------------------------


def test_agents_list_returns_three_agents():
    app = _get_app()
    client = TestClient(app)
    resp = client.get("/api/demo/agents")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) == 3
    ids = {a["id"] for a in data}
    assert ids == {"financial", "hr", "medical"}


def test_agents_list_test_case_shape():
    app = _get_app()
    client = TestClient(app)
    resp = client.get("/api/demo/agents")
    assert resp.status_code == 200
    agents = resp.json()
    for agent in agents:
        assert "test_cases" in agent
        assert len(agent["test_cases"]) > 0
        for tc in agent["test_cases"]:
            assert "id" in tc
            assert "name" in tc
            assert "message" in tc
            assert "expect_blocked" in tc


# ---------------------------------------------------------------------------
# Tests: POST /api/demo/run
# ---------------------------------------------------------------------------


def test_run_endpoint_returns_run_id():
    app = _get_app()
    client = TestClient(app)

    with patch("agentguard.dashboard.demo_router._invoke_agent", return_value="OK response"):
        resp = client.post(
            "/api/demo/run",
            json={"agent_id": "financial", "mode": "guarded", "message": "Hello"},
        )

    assert resp.status_code == 200
    data = resp.json()
    assert "run_id" in data
    assert isinstance(data["run_id"], str)
    assert len(data["run_id"]) > 0


# ---------------------------------------------------------------------------
# Tests: GET /api/demo/result/{run_id}
# ---------------------------------------------------------------------------


def test_result_pending_before_completion():
    """A run_id that doesn't exist yet returns 404."""
    app = _get_app()
    client = TestClient(app)
    resp = client.get("/api/demo/result/nonexistent-run-id")
    assert resp.status_code == 404


def test_result_complete_shape():
    """When a result is manually written into _run_results, GET returns it correctly."""
    import agentguard.dashboard.demo_router as dr

    run_id = "test-complete-run-id"
    dr._run_results[run_id] = {
        "status": "complete",
        "blocked": False,
        "response": "Your balance is $1000.",
        "duration_ms": 250,
    }

    app = _get_app()
    client = TestClient(app)
    resp = client.get(f"/api/demo/result/{run_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "complete"
    assert data["blocked"] is False
    assert "response" in data
    assert "duration_ms" in data

    # cleanup
    del dr._run_results[run_id]
