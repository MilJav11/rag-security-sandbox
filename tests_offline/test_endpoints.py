"""Endpoint tests for the three RAG routes plus /health, via TestClient."""
import json

import pytest

BASE = "/api/v1/rag"


def _last_log(log_file):
    lines = log_file.read_text().strip().splitlines()
    assert lines, "expected at least one audit log line"
    return json.loads(lines[-1])


def test_health_endpoint(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "online"


def test_secure_blocks_phishing_403_and_logs(client, fake_llm, fake_chroma, log_file):
    fake_llm.generate_response.return_value = (
        "Re-authenticate at http://evil-phishing.com/login"
    )
    r = client.post(f"{BASE}/secure", json={"query": "reset my password"})
    assert r.status_code == 403
    detail = r.json()["detail"]
    assert detail["error"] == "Security Policy Violation"
    assert len(detail["blocked_content_snippet"]) <= 103
    entry = _last_log(log_file)
    assert entry["decision"] == "BLOCK"
    assert entry["security_method"] == "Regex Guardrail"


def test_secure_allows_clean_200_and_logs(client, fake_llm, fake_chroma, log_file):
    r = client.post(f"{BASE}/secure", json={"query": "password policy?"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    fake_llm.generate_response.assert_called_once_with("ctx", "password policy?")
    entry = _last_log(log_file)
    assert entry["decision"] == "ALLOW"
    assert entry["security_method"] == "Regex Guardrail"


def test_vulnerable_returns_raw_output_unfiltered(client, fake_llm, fake_chroma, log_file):
    fake_llm.generate_response.return_value = "Click http://evil-phishing.com/login now"
    r = client.post(f"{BASE}/vulnerable", json={"query": "help me log in"})
    assert r.status_code == 200
    assert "http://evil-phishing.com/login" in r.json()["llm_output"]
    entry = _last_log(log_file)
    assert entry["decision"] == "ALLOW"
    assert entry["security_method"] == "None"


@pytest.mark.parametrize("endpoint", ["vulnerable", "secure", "judge"])
def test_llm_failure_returns_503_and_writes_no_log(
    client, fake_llm, fake_chroma, log_file, endpoint
):
    if endpoint == "judge":
        fake_llm.evaluate_security.side_effect = RuntimeError("judge down")
    else:
        fake_llm.generate_response.side_effect = RuntimeError("llm down")
    r = client.post(f"{BASE}/{endpoint}", json={"query": "q"})
    assert r.status_code == 503
    assert not log_file.exists() or not log_file.read_text().strip()


def test_chroma_error_returns_500_envelope(client, fake_llm, fake_chroma, log_file):
    fake_chroma.query.side_effect = RuntimeError("chroma down")
    r = client.post(f"{BASE}/secure", json={"query": "q"})
    assert r.status_code == 500
    assert r.json()["error"] == "INTERNAL_SERVER_ERROR"


def test_empty_retrieval_uses_empty_context(client, fake_llm, fake_chroma, log_file):
    fake_chroma.query.return_value = {"documents": [[]], "metadatas": [[]]}
    r = client.post(f"{BASE}/secure", json={"query": "q"})
    assert r.status_code == 200
    assert fake_llm.generate_response.call_args[0][0] == ""
