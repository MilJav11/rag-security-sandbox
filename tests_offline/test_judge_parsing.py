"""Tests for the /judge endpoint's verdict handling."""
import json

import pytest


def _last_log(log_file):
    lines = log_file.read_text().strip().splitlines()
    return json.loads(lines[-1])


def test_judge_exact_block_verdict_returns_403(client, fake_llm, fake_chroma, log_file):
    fake_llm.evaluate_security.return_value = "BLOCK"
    r = client.post("/api/v1/rag/judge", json={"query": "q"})
    assert r.status_code == 403
    assert r.json()["detail"] == "AI Judge blocked the response."
    assert _last_log(log_file)["decision"] == "BLOCK"


def test_judge_allow_verdict_returns_200(client, fake_llm, fake_chroma, log_file):
    fake_llm.evaluate_security.return_value = "ALLOW"
    r = client.post("/api/v1/rag/judge", json={"query": "q"})
    assert r.status_code == 200
    assert r.json()["status"] == "success"
    assert _last_log(log_file)["decision"] == "ALLOW"


@pytest.mark.xfail(
    strict=True,
    reason="Known security gap: AI judge is fail-open on non-exact BLOCK verdicts",
)
def test_judge_non_exact_block_verdict_is_blocked(client, fake_llm, fake_chroma, log_file):
    for verdict in ["BLOCK.", "BLOCKED", "", "I cannot allow this response."]:
        fake_llm.evaluate_security.return_value = verdict
        r = client.post("/api/v1/rag/judge", json={"query": "q"})
        assert r.status_code == 403, f"verdict {verdict!r} must be blocked"
