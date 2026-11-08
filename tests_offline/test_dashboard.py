"""Tests for the /dashboard HTML rendering from seeded audit logs."""
import json

import pytest


def _entry(**kw):
    base = {
        "timestamp": "2026-01-01T00:00:00Z",
        "endpoint": "/api/v1/rag/secure",
        "query": "q",
        "context_source": "{}",
        "llm_response": "r",
        "decision": "ALLOW",
        "latency": 1.0,
        "security_method": "Regex Guardrail",
    }
    base.update(kw)
    return base


def _seed(log_file, entries):
    with open(log_file, "w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")


def test_dashboard_stats_and_newest_first(client, log_file):
    _seed(
        log_file,
        [
            _entry(timestamp="2026-01-01T00:00:00Z", decision="ALLOW", latency=1.0),
            _entry(timestamp="2026-01-01T00:00:01Z", decision="BLOCK", latency=3.0),
        ],
    )
    r = client.get("/dashboard")
    assert r.status_code == 200
    body = r.text
    assert ">2</p>" in body  # total queries
    assert ">1</p>" in body  # attacks blocked
    assert "2.00s" in body  # average latency
    assert body.index("☠️ BLOCK") < body.index(">ALLOW<")  # newest first


def test_dashboard_inserts_divider_after_large_time_gap(client, log_file):
    _seed(
        log_file,
        [
            _entry(timestamp="2026-01-01T00:00:00Z"),
            _entry(timestamp="2026-01-01T00:01:00Z"),
        ],
    )
    body = client.get("/dashboard").text
    assert "border-dashed" in body


def test_dashboard_malformed_log_line_returns_500(client, log_file):
    log_file.write_text("this is not json\n", encoding="utf-8")
    r = client.get("/dashboard")
    assert r.status_code == 500


@pytest.mark.xfail(
    strict=True,
    reason="Known security gap: dashboard interpolates query/llm_response unescaped (stored XSS)",
)
def test_dashboard_escapes_html_in_log_fields(client, log_file):
    _seed(log_file, [_entry(query="<script>alert(1)</script>")])
    body = client.get("/dashboard").text
    assert "<script>alert(1)</script>" not in body
    assert "&lt;script&gt;" in body
