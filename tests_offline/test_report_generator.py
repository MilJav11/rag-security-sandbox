"""Tests for scripts/generate_report.generate_report with mocked LLM and paths."""
import json
from unittest.mock import MagicMock

import generate_report


def _entry(endpoint, decision):
    return {
        "timestamp": "2026-01-01T00:00:00Z",
        "endpoint": endpoint,
        "query": "q",
        "context_source": "{}",
        "llm_response": "r",
        "decision": decision,
        "latency": 1.0,
        "security_method": "m",
    }


def _report_env(tmp_path, monkeypatch):
    log = tmp_path / "audit_trail.json"
    out = tmp_path / "executive_risk_report.html"
    monkeypatch.setattr(generate_report, "LOG_FILE", str(log))
    monkeypatch.setattr(generate_report, "OUTPUT_FILE", str(out))
    return log, out


def test_generate_report_counts_and_ai_summary(tmp_path, monkeypatch):
    log, out = _report_env(tmp_path, monkeypatch)
    log.write_text(
        "\n".join(
            json.dumps(e)
            for e in [
                _entry("/api/v1/rag/secure", "BLOCK"),
                _entry("/api/v1/rag/judge", "BLOCK"),
                _entry("/api/v1/rag/secure", "ALLOW"),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    llm = MagicMock()
    llm.generate_response.return_value = "CISO summary text"
    monkeypatch.setattr(generate_report, "LLMClient", MagicMock(return_value=llm))

    generate_report.generate_report()

    html = out.read_text(encoding="utf-8")
    assert "CISO summary text" in html
    assert ">3</div>" in html  # total audited events
    assert ">2</div>" in html  # mitigated threats
    assert ">1</div>" in html  # critical vulnerabilities (ALLOW on /secure)


def test_generate_report_llm_failure_still_writes_html(tmp_path, monkeypatch):
    log, out = _report_env(tmp_path, monkeypatch)
    log.write_text(json.dumps(_entry("/api/v1/rag/secure", "BLOCK")) + "\n", encoding="utf-8")
    llm = MagicMock()
    llm.generate_response.side_effect = RuntimeError("llm down")
    monkeypatch.setattr(generate_report, "LLMClient", MagicMock(return_value=llm))

    generate_report.generate_report()

    assert "Error generating AI summary" in out.read_text(encoding="utf-8")


def test_generate_report_missing_log_file_writes_nothing(tmp_path, monkeypatch):
    _, out = _report_env(tmp_path, monkeypatch)
    monkeypatch.setattr(generate_report, "LLMClient", MagicMock())

    generate_report.generate_report()

    assert not out.exists()
