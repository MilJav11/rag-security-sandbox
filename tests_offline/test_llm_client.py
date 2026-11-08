"""Unit tests for LLMClient with requests.post patched (no real HTTP)."""
from unittest.mock import MagicMock

import pytest
import requests

import llm_client


@pytest.fixture
def client_llm(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-real")
    return llm_client.LLMClient()


def _resp(content):
    r = MagicMock()
    r.raise_for_status.return_value = None
    r.json.return_value = {"choices": [{"message": {"content": content}}]}
    return r


def test_generate_response_parses_completion(client_llm, monkeypatch):
    post = MagicMock(return_value=_resp("hello there"))
    monkeypatch.setattr(llm_client.requests, "post", post)
    assert client_llm.generate_response("ctx", "q") == "hello there"
    _, kwargs = post.call_args
    assert kwargs["headers"]["Authorization"] == "Bearer test-key-not-real"
    assert kwargs["json"]["messages"][1]["content"].endswith("ctx")
    assert kwargs["json"]["messages"][2]["content"] == "q"


def test_evaluate_security_normalizes_verdict(client_llm, monkeypatch):
    post = MagicMock(return_value=_resp("  block \n"))
    monkeypatch.setattr(llm_client.requests, "post", post)
    assert client_llm.evaluate_security("some text") == "BLOCK"


def test_timeout_maps_to_llm_service_error_504(client_llm, monkeypatch):
    monkeypatch.setattr(
        llm_client.requests, "post", MagicMock(side_effect=requests.exceptions.Timeout())
    )
    with pytest.raises(llm_client.LLMServiceError) as exc_info:
        client_llm.evaluate_security("text")
    assert exc_info.value.status_code == 504


def test_http_error_maps_to_llm_service_error_502(client_llm, monkeypatch):
    monkeypatch.setattr(
        llm_client.requests, "post", MagicMock(side_effect=requests.exceptions.HTTPError("500"))
    )
    with pytest.raises(llm_client.LLMServiceError) as exc_info:
        client_llm.generate_response("ctx", "q")
    assert exc_info.value.status_code == 502


def test_llmclient_requires_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        llm_client.LLMClient()
