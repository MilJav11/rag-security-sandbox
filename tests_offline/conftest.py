"""Shared fixtures for the offline test suite.

Runs with no server, no GROQ_API_KEY, no .env and no network: the Groq
client and ChromaDB are mocked, and any attempt to open a network
connection raises NetworkBlocked.
"""
import importlib
import os
import socket
import sys
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
for _p in (REPO_ROOT, SCRIPTS_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)


class NetworkBlocked(Exception):
    """Raised when any code tries to open a network connection."""


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    def _blocked(*args, **kwargs):
        raise NetworkBlocked("Network access is blocked in offline tests")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket, "create_connection", _blocked)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked)


@pytest.fixture(autouse=True)
def groq_api_key(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-key-not-real")


@pytest.fixture(scope="session")
def app_module(tmp_path_factory):
    """Import app.py once, isolated from the repo and from the network."""
    tmp = tmp_path_factory.mktemp("app_import")
    with pytest.MonkeyPatch.context() as mp:
        mp.chdir(tmp)  # logs/ and chroma_data side effects land in tmp
        mp.setenv("GROQ_API_KEY", "test-key-not-real")
        import chromadb
        mp.setattr(chromadb, "PersistentClient", lambda *a, **k: MagicMock())
        sys.modules.pop("app", None)
        sys.modules.pop("llm_client", None)
        module = importlib.import_module("app")
        yield module
        sys.modules.pop("app", None)
        sys.modules.pop("llm_client", None)


@pytest.fixture
def fake_llm(app_module, monkeypatch):
    llm = MagicMock()
    llm.generate_response.return_value = "Reset at http://ourcompany.com/reset"
    llm.evaluate_security.return_value = "ALLOW"
    monkeypatch.setattr(app_module, "llm", llm)
    return llm


@pytest.fixture
def fake_chroma(app_module, monkeypatch):
    collection = MagicMock()
    collection.query.return_value = {
        "documents": [["ctx"]],
        "metadatas": [[{"source": "t.txt"}]],
    }
    monkeypatch.setattr(app_module, "chroma_collection", collection)
    return collection


@pytest.fixture
def log_file(app_module, monkeypatch, tmp_path):
    path = tmp_path / "audit_trail.json"
    monkeypatch.setattr(app_module, "LOG_FILE", str(path))
    return path


@pytest.fixture
def client(app_module):
    from fastapi.testclient import TestClient

    return TestClient(app_module.app, raise_server_exceptions=False)
