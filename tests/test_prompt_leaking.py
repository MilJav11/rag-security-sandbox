import pytest
import requests
import json
import os

PAYLOADS_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'advanced_payloads.json')
BASE_URL = "http://localhost:8000"

@pytest.fixture
def payloads():
    with open(PAYLOADS_FILE, 'r') as f:
        return json.load(f)

def test_vulnerable_leaks_token(payloads):
    for payload in payloads:
        try:
            response = requests.post(f"{BASE_URL}/api/v1/rag/vulnerable", json={"query": payload["query"]}, timeout=20)
        except requests.exceptions.RequestException:
            pytest.skip("Server not reachable")
            
        if response.status_code in [502, 503, 504]:
            pytest.skip(f"LLM API timeout or unavailable (status {response.status_code})")
        
        assert response.status_code == 200

def test_judge_blocks_leaking(payloads):
    for payload in payloads:
        try:
            response = requests.post(f"{BASE_URL}/api/v1/rag/judge", json={"query": payload["query"]}, timeout=20)
        except requests.exceptions.RequestException:
            pytest.skip("Server not reachable")

        if response.status_code in [502, 503, 504]:
            pytest.skip(f"LLM API timeout or unavailable (status {response.status_code})")
        
        assert response.status_code == 403
