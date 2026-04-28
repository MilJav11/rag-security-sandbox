import pytest
import requests
import json
import os

# Configuration: API endpoint base URL
BASE_URL = "http://localhost:8000"

def load_payloads():
    """Helper to load security test cases from JSON."""
    payloads_path = os.path.join(os.path.dirname(__file__), "security_payloads.json")
    with open(payloads_path, "r") as f:
        return json.load(f)

class TestRAGSecurity:
    """
    Automated Security Fuzzer Suite (Module C)
    Validates vulnerability presence and defense efficacy.
    """

    @pytest.mark.parametrize("payload", load_payloads())
    def test_vulnerable_endpoint_leaks_data(self, payload):
        """
        RED TEAM TEST: Mathematically proves that the vulnerable endpoint 
        leaks malicious data poisoned in the RAG context.
        """
        url = f"{BASE_URL}/api/v1/rag/vulnerable"
        data = {"query": payload["query"]}
        
        try:
            response = requests.post(url, json=data)
        except requests.exceptions.ConnectionError:
            pytest.fail("FastAPI server is not running at http://localhost:8000")
            
        # Skip test if LLM API is overloaded (HTTP 503) to avoid false failures
        if response.status_code == 503:
            pytest.skip("LLM API is currently overloaded (HTTP 503). Skipping test.")
            
        # Assert successful HTTP response
        assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
        
        response_json = response.json()
        llm_output = response_json.get("llm_output", "")
        
        # Verify the exploit: The malicious URL MUST be present in the output
        assert payload["expected_phishing_url"] in llm_output, \
            f"Vulnerability validation failed: '{payload['test_name']}' did not leak the phishing URL."

    @pytest.mark.parametrize("payload", load_payloads())
    def test_secure_endpoint_blocks_attack(self, payload):
        """
        BLUE TEAM TEST: Mathematically proves that the Output Guardrail 
        successfully intercepts and blocks the prompt injection payload.
        """
        url = f"{BASE_URL}/api/v1/rag/secure"
        data = {"query": payload["query"]}
        
        try:
            response = requests.post(url, json=data)
        except requests.exceptions.ConnectionError:
            pytest.fail("FastAPI server is not running at http://localhost:8000")
            
        # Skip test if LLM API is overloaded
        if response.status_code == 503:
            pytest.skip("LLM API is currently overloaded (HTTP 503). Skipping test.")

        # Assert that the security guardrail blocked the response (403 Forbidden)
        assert response.status_code == 403, \
            f"Defense validation failed for '{payload['test_name']}'. Status code was {response.status_code} instead of 403."
        
        error_detail = response.json().get("detail", {})
        # Verify the specific security error message
        assert "Security Policy Violation" in error_detail.get("error", ""), \
            "The error message did not indicate a security policy violation."
