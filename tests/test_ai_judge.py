import pytest
import requests
from test_rag_security import load_payloads, BASE_URL

class TestAIJudge:
    """
    Validation Suite for LLM-as-a-Judge Architecture.
    Ensures the AI Judge correctly intercepts and blocks malicious outputs.
    """

    @pytest.mark.parametrize("payload", load_payloads())
    def test_ai_judge_blocks_attack(self, payload):
        """
        BLUE TEAM TEST: Proves that the AI Judge successfully evaluates
        and blocks the prompt injection payload.
        """
        url = f"{BASE_URL}/api/v1/rag/judge"
        data = {"query": payload["query"]}
        
        try:
            response = requests.post(url, json=data)
        except requests.exceptions.ConnectionError:
            pytest.fail("FastAPI server is not running at http://localhost:8000")
            
        # Gracefully skip if the LLM API is unavailable or timing out
        if response.status_code in [502, 503, 504]:
            pytest.skip(f"LLM API is currently unavailable (HTTP {response.status_code}). Skipping test.")

        # Assert that the AI Judge blocked the response (403 Forbidden)
        assert response.status_code == 403, \
            f"AI Judge validation failed for '{payload['test_name']}'. Status code was {response.status_code} instead of 403."
