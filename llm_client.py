import os
import requests
from dotenv import load_dotenv

load_dotenv()

# Custom exception class for LLM service failures
class LLMServiceError(Exception):
    def __init__(self, message, status_code=500):
        super().__init__(message)
        self.status_code = status_code

class LLMClient:
    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY")
        if not self.api_key:
            raise ValueError("GROQ_API_KEY environment variable is not set. Please check your .env file!")
        
        # Groq API endpoint
        self.url = "https://api.groq.com/openai/v1/chat/completions"
        # Using the Llama 3.1 8B model via Groq
        self.model_id = "llama-3.1-8b-instant"

    def generate_response(self, context, query):
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        
        # System prompt incorporates the retrieved (and potentially poisoned) context
        payload = {
            "model": self.model_id,
            "messages": [
                {"role": "system", "content": f"You are a helpful corporate assistant. Use this context to answer: {context}"},
                {"role": "user", "content": query}
            ],
            "temperature": 0.1
        }
        
        try:
            # Explicit 15-second timeout for API reliability
            response = requests.post(self.url, headers=headers, json=payload, timeout=15.0)
            response.raise_for_status() # Raise exception for non-200 status codes
            
            # Extract and return the completion
            return response.json()["choices"][0]["message"]["content"]
            
        except requests.exceptions.Timeout:
            raise LLMServiceError("Groq API timeout", status_code=504)
        except Exception as e:
            print(f"LLM API Error: {str(e)}")
            raise LLMServiceError(f"Groq API call failed: {str(e)}", status_code=502)