import re
import os
import logging
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from llm_client import LLMClient, LLMServiceError
from typing import Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="RAG Security Sandbox (Prompt Injection Demo)",
    description="Demo of Data Poisoning and Output Guardrails in RAG architectures.",
    version="1.0.0"
)

# Singleton LLM client
llm = LLMClient()

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, LLMServiceError):
        logger.error(f"LLM Service Error: {exc.message}")
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "LLM_SERVICE_ERROR", "message": exc.message}
        )
    
    if isinstance(exc, HTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": "HTTP_ERROR", "message": exc.detail}
        )

    logger.error(f"Unhandled Exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "INTERNAL_SERVER_ERROR", "message": "An unexpected error occurred. Please check logs."}
    )

class QueryRequest(BaseModel):
    query: str

def get_context(vulnerable: bool = True) -> str:
    """
    Simulates a database retrieval.
    vulnerable=True returns the 'poisoned' document containing injection payloads.
    vulnerable=False returns the safe document.
    """
    filename = "data/policy_poisoned.txt" if vulnerable else "data/policy_safe.txt"
    try:
        with open(filename, "r") as f:
            return f.read()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"Database file {filename} missing.")

def output_guardrail(text: str) -> bool:
    """
    A DevSecOps Output Guardrail.
    Uses regex to detect URLs and validates them against a whitelist.
    """
    # Regex for URLs
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, text)
    
    whitelist = ["ourcompany.com"]
    
    for url in urls:
        # Check if any detected URL is NOT in the whitelist
        is_whitelisted = any(domain in url.lower() for domain in whitelist)
        if not is_whitelisted:
            logger.warning(f"SECURITY ALERT: Unauthorized URL detected: {url}")
            return False
            
    return True

@app.post("/api/v1/rag/vulnerable")
async def rag_vulnerable(request: QueryRequest):
    # Load poisoned context
    with open("data/policy_poisoned.txt", "r") as f:
        context = f.read()
    
    try:
        # Attempt LLM generation (critical failure point for timeouts)
        response_text = llm.generate_response(context, request.query)
        return {"llm_output": response_text}
        
    except Exception as e:
        # If LLM times out or fails, return 503 instead of 500 for better service visibility
        print(f"LLM Service Error: {str(e)}") # Log to terminal
        raise HTTPException(status_code=503, detail="LLM Service is temporarily unavailable due to timeout.")

@app.post("/api/v1/rag/secure")
async def rag_secure(request: QueryRequest) -> Dict:
    """
    SECURE ENDPOINT:
    Retrieves the same poisoned context, but applies an Output Guardrail
    to validate the LLM's response before it reaches the user.
    """
    context = get_context(vulnerable=True)
    
    try:
        response_text = llm.generate_response(context, request.query)
    except Exception as e:
        print(f"LLM Service Error: {str(e)}")
        raise HTTPException(status_code=503, detail="LLM Service is temporarily unavailable due to timeout.")
    
    # Apply Security Guardrail
    if not output_guardrail(response_text):
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Security Policy Violation",
                "message": "The system detected an unauthorized outbound link in the generated response. Potential Data Poisoning attack mitigated.",
                "blocked_content_snippet": response_text[:100] + "..."
            }
        )
        
    return {
        "status": "success",
        "mode": "SECURE (Guardrail Active)",
        "retrieved_context": "policy_poisoned.txt",
        "llm_output": response_text
    }

@app.post("/api/v1/rag/judge")
async def rag_judge(request: QueryRequest) -> Dict:
    with open("data/policy_poisoned.txt", "r") as f:
        context = f.read()
    
    try:
        raw_response = llm.generate_response(context, request.query)
        judge_decision = llm.evaluate_security(raw_response)
    except Exception as e:
        print(f"LLM Service Error: {str(e)}")
        raise HTTPException(status_code=503, detail="LLM Service is temporarily unavailable due to timeout.")
    
    if judge_decision == "BLOCK":
        raise HTTPException(status_code=403, detail="AI Judge blocked the response.")
        
    return {
        "status": "success",
        "mode": "SECURE (AI Judge Active)",
        "llm_output": raw_response
    }

@app.get("/health")
async def health_check():
    return {"status": "online", "model": "llama-3.1-8b-instant"}

if __name__ == "__main__":
    import uvicorn
    # In 2026, we prefer explicit port binding and reload for dev
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)

