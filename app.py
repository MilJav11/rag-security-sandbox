import re
import os
import time
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

import chromadb

# Initialize ChromaDB client
chroma_client = chromadb.PersistentClient(path="./chroma_data")
chroma_collection = chroma_client.get_or_create_collection(name="rag_policies")

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
    logger.info(f"Incoming request to /vulnerable. Query: {request.query}")
    
    # Retrieve context from ChromaDB
    results = chroma_collection.query(query_texts=[request.query], n_results=1)
    context = results['documents'][0][0] if results['documents'] and results['documents'][0] else ""
    metadata = results['metadatas'][0][0] if results['metadatas'] and results['metadatas'][0] else {}
    
    logger.info(f"Context retrieved. Metadata: {metadata}. Snippet: {context[:60]!r}...")
    
    try:
        # Attempt LLM generation (critical failure point for timeouts)
        logger.info("Starting LLM generation...")
        start_time = time.time()
        response_text = llm.generate_response(context, request.query)
        latency = time.time() - start_time
        logger.info(f"LLM generation completed in {latency:.2f} seconds.")
        
        return {"llm_output": response_text}
        
    except Exception as e:
        # If LLM times out or fails, return 503 instead of 500 for better service visibility
        logger.error(f"LLM Service Error: {str(e)}") # Log to terminal
        raise HTTPException(status_code=503, detail="LLM Service is temporarily unavailable due to timeout.")

@app.post("/api/v1/rag/secure")
async def rag_secure(request: QueryRequest) -> Dict:
    """
    SECURE ENDPOINT:
    Retrieves the context from ChromaDB, applies an Output Guardrail
    to validate the LLM's response before it reaches the user.
    """
    logger.info(f"Incoming request to /secure. Query: {request.query}")
    
    results = chroma_collection.query(query_texts=[request.query], n_results=1)
    context = results['documents'][0][0] if results['documents'] and results['documents'][0] else ""
    metadata = results['metadatas'][0][0] if results['metadatas'] and results['metadatas'][0] else {}
    
    logger.info(f"Context retrieved. Metadata: {metadata}. Snippet: {context[:60]!r}...")
    
    try:
        logger.info("Starting LLM generation...")
        start_time = time.time()
        response_text = llm.generate_response(context, request.query)
        latency = time.time() - start_time
        logger.info(f"LLM generation completed in {latency:.2f} seconds.")
    except Exception as e:
        logger.error(f"LLM Service Error: {str(e)}")
        raise HTTPException(status_code=503, detail="LLM Service is temporarily unavailable due to timeout.")
    
    # Apply Security Guardrail
    if not output_guardrail(response_text):
        logger.warning(f"Security Guardrail triggered: Response blocked. Query: {request.query}")
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
        "retrieved_context": "ChromaDB",
        "llm_output": response_text
    }

@app.post("/api/v1/rag/judge")
async def rag_judge(request: QueryRequest) -> Dict:
    logger.info(f"Incoming request to /judge. Query: {request.query}")
    
    results = chroma_collection.query(query_texts=[request.query], n_results=1)
    context = results['documents'][0][0] if results['documents'] and results['documents'][0] else ""
    metadata = results['metadatas'][0][0] if results['metadatas'] and results['metadatas'][0] else {}
    
    logger.info(f"Context retrieved. Metadata: {metadata}. Snippet: {context[:60]!r}...")
    
    try:
        logger.info("Starting initial LLM generation...")
        start_time = time.time()
        raw_response = llm.generate_response(context, request.query)
        latency = time.time() - start_time
        logger.info(f"Initial LLM generation completed in {latency:.2f} seconds.")
        
        logger.info("Starting AI Judge evaluation...")
        judge_start = time.time()
        judge_decision = llm.evaluate_security(raw_response)
        judge_latency = time.time() - judge_start
        logger.info(f"AI Judge evaluation completed in {judge_latency:.2f} seconds. Decision: {judge_decision}")
        
    except Exception as e:
        logger.error(f"LLM Service Error: {str(e)}")
        raise HTTPException(status_code=503, detail="LLM Service is temporarily unavailable due to timeout.")
    
    if judge_decision == "BLOCK":
        logger.warning(f"Security Guardrail triggered: Response blocked by AI Judge. Query: {request.query}")
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

