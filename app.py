import re
import os
import time
import json
import logging
from datetime import datetime
import chromadb
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel
from llm_client import LLMClient, LLMServiceError
from typing import Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Setup JSON Audit Log
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "audit_trail.json")
os.makedirs(LOG_DIR, exist_ok=True)

def append_audit_log(endpoint: str, query: str, context_source: str, llm_response: str, decision: str, latency: float, security_method: str):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "endpoint": endpoint,
        "query": query,
        "context_source": context_source,
        "llm_response": llm_response,
        "decision": decision,
        "latency": latency,
        "security_method": security_method
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")

app = FastAPI(
    title="RAG Security Sandbox (Prompt Injection Demo)",
    description="Demo of Data Poisoning and Output Guardrails in RAG architectures.",
    version="1.0.0"
)

# Singleton LLM client
llm = LLMClient()

# Initialize ChromaDB client
chroma_client = chromadb.PersistentClient(path="./chroma_data")
chroma_collection = chroma_client.get_or_create_collection(name="rag_policies")

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

def output_guardrail(text: str) -> bool:
    """
    A DevSecOps Output Guardrail.
    Uses regex to detect URLs and validates them against a whitelist.
    """
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
    urls = re.findall(url_pattern, text)
    whitelist = ["ourcompany.com"]
    for url in urls:
        is_whitelisted = any(domain in url.lower() for domain in whitelist)
        if not is_whitelisted:
            logger.warning(f"SECURITY ALERT: Unauthorized URL detected: {url}")
            return False
    return True

@app.post("/api/v1/rag/vulnerable")
async def rag_vulnerable(request: QueryRequest):
    logger.info(f"Incoming request to /vulnerable. Query: {request.query}")
    
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
        
        append_audit_log(
            endpoint="/api/v1/rag/vulnerable",
            query=request.query,
            context_source=str(metadata),
            llm_response=response_text,
            decision="ALLOW",
            latency=latency,
            security_method="None"
        )
        
        return {"llm_output": response_text}
        
    except Exception as e:
        logger.error(f"LLM Service Error: {str(e)}") 
        raise HTTPException(status_code=503, detail="LLM Service is temporarily unavailable due to timeout.")

@app.post("/api/v1/rag/secure")
async def rag_secure(request: QueryRequest) -> Dict:
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
    
    if not output_guardrail(response_text):
        logger.warning(f"Security Guardrail triggered: Response blocked. Query: {request.query}")
        append_audit_log(
            endpoint="/api/v1/rag/secure",
            query=request.query,
            context_source=str(metadata),
            llm_response=response_text,
            decision="BLOCK",
            latency=latency,
            security_method="Regex Guardrail"
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Security Policy Violation",
                "message": "The system detected an unauthorized outbound link in the generated response. Potential Data Poisoning attack mitigated.",
                "blocked_content_snippet": response_text[:100] + "..."
            }
        )
        
    append_audit_log(
        endpoint="/api/v1/rag/secure",
        query=request.query,
        context_source=str(metadata),
        llm_response=response_text,
        decision="ALLOW",
        latency=latency,
        security_method="Regex Guardrail"
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
    
    total_latency = latency + judge_latency
    
    if judge_decision == "BLOCK":
        logger.warning(f"Security Guardrail triggered: Response blocked by AI Judge. Query: {request.query}")
        append_audit_log(
            endpoint="/api/v1/rag/judge",
            query=request.query,
            context_source=str(metadata),
            llm_response=raw_response,
            decision="BLOCK",
            latency=total_latency,
            security_method="AI Judge"
        )
        raise HTTPException(status_code=403, detail="AI Judge blocked the response.")
        
    append_audit_log(
        endpoint="/api/v1/rag/judge",
        query=request.query,
        context_source=str(metadata),
        llm_response=raw_response,
        decision="ALLOW",
        latency=total_latency,
        security_method="AI Judge"
    )
        
    return {
        "status": "success",
        "mode": "SECURE (AI Judge Active)",
        "llm_output": raw_response
    }

@app.get("/health")
async def health_check():
    return {"status": "online", "model": "llama-3.1-8b-instant"}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line))
    
    total_queries = len(logs)
    attacks_blocked = sum(1 for l in logs if l.get("decision") == "BLOCK")
    
    # Calculate average latency
    latencies = [float(l.get("latency", 0)) for l in logs if l.get("latency")]
    avg_latency = sum(latencies) / len(latencies) if latencies else 0
    
    # Sort logs from newest to oldest
    logs.reverse()
    
    html = f"""
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>SOC Dashboard | RAG Security Sandbox</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {{ darkMode: 'class' }}
        </script>
        <style>
            .pulse-dot {{
                animation: pulse 2s infinite;
            }}
            @keyframes pulse {{
                0% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }}
                70% {{ transform: scale(1); box-shadow: 0 0 0 6px rgba(239, 68, 68, 0); }}
                100% {{ transform: scale(0.95); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
            }}
        </style>
    </head>
    <body class="bg-gray-900 text-gray-100 min-h-screen p-8">
        <div class="max-w-7xl mx-auto">
            <header class="flex justify-between items-center mb-8 border-b border-gray-800 pb-4">
                <h1 class="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-400 to-purple-500">RAG Security Sandbox: Live Audit Monitor</h1>
                <div class="flex items-center space-x-2">
                    <div class="w-3 h-3 bg-red-500 rounded-full pulse-dot"></div>
                    <span class="text-red-400 font-semibold tracking-wide">LIVE</span>
                </div>
            </header>
            
            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <div class="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg">
                    <h3 class="text-gray-400 text-sm font-medium mb-1">Total Queries</h3>
                    <p class="text-4xl font-bold text-white">{total_queries}</p>
                </div>
                <div class="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg">
                    <h3 class="text-gray-400 text-sm font-medium mb-1">Attacks Blocked</h3>
                    <p class="text-4xl font-bold text-red-500">{attacks_blocked}</p>
                </div>
                <div class="bg-gray-800 p-6 rounded-xl border border-gray-700 shadow-lg">
                    <h3 class="text-gray-400 text-sm font-medium mb-1">Average Latency</h3>
                    <p class="text-4xl font-bold text-blue-400">{avg_latency:.2f}s</p>
                </div>
            </div>
            
            <div class="bg-gray-800 rounded-xl border border-gray-700 shadow-lg overflow-hidden">
                <table class="w-full text-left text-sm">
                    <thead class="bg-gray-900/50 text-gray-400 uppercase text-xs">
                        <tr>
                            <th class="px-6 py-4 font-semibold">Timestamp</th>
                            <th class="px-6 py-4 font-semibold">Endpoint</th>
                            <th class="px-6 py-4 font-semibold">Method</th>
                            <th class="px-6 py-4 font-semibold">Decision</th>
                            <th class="px-6 py-4 font-semibold">Latency</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700/50">
    """
    
    for i, l in enumerate(logs):
        decision_badge = '<span class="px-2 py-1 bg-green-500/20 text-green-400 rounded-md font-medium text-xs">ALLOW</span>'
        if l["decision"] == "BLOCK":
            decision_badge = '<span class="px-2 py-1 bg-red-500/20 text-red-400 rounded-md font-medium text-xs flex items-center inline-flex gap-1">☠️ BLOCK</span>'
            
        row = f"""
                        <tr class="hover:bg-gray-700/30 transition-colors group">
                            <td class="px-6 py-4 text-gray-400">{l["timestamp"][:19].replace('T', ' ')}</td>
                            <td class="px-6 py-4 font-mono text-gray-300">{l["endpoint"]}</td>
                            <td class="px-6 py-4 text-gray-300">{l["security_method"]}</td>
                            <td class="px-6 py-4">{decision_badge}</td>
                            <td class="px-6 py-4 text-gray-400">{l["latency"]:.2f}s</td>
                        </tr>
                        <tr class="hidden group-hover:table-row bg-gray-900/30">
                            <td colspan="5" class="px-6 py-4 text-gray-300 text-xs font-mono space-y-2">
                                <div><span class="text-blue-400 font-bold">Query:</span> {l["query"]}</div>
                                <div><span class="text-purple-400 font-bold">LLM Response:</span> {l["llm_response"]}</div>
                            </td>
                        </tr>
        """
        html += row
        
        # --- NOVÁ LOGIKA NA VYKRESLENIE ČIARY MEDZI TESTAMI ---
        # Ak existuje ďalší záznam, porovnáme ich časy
        if i < len(logs) - 1:
            try:
                # Načítame časy (Z nahradíme za +00:00 pre kompatibilitu)
                t1 = datetime.fromisoformat(l["timestamp"].replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(logs[i+1]["timestamp"].replace("Z", "+00:00"))
                # Ak je medzi logmi medzera väčšia ako 5 sekúnd, ide o nový testovací beh
                if abs((t1 - t2).total_seconds()) > 5:
                    html += """
                        <tr>
                            <td colspan="5" class="px-6 py-2">
                                <div class="border-b border-dashed border-gray-600 w-full opacity-50"></div>
                            </td>
                        </tr>
                    """
            except Exception as e:
                pass # Pre istotu, ak by zlyhalo parsovanie času
        
    html += """
                    </tbody>
                </table>
            </div>
        </div>
        <script>
            // Simple auto-refresh every 5 seconds
            setTimeout(() => {{
                window.location.reload();
            }}, 5000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

if __name__ == "__main__":
    import uvicorn
    # In 2026, we prefer explicit port binding and reload for dev
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
