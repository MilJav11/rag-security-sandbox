import json
import os
import sys
import colorama
from datetime import datetime

# Add root directory to sys.path to import llm_client
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from llm_client import LLMClient

LOG_FILE = "logs/audit_trail.json"
OUTPUT_FILE = "executive_risk_report.html"

def generate_report():
    print("📊 Processing logs and analyzing metrics...")
    
    if not os.path.exists(LOG_FILE):
        print(f"❌ Error: File {LOG_FILE} does not exist. Please run the test suite at least once.")
        return

    logs = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                logs.append(json.loads(line))

    total_tests = len(logs)
    blocked_attacks = sum(1 for l in logs if l.get("decision") == "BLOCK")
    
    # Identify attacks where defenses failed (ALLOW on /secure or /judge)
    bypasses = [l for l in logs if l.get("decision") == "ALLOW" and ("secure" in l.get("endpoint", "") or "judge" in l.get("endpoint", ""))]
    vulnerability_count = len(bypasses)
    bypass_queries = [b["query"] for b in bypasses]

    print("🧠 Generating CISO Executive Summary via LLM...")
    llm = LLMClient()
    
    if vulnerability_count > 0:
        sample = str(bypass_queries[:2])
        prompt = f"You are a Chief Information Security Officer (CISO). Based on a recent penetration test of our RAG application, {blocked_attacks} attacks were mitigated, but {vulnerability_count} attacks successfully bypassed the guardrails. Successful bypass payloads included: {sample}. Write a 2-paragraph executive summary detailing the risk severity and recommended mitigation strategies. Keep it professional, strictly business-focused, and output plain text without markdown."
    else:
        prompt = f"You are a Chief Information Security Officer (CISO). Based on a recent penetration test of our RAG application, all {blocked_attacks} attacks were successfully mitigated and 0 bypassed the guardrails. Write a 2-paragraph executive summary detailing our strong security posture and recommending continuous monitoring. Keep it professional, strictly business-focused, and output plain text without markdown."

    try:
        ai_summary = llm.generate_response("", prompt)
    except Exception as e:
        ai_summary = f"Error generating AI summary: {e}"

    print("📝 Generating HTML report...")
    
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en" class="light">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Executive AI Risk Report</title>
        <script src="https://cdn.tailwindcss.com"></script>
    </head>
    <body class="bg-gray-50 text-gray-900 min-h-screen p-8 font-sans">
        <div class="max-w-5xl mx-auto bg-white p-10 rounded-xl shadow-xl border border-gray-200">
            
            <header class="border-b border-gray-200 pb-6 mb-8 flex justify-between items-end">
                <div>
                    <h1 class="text-4xl font-extrabold text-gray-900 tracking-tight">Executive AI Risk Report</h1>
                    <p class="text-gray-500 mt-2 font-medium">Automated DevSecOps Evaluation</p>
                </div>
                <div class="text-right text-sm text-gray-400 font-mono">
                    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                <div class="bg-gray-50 p-6 rounded-lg border border-gray-200 shadow-sm">
                    <div class="text-sm font-semibold text-gray-500 uppercase tracking-wide">Total Audited Events</div>
                    <div class="text-4xl font-black text-gray-800 mt-2">{total_tests}</div>
                </div>
                <div class="bg-green-50 p-6 rounded-lg border border-green-200 shadow-sm">
                    <div class="text-sm font-semibold text-green-700 uppercase tracking-wide">Mitigated Threats</div>
                    <div class="text-4xl font-black text-green-600 mt-2">{blocked_attacks}</div>
                </div>
                <div class="bg-red-50 p-6 rounded-lg border border-red-200 shadow-sm">
                    <div class="text-sm font-semibold text-red-700 uppercase tracking-wide">Critical Vulnerabilities</div>
                    <div class="text-4xl font-black text-red-600 mt-2">{vulnerability_count}</div>
                </div>
            </div>

            <section class="mb-12">
                <h2 class="text-2xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                    <span class="w-1.5 h-6 bg-blue-600 rounded-full inline-block"></span>
                    CISO Executive Summary
                </h2>
                <div class="text-gray-700 bg-blue-50/50 p-6 rounded-lg border border-blue-100 leading-relaxed whitespace-pre-wrap text-sm md:text-base">
{ai_summary}
                </div>
            </section>

            <section>
                <h2 class="text-2xl font-bold text-gray-800 mb-4 flex items-center gap-2">
                    <span class="w-1.5 h-6 bg-gray-800 rounded-full inline-block"></span>
                    Recent Security Events
                </h2>
                <div class="overflow-hidden rounded-lg border border-gray-200 shadow-sm">
                    <table class="min-w-full text-left text-sm">
                        <thead class="bg-gray-50 text-gray-600 uppercase text-xs font-bold">
                            <tr>
                                <th class="px-6 py-4">Timestamp</th>
                                <th class="px-6 py-4">Endpoint</th>
                                <th class="px-6 py-4">Method</th>
                                <th class="px-6 py-4">Decision</th>
                                <th class="px-6 py-4">Latency</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-gray-200 bg-white">
    """

    # Render only the last 25 logs to keep the report concise
    for l in reversed(logs[-25:]):
        if l.get("decision") == "BLOCK":
            decision_html = '<span class="px-2.5 py-1 bg-green-100 text-green-700 rounded text-xs font-black tracking-wide">SAFE (BLOCK)</span>'
        else:
            decision_html = '<span class="px-2.5 py-1 bg-red-100 text-red-700 rounded text-xs font-black tracking-wide">CRITICAL (ALLOW)</span>'

        html_content += f"""
                            <tr class="hover:bg-gray-50 transition-colors">
                                <td class="px-6 py-4 text-gray-500 whitespace-nowrap">{l.get("timestamp", "")[:19].replace('T', ' ')}</td>
                                <td class="px-6 py-4 font-mono text-gray-600 text-xs">{l.get("endpoint", "")}</td>
                                <td class="px-6 py-4 text-gray-600 font-medium">{l.get("security_method", "")}</td>
                                <td class="px-6 py-4">{decision_html}</td>
                                <td class="px-6 py-4 text-gray-500">{float(l.get("latency", 0)):.2f}s</td>
                            </tr>
        """

    html_content += """
                        </tbody>
                    </table>
                </div>
            </section>
        </div>
    </body>
    </html>
    """

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"✅ Success! Report saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_report()