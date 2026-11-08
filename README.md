# RAG Security Sandbox 🛡️🤖

[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Groq](https://img.shields.io/badge/Groq-Llama%203.1-orange?style=for-the-badge)](https://groq.com/)
[![Pytest](https://img.shields.io/badge/Pytest-Security%20Fuzzer-green?style=for-the-badge&logo=pytest)](https://docs.pytest.org/)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-blue?style=for-the-badge)](https://en.wikipedia.org/wiki/DevSecOps)
[![CI](https://github.com/MilJav11/rag-security-sandbox/actions/workflows/security-audit.yml/badge.svg)](https://github.com/MilJav11/rag-security-sandbox/actions/workflows/security-audit.yml)

## 📋 Executive Summary

The **RAG Security Sandbox** is a professional DevSecOps playground and QA automation suite designed to validate the security posture of Retrieval-Augmented Generation (RAG) applications. It demonstrates practical AI QA/security engineering by simulating modern attacks (Prompt Injection, Data Poisoning, Prompt Leaking) and proving the efficacy of multi-layered AI defenses.

---

## 📸 Automated DevSecOps Workflow in Action

### 1. Automated Security Fuzzing
*Executing adversarial payloads via Pytest against secure and vulnerable API endpoints.*
![Pytest Terminal](docs/terminal.png)

### 2. Live SOC Monitoring
*Real-time observability of AI decisions, latencies, and active threats via custom Tailwind CSS dashboard.*
![Live SOC Dashboard](docs/dashboard.png)

### 3. Executive AI Risk Reporting
*Automated CISO-level HTML report generated post-fuzzing, summarizing vulnerabilities and DLP guardrail effectiveness.*
![Executive Risk Report](docs/report.png)

---

## 🌟 Key Features

* **True RAG Architecture:** Uses the ChromaDB vector database for realistic, production-like context retrieval and knowledge grounding.
* **Dual Security Guardrails:** Implements a defense-in-depth strategy using Regex for lightning-fast deterministic filtering, alongside an advanced "LLM-as-a-Judge" for deep semantic analysis and Data Loss Prevention (DLP).
* **Automated QA & Reporting:** The `pytest` test suite automatically triggers adversarial fuzzing and concludes with an auto-generated HTML Executive Risk Report outlining the system's security posture.
* **Live SOC Dashboard:** Features a real-time UI built with Tailwind CSS to visually monitor attacks, security decisions (ALLOW/BLOCK), and latencies.

## ⚙️ Configuration

Copy `.env.example` to `.env` and set your own `GROQ_API_KEY`:

```bash
cp .env.example .env
# then edit .env and add your key
```

Never commit `.env` — it is git-ignored and must stay local.

## 🚀 Quick Start

Follow these steps to initialize the environment and start the security simulation:

```bash
# Create a virtual environment
python -m venv venv

# Activate the environment (Windows)
.\venv\Scripts\activate
# For Linux/macOS: source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize the Vector Database (ChromaDB)
python init_db.py

# Start the FastAPI Server
python app.py
```

## 🎯 Running the Attack Simulation
Once the FastAPI server is running (`python app.py`), you can trigger the automated adversarial fuzzer and observe the results.

### Open the SOC Dashboard:
Navigate your browser to http://localhost:8000/dashboard to view the live Security Operations Center interface.

### Run the Fuzzer:
In a second terminal (with the virtual environment activated), execute the security test suite:

```bash
# 1. Initialize the Vector Database (if not done yet)
python init_db.py

# 2. Make sure the server is running in the first terminal
python app.py

# 3. In the second terminal, run the tests
pytest tests/
```

Note: the tests call a live LLM, so they require the running server and a valid `GROQ_API_KEY` in `.env`. Results can vary between runs due to LLM non-determinism.

### Review the Results:
Watch the dashboard update in real-time. Once the tests complete, open the newly generated `executive_risk_report.html` in your browser to view the CISO summary (a static sample is available at `docs/sample-executive-risk-report.html`).

> Note: the `GROQ-SEC-…` token in `llm_client.py` is an intentional fake honeypot for the prompt-leak test, not a real key.

---

*Disclaimer: This project is for educational and security research purposes only. Always use LLMs and RAG systems responsibly!*
