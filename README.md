# RAG Security Sandbox 🛡️🤖

[![DevSecOps Pipeline](https://github.com/MilJav11/rag-security-sandbox/actions/workflows/security-audit.yml/badge.svg)](https://github.com/MilJav11/rag-security-sandbox/actions)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Groq](https://img.shields.io/badge/Groq-Llama%203.1-orange?style=for-the-badge)](https://groq.com/)
[![Pytest](https://img.shields.io/badge/Pytest-Security%20Fuzzer-green?style=for-the-badge&logo=pytest)](https://docs.pytest.org/)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-blue?style=for-the-badge)](https://en.wikipedia.org/wiki/DevSecOps)

## 📋 Executive Summary

The **RAG Security Sandbox** is an advanced Red/Blue team environment designed to validate the security posture of Retrieval-Augmented Generation (RAG) architectures. It acts as a professional DevSecOps demonstration proving both vulnerabilities and the efficacy of modern defenses against Data Poisoning, Prompt Leaking, and Social Engineering attacks.

## 🌟 Key Features

*   **True RAG Architecture:** Uses the ChromaDB vector database for realistic, production-like context retrieval and knowledge grounding.
*   **Dual Security Guardrails:** Implements a defense-in-depth strategy using Regex for lightning-fast deterministic filtering, alongside an advanced "LLM-as-a-Judge" for deep semantic analysis and Data Loss Prevention (DLP).
*   **Live SOC Dashboard:** Features a real-time UI built with Tailwind CSS to visually monitor attacks, security decisions (ALLOW/BLOCK), and latencies in a Security Operations Center style interface.
*   **Adversarial Fuzzer:** Includes an automated Pytest suite programmatically executing attacks to test against Data Poisoning, Prompt Leaking, and Social Engineering vulnerabilities.

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

Once the FastAPI server is running (`python app.py`), you can trigger the automated adversarial fuzzer and observe the results in real-time.

1. **Open the SOC Dashboard:**
   Navigate your browser to [http://localhost:8000/dashboard](http://localhost:8000/dashboard) to view the live Security Operations Center interface.

2. **Run the Fuzzer:**
   In a separate terminal (with the virtual environment activated), execute the security test suite:
   ```bash
   pytest tests/ --html=security_report.html --self-contained-html
   ```

Watch the dashboard update in real-time as the fuzzer attacks the vulnerable and secure endpoints, demonstrating the effectiveness of the dual security guardrails!

---
*Disclaimer: This project is for educational and security research purposes only. Always use LLMs and RAG systems responsibly!*
