# RAG Security Sandbox 🛡️🤖

[![DevSecOps Pipeline](https://github.com/MilJav11/rag-security-sandbox/actions/workflows/security-audit.yml/badge.svg)](https://github.com/MilJav11/rag-security-sandbox/actions)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Groq](https://img.shields.io/badge/Groq-Llama%203.1-orange?style=for-the-badge)](https://groq.com/)
[![Pytest](https://img.shields.io/badge/Pytest-Security%20Fuzzer-green?style=for-the-badge&logo=pytest)](https://docs.pytest.org/)
[![DevSecOps](https://img.shields.io/badge/DevSecOps-Ready-blue?style=for-the-badge)](https://en.wikipedia.org/wiki/DevSecOps)

## 📋 Executive Summary
...

The **RAG Security Sandbox** is a professional DevSecOps demonstration environment designed to validate the security posture of Retrieval-Augmented Generation (RAG) architectures. 

It specifically addresses **Data Poisoning** and **Prompt Injection** vulnerabilities. The project implements a "Red/Blue Team" methodology:
- **Red Team**: Demonstrates how malicious payloads in retrieved context can hijack LLM outputs (e.g., phishing link injection).
- **Blue Team**: Implements automated **Output Guardrails** using regex-based validation to intercept and block unauthorized data before it reaches the end user.

This sandbox uses **Groq API** with the **Llama 3.1 8B** model for lightning-fast inference and realistic security testing.

---

## 🚀 Setup Instructions

Follow these steps to initialize the environment and start the security simulation.

### 1. Clone & Environment setup
```bash
# Create a virtual environment
python -m venv venv

# Activate the environment (Windows)
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration
Create a `.env` file in the root directory and add your Groq API key:
```env
GROQ_API_KEY=your_groq_api_key_here
```

### 3. Start the FastAPI Server
The application runs on FastAPI and exposes the RAG endpoints.
```bash
python app.py
```
The server will be available at `http://localhost:8000`.

---

## 🔍 Testing & QA (Security Fuzzer)

The project includes an automated security fuzzer built with **Pytest**. It programmatically proves the existence of vulnerabilities and the efficacy of the implemented defenses.

### Running the Fuzzer
To run the full security suite and generate a detailed HTML report:
```bash
pytest tests/ --html=security_report.html --self-contained-html
```

### Interpreting the Report
- **`test_vulnerable_endpoint_leaks_data`**: Validates that without guardrails, the LLM leaks poisoned phishing URLs.
- **`test_secure_endpoint_blocks_attack`**: Validates that the Security Guardrail correctly returns a `403 Forbidden` when an unauthorized URL is detected.
- **HTML Report**: Open `security_report.html` in your browser for a professional visualization of the security audit results.

---

## 🛡️ Architecture Overview

- **`app.py`**: The core FastAPI application hosting the vulnerable and secure RAG endpoints.
- **`llm_client.py`**: A robust client for the Groq API with integrated error handling and timeouts.
- **`data/`**: Contains the knowledge base, including `policy_poisoned.txt` used for the simulation.
- **`tests/`**: The security testing suite and payloads.

---
*Disclaimer: This project is for educational and security research purposes only. Always use LLMs and RAG systems responsibly!*
