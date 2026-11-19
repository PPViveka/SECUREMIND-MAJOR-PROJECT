# 📖 SageArmor Runbook: Environment Setup & Operations

This document provides the canonical operating instructions for running the SageArmor backend, frontend dashboard, VS Code extension, sandbox verification harness, and evaluation benchmarks.

---

## 1. System Requirements & Prerequisites

- **Operating System:** macOS (Apple Silicon or Intel), Linux (Ubuntu 20.04+), or Windows (WSL2)
- **Python:** Python 3.9+ (`python3 --version`)
- **Node.js:** Node.js 18+ and npm 9+ (`node --version`, `npm --version`)
- **Docker (Optional):** Docker Desktop / daemon for containerized sandbox verification. If Docker is unavailable, SageArmor automatically falls back to hardened native subprocess process isolation (`runtime="host"`).

---

## 2. Environment Configuration

Copy the example environment configuration into `backend/.env` (or configure system environment variables):

```bash
# Backend Network & Security
PORT=6060
HOST=127.0.0.1
MAX_REQUEST_BYTES=2097152
CORS_ORIGINS=http://localhost:5173,http://localhost:3000
RATE_LIMIT_PER_MINUTE=120
SAGEARMOR_AUTH_TOKEN=           # Optional: required if bound to non-loopback host

# LLM Providers (Select one or use local rules fallback)
LLM_PROVIDER=bedrock            # 'bedrock' | 'nvidia' | 'gemini' | 'mock' | 'recorded'
BEDROCK_MODEL_ID=anthropic.claude-3-5-sonnet-20241022-v2:0
AWS_REGION=us-east-1

# Optional NVIDIA NIM provider
# LLM_PROVIDER=nvidia
# NVIDIA_API_KEY=nvapi-...
# NVIDIA_MODEL=meta/llama3-8b-instruct

# State Storage
SAGEARMOR_CACHE_DB=backend/.sage_armor_cache.db
SAGEARMOR_JOBS_DB=backend/jobs.db
SAGEARMOR_SANDBOX_RUNTIME=host  # 'host' or 'docker'
```

---

## 3. Starting the Services

### Backend Native Server

```bash
# From workspace root
python3 backend/dev_server.py
```
- Listens on `http://localhost:6060`
- Provides endpoints: `/review`, `/review/status`, `/repo-scan/*`, `/repo-autofix/*`, `/attack-path`, `/risk-score`, `/simulate`, `/copilot`, and `/healthz`.

### Frontend Dashboard

```bash
# From frontend directory
cd frontend
npm install
npm run dev
```
- Available in browser at `http://localhost:5173`
- Pre-configured to communicate with backend at `http://localhost:6060`.

### VS Code Extension

```bash
# From extension directory
cd extension
npm install
npm run compile
npm test
```
- Open `extension/` in VS Code and press `F5` to launch an Extension Development Host.

---

## 4. Verification Gate Calibration & Benchmarks

### Sandbox Gate Calibration

Run gate calibration to verify that all 5 verification gates (AST Compile, Differential Sandbox, Regression Tests, Rescan Clean, and Signature Parity) pass before running evaluations:

```bash
python3 backend/scripts/calibrate_gates.py
```
- Generates `backend/benchmarks/calibration_report.json`.

### Benchmark Evaluation Suite

Run the empirical evaluation harness across all 5 CWE vulnerability classes (100 functions balanced across `dev` and `eval` splits):

```bash
# Run deterministic ablation evaluation using recorded LLM fixtures
python3 backend/benchmarks/ablation_runner.py --split dev --llm recorded

# Run fast mock evaluation
python3 backend/benchmarks/ablation_runner.py --split dev --llm mock
```

---

## 5. Continuous Integration Commands

- **Backend Tests:** `python3 -m unittest discover backend/tests -p "test_*.py"`
- **Frontend Build:** `cd frontend && npm run build`
- **Extension Tests:** `cd extension && npm run compile && npm test`
