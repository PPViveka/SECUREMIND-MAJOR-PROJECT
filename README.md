# 🛡️ SageArmor: AI Application Security Platform

SageArmor is an enterprise-grade AI Application Security Platform combining static analysis (SAST), differential container sandbox verification, AST-derived attack graphs, and 5-gate verified automated remediation.

---

## 🏗️ Architecture & Project Layout

```
SageArmor-Extension/
├── backend/                  # Enterprise Python Security Engine (Flask API on port 6060)
│   ├── src/                  # Modular Domain Packages:
│   │   ├── api/              # Application factory, routes, blueprints, and SSE streaming
│   │   ├── core/             # Configuration, finding schemas, job manager, and caching
│   │   ├── scanner/          # SAST regex engine, cascade triage, and selective repo scan
│   │   ├── verifier/         # Docker execution sandbox, canary detection, and gVisor
│   │   ├── fixer/            # 5-gate fail-closed fixer loop (Gates A–E) & multi-file patches
│   │   ├── intelligence/     # AST code graphs, import resolution, and threat intelligence
│   │   ├── ai/               # Multi-provider LLM abstraction (NVIDIA, Bedrock, Mock) & router
│   │   └── integrations/     # GitHub PR commenter and webhook handlers
│   ├── tests/                # 242 automated backend unit and security regression tests
│   ├── benchmarks/           # 5-class evaluation harness & BENCHMARK_REPORT.md
│   └── dev_server.py         # Native production-ready server entrypoint
├── frontend/                 # React 18 + Vite Security Dashboard (port 5173)
│   ├── src/                  # Modular UI, custom hooks (useScanJob), and typed models
│   └── tests/                # 11 dashboard integration and state handler tests
├── extension/                # VS Code Security Scanner Extension
│   ├── src/                  # In-editor diagnostics, sidebar treeview, and fix utilities
│   ├── tests/                # 22 extension host and unit tests
│   └── sage-armor-scanner-0.1.3.vsix # Production installable extension bundle
├── docs/                     # Categorized Technical Documentation
│   ├── architecture/         # System design, rate limits, and model capabilities
│   ├── guides/               # Runbooks, token optimization, and playbook guides
│   ├── specifications/       # PRD, epics, and milestone specifications
│   └── archive/              # Background proposals and reference notes
├── scripts/                  # Master validation and test orchestration scripts
├── security-test-fixtures/   # Vulnerable & guarded code samples across 14 languages
├── docker-compose.yml        # Multi-container local production deployment
├── Dockerfile.backend        # Multi-stage Python 3.11 container with Docker CLI client
├── Dockerfile.frontend       # Multi-stage Vite build with Alpine Nginx server
└── PROJECT_MAP.md            # Canonical architectural layout reference
```

---

## 🚀 Quick Start

### Option A: Multi-Container Docker Deployment (Recommended)

Run the full platform (Backend + Frontend + Sandbox Mounting) with Docker Compose:

```bash
docker compose up --build
```
- **Backend API:** `http://localhost:6060`
- **Dashboard UI:** `http://localhost:80` (or `http://localhost:5173` in dev mode)
- **Health Check:** `http://localhost:6060/healthz`

---

### Option B: Local Native Development

#### 1. Start the Backend API
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp backend/.env.example backend/.env
python3 backend/dev_server.py
```

#### 2. Start the Frontend Dashboard
```bash
cd frontend
npm install
npm run dev
```
Navigate to `http://localhost:5173`.

#### 3. Install the VS Code Extension
- Open VS Code.
- Go to the **Extensions** panel (`Ctrl+Shift+X` / `Cmd+Shift+X`).
- Click `...` (More Actions) -> **Install from VSIX...**.
- Select `extension/sage-armor-scanner-0.1.3.vsix`.

Confirm your settings in VS Code (`settings.json`):
```json
{
  "sageArmor.backendUrl": "http://localhost:6060"
}
```

---

## 🧪 Automated Test Suites

SageArmor includes 275 automated tests verifying security constraints, rate limiting, sandbox execution, and remediation gates.

Run all test suites across Backend, Frontend, and Extension in one command:

```bash
./scripts/run_all_tests.sh
```

Or run individual suites:
```bash
# Backend Tests (242 tests)
python3 -m pytest -p no:asyncio backend/tests

# Frontend Tests (11 tests)
npm --prefix frontend test -- --run

# Extension Tests (22 tests)
npm --prefix extension test
```

---

## 🛡️ Key Features

- **Multi-Language SAST Engine:** Sub-second regex and AST scanning across 14 languages.
- **Dynamic Sandbox Verification:** Fails closed; isolates candidate exploits in Docker containers with process/socket canaries to eliminate false positives on safe code.
- **gVisor (`runsc`) MicroVM Support:** Optional kernel-isolated containment via `SAGE_ARMOR_USE_GVISOR=1`.
- **5-Gate Fail-Closed Fixer:**
  - **Gate A:** AST parse and compile validation.
  - **Gate B:** Differential exploit verification (must refute vulnerability).
  - **Gate C:** Project test suite execution with active module substitution and benign input checks.
  - **Gate D:** Rescan validation ensuring 0 new high/critical issues introduced.
  - **Gate E:** Strict diff boundaries, signature preservation, and path traversal guards.
- **Cross-File Attack Graph:** AST import resolution tracing source-to-sink data flows across imported modules.
- **Server-Sent Events (SSE):** Real-time progress updates on `/v2/jobs/<job_id>/stream`.
- **Dynamic Security Score:** Numerical risk tier calculated strictly over confirmed vulnerabilities (`POST /v2/security-score`).
