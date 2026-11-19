# SageArmor Production Project Architecture Map

This document outlines the canonical production-grade architecture and modular organization of SageArmor.

---

## 1. System Overview

SageArmor is an enterprise-grade AI Application Security Platform combining static analysis (SAST), differential execution sandbox verification, AST-derived attack graphs, and 5-gate verified remediation.

```
                      +-----------------------------+
                      |   VS Code Extension / Web   |
                      +--------------+--------------+
                                     |  REST / SSE
                                     v
                      +-----------------------------+
                      |     Backend API Gateway     |
                      |  (Flask / Blueprint / Auth) |
                      +--------------+--------------+
                                     |
    +-------------------+------------+------------+--------------------+
    |                   |                         |                    |
    v                   v                         v                    v
+-----------+   +---------------+         +---------------+    +---------------+
|  Scanner  |   |   Verifier    |         |     Fixer     |    | Intelligence  |
|  Engine   |   | (Docker/gVis) |         | (5-Gate Loop) |    |  (AST Graph)  |
+-----+-----+   +-------+-------+         +-------+-------+    +-------+-------+
      |                 |                         |                    |
      +-----------------+------------+------------+--------------------+
                                     |
                                     v
                      +-----------------------------+
                      |      AI / LLM Routing       |
                      |  (NVIDIA / Bedrock / Mock)  |
                      +-----------------------------+
```

---

## 2. Directory Structure

### Root Infrastructure
- `docker-compose.yml`: Local production multi-container orchestration.
- `Dockerfile.backend`: Multi-stage Python 3.11 container with Docker CLI client.
- `Dockerfile.frontend`: Multi-stage Node/Vite build with Alpine Nginx server.
- `.dockerignore`: Exclusion rules for optimal container build caching.
- `RUNBOOK.md`: Operational guide for deployment, monitoring, and troubleshooting.

### Backend (`backend/`)
- `dev_server.py`: Native development and production server entrypoint.
- `src/`: Production-grade modular Python package (`sagearmor`).
  - `config.py`: Centralized configuration management with environment validation.
  - `api/`: API application factory, middleware, blueprints, and SSE streaming.
    - `app.py`: `create_app()` factory with CORS, security guards, and error envelopes.
    - `middleware.py`: Thread-safe sliding-window rate limiter and token authentication.
    - `routes.py`: Flask blueprints for review, jobs, streaming, autofix, and risk scores.
  - `core/`: Data models, caching, and background job orchestration.
    - `finding_schema.py`: Canonical finding normalization and AST line anchoring.
    - `job_manager.py`: Persistent SQLite job store with state transitions and metrics.
    - `function_cache.py`: Dual-partitioned function hash scanner and cache.
  - `scanner/`: Fast static analysis and triage.
    - `sast_scanner.py`: Deterministic multi-language regex pattern detection.
    - `cascade_engine.py`: Cost-minimizing static-to-model triage cascade.
    - `repo_scan_engine.py` & `repo_selective_scan.py`: Git repo cloning and selective scanning.
  - `verifier/`: Dynamic exploit confirmation.
    - `sandbox_verifier.py`: Isolated container execution with canary detection and gVisor support.
  - `fixer/`: Autonomous remediation.
    - `verified_fixer.py`: 5-gate fail-closed verification loop (Gates A through E).
    - `autofix_engine.py`: Coordinated multi-span and multi-file patch validation.
    - `autofix_prompt.py`: Few-shot AST patch generation prompts.
  - `intelligence/`: Attack flow and threat modeling.
    - `code_graph.py`: AST function call graph and cross-file import flow tracing.
    - `attack_intelligence.py`: Dynamic exploit scenario generation and threat modeling.
  - `ai/`: Model provider abstraction and prompt engineering.
    - `llm_provider.py`: NVIDIA, Bedrock, Gemini, Recorded, and Mock providers with TaskRouter.
    - `prompt_builder.py`: Structured prompt construction with secret redaction.
  - `integrations/`: External ecosystem adapters.
    - `github_commenter.py`: GitHub PR review commenting and webhook validation.
- `tests/`: 242 automated backend unit, integration, and security regression tests.
- `benchmarks/`: 5-class evaluation harness, labels, and `BENCHMARK_REPORT.md`.

### Frontend (`frontend/`)
- `src/`: React 18 + Vite TypeScript single-page application.
  - `types/`: Strongly-typed TypeScript interfaces (`NormalizedFinding`, `JobStatus`, etc.).
  - `hooks/`: Custom state and lifecycle hooks (`useScanJob.ts`).
  - `services/`: REST client (`api.ts`) and session management (`auth.ts`).
  - `pages/`: `ScannerPage.tsx`, `LandingPage.tsx`, `AuthPage.tsx`.
  - `components/`: Modular UI widgets, finding cards, and status badges.
- `tests/`: Automated unit and dashboard integration tests (11 tests).

### Extension (`extension/`)
- `src/`: VS Code extension source.
  - `extension.ts`: Activation lifecycle, commands, and hook registrations.
  - `testable.ts`: Core testable exports.
  - `client.ts`: Backend communication client.
  - `scanner.ts`: Document change listener and scan dispatcher.
  - `diagnostics.ts`: In-editor problem diagnostics and squiggles.
  - `sidebar.ts`: Tree view provider for repository findings.
  - `fixUtils.ts` & `scanUtils.ts`: Indentation, unified diffs, and severity filters.
- `tests/`: Extension host and unit test suite (22 tests).
- `sage-armor-scanner-0.1.3.vsix`: Packaged VS Code extension bundle.

### Test Fixtures (`security-test-fixtures/`)
- Vulnerable and guarded twins across 14 supported programming languages.
