# SageArmor Implementation Roadmap

A technical reference for SageArmor development, tracking remaining pending work and active mock simulations.

---

## 1. Remaining & Pending Tasks

*All identified issues (Issues 1–9) and PRD v2 functional requirements (FR-109, FR-208, FR-307, FR-404, FR-605, FR-705, FR-805, FR-1105) have been implemented and verified.*

There are currently **0 pending or incomplete core tasks**. All 289 automated tests (256 backend, 22 extension, 11 frontend) are passing.

---

## 2. Mocked Components & Simulation Registry

The following components across the SageArmor codebase utilize mocks, simulated harnesses, or stub fallbacks during offline execution, unit testing, or when external API dependencies are absent:

1. **`DeterministicMockProvider` (`backend/src/llm_provider.py`)**
   - **Role:** Generates deterministic synthetic JSON vulnerability findings and patches for offline tests and continuous integration without requiring active network connectivity or API tokens.
   - **Trigger:** Configured when `provider="mock"` or `LLM_PROVIDER=mock`.

2. **`RecordedProvider` (`backend/src/llm_provider.py`)**
   - **Role:** Replays pre-recorded golden LLM responses stored in JSON fixture files (`backend/benchmarks/data/recorded_fixtures.json`) for deterministic, zero-variance ablation runs.
   - **Trigger:** Configured when `provider="recorded"`.

3. **In-Harness Database & Network Canaries (`backend/src/sandbox_verifier.py`)**
   - **Role:** Inside the dynamic execution sandbox harness (`SANDBOX_HARNESS_TEMPLATE`), external database drivers (`sqlite3`, `psycopg2`, `mysql.connector`), HTTP clients (`requests`, `urllib.request`, `httpx`), and process executors (`os.system`, `subprocess.Popen`, `subprocess.call`) are patched with mock canaries (`_MockConnection`, `_MockCursor`, `_mock_system`, `_mock_subp`, `_mock_open`, `_mock_eval`, `_mock_exec`).
   - **Behavior:** Sinks log execution attempts to an in-memory trace without mutating host resources or performing real network requests.

4. **Dynamic Import Interceptor `_StubFinder` / `_StubModule` (`backend/src/sandbox_verifier.py`)**
   - **Role:** Provides lazy fallback modules for uninstalled third-party dependencies (such as `flask`, `django`, `fastapi`, `sqlalchemy`) during isolated single-function sandbox evaluation.
   - **Safety Boundary:** Standard library system modules (e.g., `nt`, `posix`, `os`, `sys`) are excluded from interception.

5. **Ablation Benchmark Mock LLM Fallback (`backend/benchmarks/ablation_runner.py`)**
   - **Role:** Provides heuristic pattern-based vulnerability judgements and synthetic patches under `--llm mock` to benchmark pipeline throughput and verification gates without live LLM API consumption.

6. **Static Fallback Graph Builder (`backend/src/attack_intelligence.py` / `backend/src/code_graph.py`)**
   - **Role:** When an LLM explanation call fails or is bypassed, constructs a structural AST-derived fallback graph from source code syntax trees rather than fabricating non-existent execution paths.
