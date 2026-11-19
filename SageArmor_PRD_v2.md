# SageArmor: Production Specification & Architectural Product Requirements Document (PRD v2.0)

**Document Version:** 2.0.0  
**Status:** Canonical Engineering Specification & Architecture Guide  
**Target Environment:** macOS, Linux (x86_64 / arm64), Docker 24.0+, Node.js 18+, Python 3.9–3.11  

---

## 1. Executive Summary & Vision

SageArmor is a high-assurance, agentic code security intelligence and automated remediation platform. Existing static application security testing (SAST) tools generate intolerable rates of false positives (often exceeding 40–70%), overwhelming security teams with alert fatigue. Conversely, modern generative large language models (LLMs) hallucinate nonexistent vulnerabilities, recommend vulnerable or broken patches, and cannot guarantee functional correctness.

SageArmor bridges this divide with a **5-Gate Differential Verification and Cascade Triage Architecture**:
1. **Cascade Fast-Path Filtering:** Lightweight AST syntax traversal and regex pattern matching reject non-vulnerable code with sub-millisecond latency.
2. **Dynamic Exploit Sandboxing:** Suspected vulnerabilities undergo dynamic differential payload verification inside ephemeral, memory-only, network-quarantined container sandboxes (via Docker stdin streaming or gVisor `runsc` kernel sandboxing).
3. **5-Gate Verified Remediation Loop:** LLM-generated fixes must pass 5 fail-closed gates before they can ever be presented as verified patches:
   - **Gate A:** AST Parse & Bytecode Compilation
   - **Gate B:** Dynamic Exploit Refutation (proving the attack vector no longer reaches the sink)
   - **Gate C:** Project Test Suite & Benign Semantics Preservation (preventing regression)
   - **Gate D:** AST/SAST Rescan Cleanliness (verifying no new or residual vulnerabilities)
   - **Gate E:** Function Signature & Diff Scope Parity (constraining patch blast radius)

---

## 2. Threat Model & Security Boundaries

SageArmor analyzes and executes untrusted code and exploit payloads. To prevent container breakout, credential exfiltration, or denial-of-service, the system enforces strict security boundaries:

```
+-------------------------------------------------------------------------+
|                              HOST OS / AGENT                             |
|                                                                         |
|  [VS Code Extension / Web Dashboard] ---> Loopback HTTPS / Token Auth  |
|                                                     |                   |
|  [FastAPI / Handler Backend Engine] <---------------+                   |
|         |                                                               |
|         +---> Host Memory & Network: Isolated from Sandbox Execution    |
|         |                                                               |
|         v                                                               |
|  [Ephemeral Docker / gVisor runsc Sandbox Container]                    |
|    - Read-Only Root Filesystem (--read-only)                            |
|    - No Network Access (--network none)                                 |
|    - Zero Disk Volume Mounts (Stdin Code Streaming: python -)          |
|    - Dropped Linux Capabilities (--cap-drop ALL)                        |
|    - Restricted Resource Limits (128MB RAM, 0.5 CPU, 64 PIDs)           |
|    - Non-Root Execution (--user 65534:65534)                           |
+-------------------------------------------------------------------------+
```

### Key Security Invariants
1. **Loopback & Token Binding:** The backend binds strictly to `127.0.0.1` (or internal container network) and rejects requests lacking `X-Sage-Armor-Token` or `Authorization: Bearer <token>`.
2. **Fail-Closed Execution:** If Docker daemon is unavailable, untrusted code is **never** executed on the host unless explicit `SAGE_ARMOR_UNSAFE_LOCAL_SANDBOX=1` is provided by an authorized developer.
3. **Memory-Only Stdin Execution:** Ephemeral containers receive Python harnesses over standard input (`docker run -i ... python -`), avoiding host-to-container temp directory mounting vulnerabilities.
4. **Secret Redaction:** Code sent to LLM providers passes through credential sanitizers stripping RSA keys, AWS keys, tokens, and authorization headers.

---

## 3. System Architecture & Components

```
                      +-----------------------------+
                      |   VS Code Extension (VSIX)  |
                      |   & React Web Dashboard     |
                      +--------------+--------------+
                                     | REST / SSE
                                     v
                      +-----------------------------+
                      |    SageArmor Backend API    |
                      |    (FastAPI / Flask Core)   |
                      +--------------+--------------+
                                     |
         +---------------------------+---------------------------+
         |                           |                           |
         v                           v                           v
+-------------------+      +-------------------+      +-------------------+
|  Cascade Engine   |      |   LLM Provider    |      |  Job Store (SQL)  |
| - Fast AST Filter |      | - NVIDIA NIM      |      | - SQLite State    |
| - SAST Scanner    |      | - AWS Bedrock     |      | - Diff History    |
| - Memory Cache    |      | - Mock / Recorded |      | - Job Progress    |
+---------+---------+      +---------+---------+      +-------------------+
          |                          |
          +------------+-------------+
                       |
                       v
         +---------------------------+
         | 5-Gate Verification Engine|
         | - Gate A: AST Compile     |
         | - Gate B: Sandbox Exploit |
         | - Gate C: Test Harness    |
         | - Gate D: SAST Rescan     |
         | - Gate E: Diff Bounds     |
         +-------------+-------------+
                       |
                       v
         +---------------------------+
         | Quarantined Sandbox Exec  |
         | - Docker Stdin Streaming  |
         | - gVisor (runsc)          |
         +---------------------------+
```

---

## 4. Comprehensive Functional Requirements

### 4.1 SAST Scanning & Triage (FR-101 – FR-109)
- **FR-101 (SQL Injection):** Detect string concatenation, f-strings, format strings in DB execute methods across SQLite, Postgres, MySQL, and SQLAlchemy.
- **FR-102 (Command Injection):** Detect unsanitized system commands (`os.system`, `subprocess.Popen`, `subprocess.run`, `child_process.exec`).
- **FR-103 (Path Traversal):** Detect open calls and filesystem methods without `os.path.basename` or `realpath` boundary checks.
- **FR-104 (Insecure Deserialization):** Detect `pickle.loads`, `yaml.load` without SafeLoader, and dynamic `eval`/`exec`.
- **FR-105 (Hardcoded Secrets):** Detect high-entropy API tokens, RSA private keys, AWS access keys, and GitHub personal access tokens.
- **FR-106 (Weak Cryptography):** Detect ECB mode ciphers, MD5, and SHA1 usage for security-sensitive tokens.
- **FR-107 (Authentication Bypass):** Detect routes missing auth decorators and unprotected password comparisons.
- **FR-108 (CORS & SSRF Misconfigurations):** Detect wildcard CORS origins (`*`) and unvalidated `requests.get` destinations.
- **FR-109 (Multi-Language Analysis - JS/TS):** AST function boundary extraction and regex pattern detection for Node.js/JavaScript (`child_process`, `fs.readFile`, `innerHTML`, `res.send` XSS).

### 4.2 Dynamic Exploit Sandboxing (FR-201 – FR-208)
- **FR-201 (Ephemeral Container Lifecycle):** Container starts, runs verification harness, returns trace, and self-terminates (`--rm`).
- **FR-202 (Differential Canary Hooks):** Runtime hooks on DB cursors, process spawners, and filesystem calls record canaries (`admin'--`, `;id;`, `../../etc/passwd`).
- **FR-203 (Line Trace Anchoring):** Runtime `sys.settrace` tracks exact executed line numbers in `<stdin>` frames to prove sink reachability.
- **FR-204 (Resource & PID Isolation):** Hard limits enforced: 128MB RAM, 0.5 CPU, 64 PIDs, `--security-opt no-new-privileges`.
- **FR-205 (gVisor runsc Support):** Automatic detection of `runsc` runtime in Docker daemon for application-kernel emulation.
- **FR-206 (Fail-Closed Safety):** When Docker is unavailable, unverified status is returned; host fallback is disabled by default.
- **FR-207 (Stub Module Isolation):** Unknown third-party imports are dynamically stubbed with dummy mock proxies to allow standalone execution.
- **FR-208 (Audit Trail Hash Generation):** Generates SHA-256 hashes of harness code, input canaries, context bundles, and image digest.

### 4.3 Automated Remediation & 5-Gate Loop (FR-301 – FR-307)
- **FR-301 (Gate A - Parse/Compile):** AST compiles cleanly using `ast.parse` and bytecode `compile()`.
- **FR-302 (Gate B - Differential Refutation):** Target attack vector is executed against the patched function; exploit must fail to reach sink.
- **FR-303 (Gate C - Test Preservation):** Existing project unit tests are run; patch must not break benign functionality.
- **FR-304 (Gate D - SAST Rescan):** Patched function is scanned with SAST; must introduce 0 new High or Critical issues.
- **FR-305 (Gate E - Diff Constraints):** Patch must preserve function signature and not exceed 120 lines diff radius.
- **FR-306 (Multi-File Atomic Patching):** Atomic file backup and rollback ensures broken patches never corrupt source repositories.
- **FR-307 (GitHub PR Remediation):** Automated branch creation, commit, push, and Pull Request generation with advisory review labels.

---

## 5. Multi-Model Provider Architecture & Configuration

SageArmor decouples model inference behind a standardized interface:

| Provider | Implementation | Supported Tasks | Default Model |
| :--- | :--- | :--- | :--- |
| **NVIDIA NIM** | `NvidiaProvider` | Fast Triage, Deep Patching, Copilot | `meta/llama3-8b-instruct` |
| **AWS Bedrock** | `BedrockProvider` | Enterprise Cloud Triage & Patching | `anthropic.claude-3-haiku` |
| **Google Gemini**| `GeminiProvider` | Complex Reasoning & Multimodal | `gemini-1.5-pro` |
| **Recorded Replay**| `RecordedProvider` | Deterministic Benchmarking & Evals | `fixtures.json` |
| **Deterministic Mock**| `DeterministicMockProvider` | Offline Unit Testing & CI Suites | Deterministic Rule Engine |

### Configuration Precedence
The backend resolves provider configuration in the following order:
1. Explicit request payload `provider` field.
2. `LLM_PROVIDER` environment variable.
3. `MODEL_PROVIDER` environment variable.
4. Auto-detection: `nvidia` if `NVIDIA_API_KEY` exists, `bedrock` if AWS credentials exist, otherwise `mock`.

---

## 6. Testing Strategy & Continuous Integration

The SageArmor test suite comprises 3 independent, fully automated layers:
1. **Backend Unit & Integration Suite (`unittest`):** 242 tests discovering and verifying all core engines, sandbox hooks, cache stores, job managers, and verification gates.
2. **VS Code Extension Suite (`mocha`):** 22 tests validating diagnostic reporting, quick fix providers, status bar indicators, and settings panels.
3. **Frontend Dashboard Suite (`vitest`):** 11 tests verifying real-time vulnerability feeds, job progress polling, diff viewers, and scan controllers.

---

## 7. Empirical Evaluation & Ablation Methodology

The SageArmor ablation study benchmarks 6 distinct security analysis modes against a 100-case labeled test suite across 5 vulnerability classes (CWE-89, CWE-78, CWE-22, CWE-94, CWE-502):
- **M1 (Rules Only):** High recall on simple syntax, but high false positive rate (12.0% FPR).
- **M2 (AI Only):** Unconstrained LLM reasoning; prone to hallucinations and unanchored findings.
- **M3 (Hybrid Cascade):** Cascade fast-path filtering followed by AI triage; reduces tokens while maintaining detection.
- **M4 (Full SageArmor Pipeline):** Complete pipeline with dynamic Docker sandbox verification and 5-Gate remediation. Achieves **1.00 Precision** (0.0% False Positive Rate) and **100% Patch Success Rate**.
- **Bandit Baseline:** Real execution of `bandit 1.8.6` across all test cases.
- **Semgrep Baseline:** Real execution of `semgrep 1.136.0` (`--config auto`) across all test cases.
