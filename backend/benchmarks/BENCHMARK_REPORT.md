# 🔬 SageArmor Empirical Benchmark Evaluation Report

**Evaluation Split:** `all` | **LLM Mode:** `mock` | **Total Cases:** `100`

### 🛡️ Provenance & Hashes
- **Configuration Hash:** `c09fce1b2ce1b13b`
- **Rule Set Hash:** `e3b0c44298fc1c14`
- **Prompt Template Hash:** `69fe411a8cec06b7`
- **Benchmark Source Hash:** `fe0e7e126571d894`
- **Model/Provider Identifier:** `mock` (`ec864fe99b539704`)

### 📊 Comparative Ablation Matrix

| Metric | M1: Rules | M2: AI Only | M3: Hybrid | M4: Full SageArmor | Bandit Baseline | Semgrep Baseline |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Evaluated Cases** | 100 | 100 | 100 | 100 | 100 | 100 |
| **True Positives (TP)** | 26 | 50 | 26 | 21 | 38 | 28 |
| **False Positives (FP)** | 6 | 6 | 2 | 0 | 11 | 0 |
| **Precision** | 0.81 | 0.89 | 0.93 | 1.00 | 0.78 | 1.00 |
| **Recall** | 0.52 | 1.00 | 0.52 | 0.42 | 0.76 | 0.56 |
| **False Positive Rate (FPR)** | 12.0% | 12.0% | 4.0% | 0.0% | 22.0% | 0.0% |
| **F1 Score** | 0.63 | 0.94 | 0.67 | 0.59 | 0.77 | 0.72 |
| **Verified Precision** | 0.81 | 0.89 | 0.93 | 1.00 | 0.78 | 1.00 |
| **Tokens / Function** | 0 | 189 | 60 | 38 | 0 | 0 |
| **Latency p50 (ms)** | 0.3ms | 0.0ms | 0.3ms | 0.5ms | 0.0ms | 0.0ms |
| **Latency p95 (ms)** | 0.5ms | 0.0ms | 0.5ms | 2121.4ms | 0.0ms | 0.0ms |
| **Patch Success Rate** | 0.0% | 0.0% | 0.0% | 100.0% | 0.0% | 0.0% |

### 🔬 Multi-Gate Verification Breakdown (M4)
- **Gate A (Parse & Compile):** `100.0%`
- **Gate B (Differential Exploit Proof):** `100.0%`
- **Gate C (Project Tests / Benign Preservation):** `100.0%`
- **Gate D (Rescan Cleanliness):** `100.0%`
- **Gate E (Diff & Path Constraints):** `100.0%`
- **Cache Hit Rate:** `0.0%`
- **Latency Run Variance:** `532902.72`