# SageArmor Documentation Directory

Welcome to the SageArmor documentation repository. All architectural designs, operational guides, and specifications are indexed below.

---

## 1. Directory Layout

### [Architecture (`docs/architecture/`)](architecture/)
System design, technical rules, rate limits, and model capabilities.
- **[repo-scan-design.md](architecture/repo-scan-design.md):** Repository scanning architecture, AST traversal, and worker pool design.
- **[repo-scan-tech-rules.md](architecture/repo-scan-tech-rules.md):** Engineering rules, boundary checks, and timeout constraints.
- **[RATE_LIMITS.md](architecture/RATE_LIMITS.md):** Tiered sliding-window rate limits and quota policies.
- **[model_capabilities.yaml](architecture/model_capabilities.yaml):** Model profiles, context limits, and task compatibility matrix.

### [Guides (`docs/guides/`)](guides/)
Developer and operational playbooks.
- **[runbook.md](guides/runbook.md):** Operations, incident management, service recovery, and health checks.
- **[token-optimization-guide.md](guides/token-optimization-guide.md):** Cache-first strategies, cascade triage, and token budgeting.
- **[model-selection-playbook.md](guides/model-selection-playbook.md):** LLM routing guidelines, fallback tiers, and provider selection.
- **[PROJECT_RULES.md](guides/PROJECT_RULES.md):** Code conventions, safety invariants, and commit standards.
- **[GSD-STYLE.md](guides/GSD-STYLE.md):** Execution conventions and structured progress logging.

### [Specifications (`docs/specifications/`)](specifications/)
Product requirements and backlog specifications.
- **[PRD.md](specifications/PRD.md):** Initial baseline product requirements document.
- **[repo-scan-prd.md](specifications/repo-scan-prd.md):** Repository scanning epic requirements.
- **[repo-scan-todo.md](specifications/repo-scan-todo.md):** Milestone breakdown for repository scanning.
- **[progress.md](specifications/progress.md):** Historic feature implementation audit trail.

### [Archive (`docs/archive/`)](archive/)
Historical project proposals and background documents.
- `Final project idea.docx`: Initial project proposal document.
- `SECUREMIND PROJECT DOC.pdf`: Original design reference document.
