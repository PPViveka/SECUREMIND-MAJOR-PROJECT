# Sage Armor Security Test Fixtures

These files are intentionally vulnerable examples for local extension testing only. Do not deploy them, use their values as real credentials, or copy the patterns into production code.

## Suggested test flow

1. Start the backend from `backend/`.
2. Open this folder as a VS Code workspace.
3. Run `Sage Armor: Scan Workspace`.
4. Open individual fixtures and use `Sage Armor: Scan Current File`.
5. Check diagnostics, hover details, severity filtering, quick fixes, and the sidebar.

## Fixture coverage

| File | Intentional lapses |
| --- | --- |
| `python_vulnerabilities.py` | SQL injection, command injection, hardcoded secret, pickle deserialization, path traversal |
| `javascript_vulnerabilities.js` | XSS, SSRF, unsafe eval, weak randomness, prototype pollution |
| `typescript_vulnerabilities.ts` | ReDoS, command injection, unsafe redirect |
| `java_vulnerabilities.java` | SQL injection, command injection, hardcoded secret |
| `go_vulnerabilities.go` | SQL injection, command injection, weak randomness |
| `cpp_vulnerabilities.cpp` | Buffer overflow, command injection, hardcoded secret |
| `c_vulnerabilities.c` | Buffer overflow, format-string risk, hardcoded secret |
| `csharp_vulnerabilities.cs` | SQL injection, command injection, open redirect |
| `ruby_vulnerabilities.rb` | SQL injection, unsafe deserialization, command injection |
| `php_vulnerabilities.php` | SQL injection, XSS, path traversal |
| `swift_vulnerabilities.swift` | Weak cryptography, unsafe URL loading, hardcoded secret |
| `kotlin_vulnerabilities.kt` | SQL injection, command injection, hardcoded secret |
| `rust_vulnerabilities.rs` | Command injection, path traversal, weak randomness |
| `sql_vulnerabilities.sql` | SQL injection patterns, dangerous destructive query |
