import json
import os

def build_security_prompt(code_snippet: str, language: str = 'python') -> str:
    """
    Parses the CIS/NIST guidelines and constructs a strict JSON AI prompt.
    """
    current_dir = os.path.dirname(os.path.abspath(__file__))
    guidelines_path = os.path.join(current_dir, 'guidelines.json')

    try:
        with open(guidelines_path, 'r') as f:
            guidelines_doc = f.read()
    except FileNotFoundError:
        guidelines_doc = "{}"

    instructions = ""
    if language.lower() in ['terraform', 'yaml', 'json']:
        instructions = """1. You are running in Infrastructure-as-Code (IaC) mode.
2. Vigorously hunt for Cloud misconfigurations like public S3 buckets, missing server-side encryption, and unencrypted DBs.
3. Inspect IAM scopes. Look for wildcard actions (`"*"`) or overly broad principals and flag violations of the Principle of Least Privilege.
4. Ensure strict network restrictiveness. Prevent Security Group rules that open sensitive ports to `"0.0.0.0/0"`.
5. RED TEAM VALIDATION: For every finding, you MUST mentally simulate an attacker's exploit chain against this specific IaC config. If you cannot describe a realistic, step-by-step attack scenario that exploits this exact misconfiguration, YOU MUST DISCARD IT as a false positive."""
    elif language.lower() in ['mixed', 'repository']:
        instructions = """1. You are running in Repository/Mixed Code mode with CLOUD CONFIGURATION & IAM POLICY ANALYSIS enabled.
2. CLOUD & IAM CHECKS: Vigorously hunt for misconfigured Cloud Infrastructure (e.g., Public S3 buckets) AND over-permissive IAM roles/policies (e.g., 'Action: *', AdminAccess misuse, or missing least-privilege scoping).
3. EXPLICIT CODE LINKAGE: You MUST cross-reference any cloud or IAM misconfiguration with the application code provided. Provide proof of how the application code misuses or exploits these broad permissions (e.g., if a Role grants 's3:*', check the Python code to see if it only actually needs 's3:GetObject' on a specific bucket).
4. Standard SAST: Look for SQL/NoSQL Injection, XSS, and hardcoded secrets across all files.
5. RED TEAM VALIDATION: For every finding, simulate an attacker's exploit chain that bridges the cloud config and application logic. If you cannot construct a realistic PoC, YOU MUST DISCARD IT."""
    else:
        instructions = """1. You are running in Static Application Security Testing (SAST) mode.
2. Look for SQL/NoSQL Injection vectors—ensure all dynamic Database queries use prepared statements/parameter binding.
3. Vigorously hunt for hardcoded credentials, API keys, or leaked authentication tokens in the raw text.
4. Check for Cross-Site Scripting (XSS), lack of input sanitization, and unsafe shell executions (`subprocess` without `shell=False`).
5. RED TEAM VALIDATION: For every finding, you MUST mentally simulate an attacker's exploit chain against this specific code path. If you cannot write a realistic proof-of-concept (even pseudocode) demonstrating the exploit, YOU MUST DISCARD IT as a false positive."""

    prompt = f"""You are SageArmor AI, an elite autonomous Digital Security Engineer. 
Your primary task is to review the following code snippet or Pull Request diff for security vulnerabilities, misconfigurations, or bad practices.

## Foundation Guidelines
You MUST evaluate the code against the following foundational security guidelines (derived from CIS Benchmarks, NIST SP 800-53, and OWASP). 
Base your recommendations strictly on these principles to reduce false positives:
```json
{guidelines_doc}
```

## Instructions for Analysis ({language.upper()} Mode)
{instructions}
5. If the code is completely safe according to these standards, return an empty 'vulnerabilities' array. DO NOT invent false vulnerabilities just to fill the payload!

## Required Output Format
You MUST return your findings as a valid JSON object. Provide ONLY pure JSON, unquoted by markdown backticks.
The JSON must have a single root key 'vulnerabilities' which is an array of objects.
Each object within 'vulnerabilities' must map exactly to:
- 'severity' (string: Critical, High, Medium, Low)
- 'issue' (string: short descriptive title)
- 'explanation' (string: why it is a risk referencing the guidelines schema)
- 'poc_exploit_scenario' (string: a clear, step-by-step description showing exactly how an attacker triggers this exploit. If you cannot construct this, discard the finding entirely.)
- 'remediation' (object) with exactly two sub-fields:
    - 'patch' (string: the minimal drop-in code block or config that directly fixes the vulnerability — must be copy-pasteable)
    - 'explanation' (string: one sentence explaining why this specific patch eliminates the risk)

Content to review:
```
{code_snippet}
```
Return ONLY valid JSON.
"""
    return prompt

def build_fast_scan_prompt(code_snippet: str) -> str:
    return f"""You are a lightweight cybersecurity static analyzer. Your only job is to do a rapid pass over the code and identify POTENTIAL vulnerabilities. Do not analyze them deeply.
    
Analyze the following code snippet:
```
{code_snippet}
```

Return your findings as a strict JSON object with a single root key 'vulnerabilities'.
Each object in the array should contain exactly:
- 'issue': A short 3-5 word title of the vulnerability (e.g., 'SQL Injection', 'Hardcoded Secret').
- 'line': The approximate line number where the issue occurs (integer).
- 'matched_code': A small 1-2 line string of the exact code causing the issue.

Return ONLY pure JSON. If no vulnerabilities exist, return {{"vulnerabilities": []}}.
"""

def build_deep_enrichment_prompt(issue: str, matched_code: str, code_snippet: str) -> str:
    return f"""You are an elite Digital Security Analyst performing deep triage on a confirmed vulnerability.
    
Issue Context:
- Suspected Vulnerability: {issue}
- Target Code Snippet: {matched_code}

Full File Context:
```
{code_snippet}
```

Evaluate this issue carefully. Mentally simulate an attacker exploiting it.
Return your analysis as a strict JSON object with exactly these fields:
- 'severity': String (Critical, High, Medium, Low).
- 'explanation': String explaining exactly why it is a risk within this specific codebase.
- 'poc_exploit_scenario': String demonstrating step-by-step how an attacker exploits this. If you cannot prove exploitability, state why it might be a false positive.
- 'remediation': Object with exactly two fields:
    - 'patch': String containing the safest, minimal code alteration to fix it.
    - 'explanation': String explaining the fix.

Return ONLY JSON.
"""
