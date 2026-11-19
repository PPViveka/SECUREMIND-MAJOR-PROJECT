"""
Real SAST (Static Application Security Testing) Scanner
Detects actual security vulnerabilities in source code using pattern matching
"""

import re
from typing import List, Dict, Any


class SASTScanner:
    """Performs real static analysis on source code to find actual vulnerabilities."""
    
    # Define real regex patterns for common vulnerabilities
    VULNERABILITY_PATTERNS = {
        'sql_injection': {
            'severity': 'High',
            'patterns': [
                r'execute\s*\(\s*["\'].*?\$|f["\'].*SELECT.*\{',  # String interpolation in SQL
                r'execute\s*\(\s*query\s*\+',  # String concatenation in execute
                r'execute\s*\(\s*["\']SELECT.*WHERE.*["\']\s*\+',  # SQL + concatenation
                r'query\s*=\s*["\']SELECT.*["\']\s*\+',  # SQL concatenation
                r'\.query\s*\(\s*["\']SELECT.*WHERE["\']\s*\+',  # ORM query concatenation
                r'\|\|\s*[:?][A-Za-z_][A-Za-z0-9_]*',  # SQL concatenation with a bind-style parameter
                r'\bOR\s+["\']?1["\']?\s*=\s*["\']?1["\']?',  # Tautological authorization predicate
            ],
            'issue': 'SQL Injection Vulnerability',
            'explanation': 'SQL query is built by concatenating user input directly into the SQL string.',
        },
        'hardcoded_secret': {
            'severity': 'High',
            'patterns': [
                r'(?:api[_-]?key|password|secret|token|auth[_-]?token)\s*[:=]\s*["\'](?!{|<<)[A-Za-z0-9\-_.]{8,}',  # Actual hardcoded values
                r'(?:api[_-]?key|password|secret|token|auth[_-]?token)\s*[:=]\s*["\'][^"\']{20,}["\']',
                r'(?:api[_-]?key|password|secret|token|auth[_-]?token)\s*:\s*&?str\s*=\s*["\'][^"\']{8,}["\']',  # Typed Rust constants
                r'BEGIN RSA PRIVATE KEY|BEGIN PRIVATE KEY|BEGIN EC PRIVATE KEY',  # Private keys
                r'aws_access_key_id\s*=\s*AKIA[0-9A-Z]{16}',  # AWS keys
                r'github[_-]?token\s*[:=]\s*ghp_[A-Za-z0-9_]{36,}',  # GitHub tokens
            ],
            'issue': 'Hardcoded Secret / Credential Exposure',
            'explanation': 'Sensitive credentials are stored directly in source code and can be extracted.',
        },
        'command_injection': {
            'severity': 'High',
            'patterns': [
                r'subprocess\.(?:run|call|Popen)\s*\(\s*f["\']',  # subprocess with f-string
                r'subprocess\.(?:run|call|Popen)\s*\(\s*["\'].*\+',  # subprocess with concatenation
                r'os\.system\s*\(\s*(?:cmd|command|input|user|f["\'])',  # System calls with variables or f-string
                r'\b(?:std::)?system\s*\(\s*(?:params?\[|cmd|command|input|user)',  # Ruby/C/C++ system calls with user input
                r'std::system\s*\([^)]*\.c_str\s*\(\s*\)\s*\)',  # C++ dynamic shell command
                r'Command::new\s*\([^)]*\)\s*\.arg\s*\(\s*["\']-c["\']\s*\)\s*\.arg\s*\(\s*\w+',  # Rust shell execution
                r'child_process\.(?:exec|execSync|spawn|spawnSync)\s*\(',  # Node.js child_process command execution (FR-109)
                r'shell\s*=\s*True',  # shell=True flag with dynamic input
            ],
            'issue': 'Command Injection / Arbitrary Code Execution',
            'explanation': 'User input is passed to shell/system execution functions without sanitization.',
        },
        'path_traversal': {
            'severity': 'Medium',
            'patterns': [
                r'open\s*\(\s*(?:request\.|user_|input|path|file_path)',  # File open with user input
                r'os\.path\.join\s*\(\s*base_path\s*,\s*(?:request\.|user_|input)',  # Path join with user input
                r'fs::read_to_string\s*\(\s*\w*(?:path|file)',  # Rust file access using a caller-controlled path
                r'fs\.(?:readFileSync|readFile|createReadStream)\s*\(\s*(?:req\.|params\.|query\.|input|\w+\s*\+)',  # Node.js fs file read (FR-109)
            ],
            'issue': 'Path Traversal / Directory Escape',
            'explanation': 'File paths are constructed using unsanitized user input, allowing directory traversal.',
        },
        'insecure_deserialization': {
            'severity': 'High',
            'patterns': [
                r'pickle\.loads?\s*\(',  # Python pickle
                r'yaml\.load\s*\(\s*(?!Loader)',  # YAML without safe loader
                r'(?<!json)\.load\s*\(\s*.*\)',  # Suspicious generic loader; JSON parsing is not inherently unsafe
                r'(?<![a-zA-Z0-9_.])eval\s*\(\s*',  # Direct eval
                r'(?<![a-zA-Z0-9_.])exec\s*\(\s*',  # Direct exec
            ],
            'issue': 'Insecure Deserialization',
            'explanation': 'User input is deserialized without validation, allowing arbitrary code execution.',
        },
        'weak_cryptography': {
            'severity': 'Medium',
            'patterns': [
                r'hashlib\.(?:md5|sha1)\(',  # md5 or sha1 hashing
                r'(?:md5|sha1|MD5|SHA1)\s*\(',  # Weak hashing functions
                r'AES\.MODE_ECB',  # ECB mode (no random IV)
            ],
            'issue': 'Weak Cryptographic Algorithm',
            'explanation': 'Code uses outdated or weak cryptographic algorithms (MD5, SHA1, ECB mode).',
        },
        'authentication_bypass': {
            'severity': 'High',
            'patterns': [
                r'@(?:app|route|api).*\(\s*["\'][^"\']*["\']?\s*\)(?:\s|.*?)def\s+\w+\s*\(.*\):\s*(?:return|pass)',  # Unprotected endpoints
                r'if\s+(?:request\.args\.get|request\.form\.get)\s*\(\s*["\']password|if\s+.*==\s*password',  # Weak auth
                r'jwt\.decode\s*\(\s*.*,\s*verify\s*=\s*False',  # JWT verification disabled
            ],
            'issue': 'Authentication / Authorization Bypass',
            'explanation': 'Authentication checks are missing or can be bypassed.',
        },
        'cors_misconfiguration': {
            'severity': 'Medium',
            'patterns': [
                r'Access-Control-Allow-Origin\s*[:=]\s*["\']?\*["\']?',  # Wildcard CORS header
                r'cors\s*=\s*["\']?\*["\']?|cors:\s*["\']?\*["\']?',  # cors setting with wildcard
                r'allowOrigin\s*=\s*["\']?\*["\']?',  # Allow all origins
                r'CORS_ORIGINS.*=\s*["\']?\*["\']?',  # Dictionary/config with wildcard
                r'cors["\']?\s*=\s*["\']?\*["\']?',  # Flask/Django CORS config
            ],
            'issue': 'Overly Permissive CORS Configuration',
            'explanation': 'CORS is configured to allow any origin, increasing exposure to cross-origin attacks.',
        },
        'unsafe_redirect': {
            'severity': 'Medium',
            'patterns': [
                r'redirect\s*\(\s*(?:request\.|url|user_input|param)',  # Redirect with user input
                r'location\s*[:=]\s*(?:request\.|user_|input)',  # Location header with user input
            ],
            'issue': 'Open Redirect',
            'explanation': 'User input is used for redirects without validation, allowing phishing attacks.',
        },
        'missing_validation': {
            'severity': 'Medium',
            'patterns': [
                r'return\s+(?:request\.|input\(|user_input)',  # Using user input directly
                r'execute\s*\(\s*(?:request\.|user_|input)',  # Executing user input
            ],
            'issue': 'Missing Input Validation',
            'explanation': 'User input is used without proper validation or sanitization.',
        },
        'xss_injection': {
            'severity': 'Medium',
            'patterns': [
                r'\.innerHTML\s*=\s*(?:req\.|params\.|query\.|user_input|\w+\s*\+)',
                r'res\.(?:send|write)\s*\(\s*["\'].*?<[a-zA-Z]+.*?\$\{',
                r'document\.write\s*\(',
            ],
            'issue': 'Cross-Site Scripting (XSS) Vulnerability',
            'explanation': 'Untrusted input is injected directly into the DOM or response HTML without encoding.',
        },
    }

    SAFE_TWINS = {
        'sql_injection': {
            'vulnerable': 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
            'safe': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        },
        'hardcoded_secret': {
            'vulnerable': 'api_key = "sk-1234567890abcdefghijklmnop"',
            'safe': 'api_key = os.environ.get("API_KEY")',
        },
        'command_injection': {
            'vulnerable': 'subprocess.run(f"process {user_input}", shell=True)',
            'safe': 'subprocess.run(["process", user_input], shell=False)',
        },
        'path_traversal': {
            'vulnerable': 'open(request.args.get("file"), "r")',
            'safe': 'filename = secure_filename(request.args.get("file"))\nopen(os.path.join(safe_dir, filename), "r")',
        },
        'insecure_deserialization': {
            'vulnerable': 'data = pickle.loads(untrusted_data)',
            'safe': 'data = json.loads(untrusted_data)',
        },
        'weak_cryptography': {
            'vulnerable': 'hashlib.md5(password.encode()).hexdigest()',
            'safe': 'hashlib.sha256(password.encode()).hexdigest()',
        },
        'authentication_bypass': {
            'vulnerable': 'jwt.decode(token, secret, verify=False)',
            'safe': 'jwt.decode(token, secret, verify=True, algorithms=["HS256"])',
        },
        'cors_misconfiguration': {
            'vulnerable': 'app.config["CORS_ORIGINS"] = "*"',
            'safe': 'app.config["CORS_ORIGINS"] = ["https://trusted.domain.com"]',
        },
        'unsafe_redirect': {
            'vulnerable': 'redirect(request.args.get("url"))',
            'safe': 'if is_safe_url(target): redirect(target)',
        },
        'missing_validation': {
            'vulnerable': 'return request.args.get("data")',
            'safe': 'return sanitize_input(request.args.get("data"))',
        },
    }

    @staticmethod
    def scan_code(code: str, file_path: str = '') -> List[Dict[str, Any]]:
        """
        Scan code for vulnerabilities using real pattern matching.
        Preserves per-occurrence findings across locations.
        
        Args:
            code: Source code to scan
            file_path: Path to the file being scanned
            
        Returns:
            List of found vulnerabilities with per-occurrence details
        """
        findings = []
        code_lower = code.lower()
        lines = code.split('\n')
        seen_line_rule = set()
        
        # Scan for each vulnerability type
        for vuln_type, vuln_config in SASTScanner.RULE_REGISTRY.items():
            for pattern in vuln_config['patterns']:
                try:
                    matches = list(re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE))
                    
                    for match in matches:
                        # Find line number
                        line_num = code[:match.start()].count('\n') + 1
                        dedup_key = (vuln_config['rule_id'], line_num)
                        if dedup_key in seen_line_rule:
                            continue
                        
                        # Get the actual line of code
                        matched_line = lines[line_num - 1] if line_num <= len(lines) else ''
                        matched_stripped = matched_line.strip()

                        # --- False positive qualification filters ---
                        # 1. json.loads and json.load are safe
                        if 'json.loads' in matched_stripped or 'json.load' in matched_stripped:
                            continue

                        # 2. Generic .load: ignore safe loaders or non-deserialization loaders
                        if vuln_type == 'insecure_deserialization' and '.load(' in matched_stripped:
                            if any(safe in matched_stripped for safe in ['json.', 'Loader=SafeLoader', 'SafeLoader', 'torch.load']):
                                continue

                        # 3. random.choice: only flag if key/secret/password generation
                        if vuln_type == 'weak_cryptography' and 'random.choice' in matched_stripped:
                            if not any(k in matched_stripped.lower() for k in ['key', 'secret', 'password', 'token', 'auth', 'credential']):
                                continue

                        # 4. ../ strings: ignore static literals or docpaths not fed into open/join
                        if vuln_type == 'path_traversal':
                            if not any(sink in matched_stripped for sink in ['open', 'os.path', 'pathlib', 'read', 'write', 'join', 'send_file', 'File']):
                                continue
                            if 'open' in matched_stripped and ('"../' in matched_stripped or "'../" in matched_stripped):
                                if re.match(r'open\s*\(\s*["\'][^"\']+["\']\s*[,)]', matched_stripped):
                                    continue

                        # 5. Generic eval: ignore constant literals (e.g. eval("1+1"), eval("{}"))
                        if vuln_type == 'insecure_deserialization' and 'eval(' in matched_stripped:
                            const_eval_match = re.search(r'eval\s*\(\s*["\']([^"\']*)["\']\s*\)', matched_stripped)
                            if const_eval_match:
                                inner_expr = const_eval_match.group(1)
                                if not any(op in inner_expr for op in ['__', 'import', 'system', 'exec', 'subprocess', 'open']):
                                    continue

                        seen_line_rule.add(dedup_key)
                        cand_id = f"cand-{vuln_type}-{line_num}-{len(findings) + 1}"
                        
                        finding = {
                            'rule_id': vuln_config['rule_id'],
                            'cwe_id': vuln_config['cwe_id'],
                            'candidate_id': cand_id,
                            'confidence': vuln_config['confidence'],
                            'languages': vuln_config['languages'],
                            'severity': vuln_config['severity'],
                            'issue': vuln_config['issue'],
                            'type': vuln_type,
                            'file': file_path,
                            'line': line_num,
                            'endLine': line_num,
                            'matched_code': matched_stripped[:100],
                            'explanation': vuln_config['explanation'],
                            'attack_vector': SASTScanner._get_attack_vector(vuln_type),
                            'poc_exploit_scenario': SASTScanner._get_poc(vuln_type),
                            'remediation': SASTScanner._get_remediation(vuln_type),
                            'suggested_fix': SASTScanner._get_fix_suggestion(vuln_type),
                            'file_references': [{
                                'file': file_path,
                                'line': line_num,
                                'endLine': line_num,
                                'matched_code': matched_stripped[:100],
                            }],
                            'file_count': 1,
                        }
                        findings.append(finding)
                        
                except re.error:
                    continue
        
        return findings

    @staticmethod
    def _get_attack_vector(vuln_type: str) -> str:
        """Get attack vector description for vulnerability type."""
        vectors = {
            'sql_injection': 'External input: User-supplied query parameters, form data, or URL arguments.',
            'hardcoded_secret': 'Code repository access: Git history, code review, or accidental exposure.',
            'command_injection': 'External input: Shell metacharacters in user-supplied arguments.',
            'path_traversal': 'External input: File path parameters with directory traversal sequences (../).',
            'insecure_deserialization': 'Untrusted data: Serialized objects from network or user input.',
            'weak_cryptography': 'Brute force or cryptanalysis: Legacy algorithms are computationally breakable.',
            'authentication_bypass': 'Missing authentication: Direct endpoint access without credentials.',
            'cors_misconfiguration': 'Cross-origin requests: Any website can make authenticated requests.',
            'unsafe_redirect': 'Open redirect: Links to user-supplied URLs without validation.',
            'missing_validation': 'Malicious input: Unsanitized user data used in sensitive operations.',
        }
        return vectors.get(vuln_type, 'External input')

    @staticmethod
    def _get_poc(vuln_type: str) -> str:
        """Get proof-of-concept scenario for vulnerability type."""
        pocs = {
            'sql_injection': "Admin login bypass: Supply user_id as '1 OR 1=1' to authenticate without password.",
            'hardcoded_secret': 'Credential reuse: Extract API key from GitHub and use it to access production systems.',
            'command_injection': 'Remote code execution: Execute shell commands like `; rm -rf /; ` via input parameter.',
            'path_traversal': 'Read sensitive files: Access /etc/passwd via file=../../etc/passwd.',
            'insecure_deserialization': 'Code execution: Craft malicious serialized object to execute arbitrary Python code.',
            'weak_cryptography': 'Hash cracking: Brute-force MD5 password hashes from public wordlists in seconds.',
            'authentication_bypass': 'Unauthorized access: Call protected endpoints without authentication token.',
            'cors_misconfiguration': 'Session hijacking: Malicious website triggers authenticated requests to steal data.',
            'unsafe_redirect': 'Phishing: Redirect user to fake login page that looks like the real service.',
            'missing_validation': 'Data corruption: Submit malformed input that breaks application logic.',
        }
        return pocs.get(vuln_type, 'Attacker exploits this vulnerability.')

    @staticmethod
    def _get_remediation(vuln_type: str) -> Dict[str, str]:
        """Get code remediation example for vulnerability type."""
        remediations = {
            'sql_injection': {
                'patch': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                'explanation': 'Use parameterized queries. Placeholders (?) prevent input from altering SQL structure.',
            },
            'hardcoded_secret': {
                'patch': 'api_key = os.getenv("API_KEY")\nif not api_key:\n    raise ValueError("Missing API_KEY env var")',
                'explanation': 'Load secrets from environment variables, not source code. Use secret managers for production.',
            },
            'command_injection': {
                'patch': 'subprocess.run(["command", arg1, arg2], check=True)',
                'explanation': 'Pass arguments as a list, not as shell string. This prevents shell interpretation.',
            },
            'path_traversal': {
                'patch': 'safe_path = os.path.normpath(os.path.join(base_dir, user_file))\nif not safe_path.startswith(base_dir):\n    raise ValueError("Invalid path")',
                'explanation': 'Validate and normalize paths. Ensure file access stays within allowed directory.',
            },
            'insecure_deserialization': {
                'patch': 'data = yaml.safe_load(user_input)\nobj = json.loads(user_input)',
                'explanation': 'Use safe deserialization methods. Never use pickle or eval on untrusted data.',
            },
            'weak_cryptography': {
                'patch': 'import hashlib\nhash_obj = hashlib.sha256(password.encode())\nfrom cryptography.fernet import Fernet',
                'explanation': 'Use SHA256+ for hashing and modern algorithms (AES-GCM, ChaCha20) for encryption.',
            },
            'authentication_bypass': {
                'patch': '@app.route("/secure")\n@require_auth\ndef secure_endpoint():\n    return "Authenticated"',
                'explanation': 'Add authentication decorators or middleware. Validate tokens on every protected request.',
            },
            'cors_misconfiguration': {
                'patch': 'Access-Control-Allow-Origin: https://trusted-app.example.com\nAccess-Control-Allow-Credentials: true',
                'explanation': 'Specify explicit allowed origins. Never use wildcard with credentials.',
            },
            'unsafe_redirect': {
                'patch': 'allowed_domains = {"example.com", "trusted.com"}\nif urllib.parse.urlparse(redirect_url).netloc not in allowed_domains:\n    return error("Invalid redirect")',
                'explanation': 'Whitelist allowed redirect destinations. Validate before redirecting.',
            },
            'missing_validation': {
                'patch': 'if not user_input or not isinstance(user_input, str):\n    raise ValueError("Invalid input")\nif len(user_input) > 100:\n    raise ValueError("Input too long")',
                'explanation': 'Validate all user input: type, length, format, and content. Use allowlists when possible.',
            },
        }
        return remediations.get(vuln_type, {'patch': '', 'explanation': ''})

    @staticmethod
    def _get_fix_suggestion(vuln_type: str) -> str:
        """Get actionable fix suggestion for vulnerability type."""
        suggestions = {
            'sql_injection': 'Replace all string concatenation in SQL queries with parameterized queries (? placeholders).',
            'hardcoded_secret': 'Remove this credential from code. Rotate the exposed key immediately. Use environment variables.',
            'command_injection': 'Convert shell command string to list format: ["command", "arg1", "arg2"].',
            'path_traversal': 'Normalize file paths and ensure they do not escape the base directory using os.path.normpath().',
            'insecure_deserialization': 'Replace pickle with json. Use yaml.safe_load() instead of yaml.load().',
            'weak_cryptography': 'Switch to SHA256/SHA512 for hashing. Use AES-GCM or ChaCha20 for encryption.',
            'authentication_bypass': 'Add authentication middleware/decorators to all protected endpoints.',
            'cors_misconfiguration': 'Replace wildcard (*) with explicit domain list: ["https://app.example.com"].',
            'unsafe_redirect': 'Whitelist allowed redirect URLs and validate before redirecting.',
            'missing_validation': 'Add input validation: type checks, length limits, and format validation.',
        }
        return suggestions.get(vuln_type, 'Review and fix this security issue.')

    def scan(self, code: str, file_path: str = '<input>') -> List[Dict[str, Any]]:
        """Instance alias for scan_code."""
        return self.scan_code(code, file_path=file_path)


_RULE_CWES = {
    'sql_injection': 'CWE-89',
    'hardcoded_secret': 'CWE-798',
    'command_injection': 'CWE-78',
    'path_traversal': 'CWE-22',
    'insecure_deserialization': 'CWE-502',
    'weak_cryptography': 'CWE-327',
    'authentication_bypass': 'CWE-287',
    'cors_misconfiguration': 'CWE-942',
    'unsafe_redirect': 'CWE-601',
    'missing_validation': 'CWE-20',
}

SASTScanner.RULE_VERSION = 'rules-v1'
SASTScanner.RULE_REGISTRY = {
    rule_type: {
        **config,
        'rule_id': f'SA-{rule_type.upper()}',
        'cwe_id': _RULE_CWES.get(rule_type),
        'languages': ['python', 'javascript', 'typescript', 'java', 'ruby', 'rust', 'sql', 'c', 'cpp', 'csharp', 'go', 'kotlin', 'php', 'swift'],
        'confidence': 'medium',
    }
    for rule_type, config in SASTScanner.VULNERABILITY_PATTERNS.items()
}
