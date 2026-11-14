import json
import os
import hmac
import hashlib
import re
import time
import requests
from dotenv import load_dotenv
import boto3
from .prompt_builder import build_security_prompt
from .github_commenter import post_pr_review
from .function_cache import SelectiveFunctionScanner
from .cascade_engine import CascadeEngine
from .sandbox_verifier import apply_verification_gate, SandboxVerifier

load_dotenv()

# try:
#     import google.generativeai as genai
# except Exception:
#     genai = None

from .prompt_builder import build_security_prompt
from .github_commenter import post_pr_review
from .attack_intelligence import build_attack_intelligence, build_copilot_prompt
from .repo_selective_scan import selective_repo_scan
from .sast_scanner import SASTScanner
from .autofix_engine import start_autofix_job
from .autofix_prompt import build_autofix_prompt

load_dotenv()

# Pick up Gemini Key from `.env`
# gemini_api_key = os.getenv('GEMINI_API_KEY')
nvidia_api_key = os.getenv('NVIDIA_API_KEY')
nvidia_model = os.getenv('NVIDIA_MODEL', 'meta/llama3-8b-instruct')
# Initialize Bedrock client
# In Lambda, boto3 natively picks up credentials and region from the IAM role.
# For local testing, it will pick up from the environment variables (.env).
# bedrock = boto3.client(
#     service_name='bedrock-runtime',
#     region_name=os.getenv('AWS_REGION', 'us-east-1')
# )

def _is_truthy(value):
    return str(value or '').strip().lower() in {'1', 'true', 'yes', 'on'}


def _get_model_provider():
    explicit = (os.getenv('MODEL_PROVIDER') or '').strip().lower()
    has_nvidia = bool(os.getenv('NVIDIA_API_KEY'))
    has_gemini = bool(os.getenv('GEMINI_API_KEY'))
    if explicit in {'nvidia', 'gemini', 'bedrock'}:
        return explicit
    if has_nvidia:
        return 'nvidia'
    return 'gemini' if has_gemini else 'bedrock'


# def _gemini_model_candidates():
#     configured = (os.getenv('GEMINI_MODEL') or '').strip()
#     preferred = [
#         'gemini-1.5-flash',
#         'gemini-2.5-flash',
#         'gemini-2.0-flash',
#         'gemini-2.0-flash-lite',
#     ]
# 
#     candidates = []
#     if configured:
#         candidates.append(configured)
# 
#     for name in preferred:
#         if name not in candidates:
#             candidates.append(name)
# 
#     return candidates


# def _extract_gemini_text(response):
#     try:
#         text = (getattr(response, 'text', '') or '').strip()
#         if text:
#             return text
#     except Exception:
#         pass
# 
#     chunks = []
#     candidates = getattr(response, 'candidates', None) or []
#     for candidate in candidates:
#         content = getattr(candidate, 'content', None)
#         parts = getattr(content, 'parts', None) if content else None
#         if not parts:
#             continue
#         for part in parts:
#             t = getattr(part, 'text', None)
#             if t:
#                 chunks.append(t)
# 
#     return '\n'.join(chunks).strip()


def _parse_json_from_text(text):
    if not text:
        raise json.JSONDecodeError('Empty text', '', 0)

    # Step 0: Strip markdown fences
    clean = text.replace('```json', '').replace('```', '').strip()

    # Step 1: Try direct parse (fastest path)
    for attempt in [clean, text]:
        try:
            return json.loads(attempt)
        except json.JSONDecodeError:
            pass

    # Step 2: Use raw_decode to handle "Extra data" — extracts first valid JSON
    decoder = json.JSONDecoder()
    for attempt in [clean, text]:
        for start_char in ['{', '[']:
            idx = attempt.find(start_char)
            if idx != -1:
                try:
                    result, _ = decoder.raw_decode(attempt, idx)
                    return result
                except json.JSONDecodeError:
                    pass

    # Step 3: Aggressive bracket matching (handles truncated JSON from token limits)
    first_obj = clean.find('{')
    last_obj = clean.rfind('}')
    if first_obj != -1 and last_obj != -1 and last_obj > first_obj:
        try:
            return json.loads(clean[first_obj:last_obj + 1])
        except json.JSONDecodeError:
            pass

    first_arr = clean.find('[')
    last_arr = clean.rfind(']')
    if first_arr != -1 and last_arr != -1 and last_arr > first_arr:
        try:
            return json.loads(clean[first_arr:last_arr + 1])
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError('Could not extract valid JSON from AI response', text, 0)


# def _repair_json_with_gemini(raw_text, max_tokens):
#     repair_prompt = (
#         'Return only valid JSON. Preserve original meaning and fields. '
#         'Do not add markdown fences.\n\n'
#         f'{raw_text}'
#     )
# 
#     last_error = None
#     for model_name in _gemini_model_candidates():
#         try:
#             model = genai.GenerativeModel(model_name=model_name)
#             response = model.generate_content(
#                 repair_prompt,
#                 generation_config={
#                     'max_output_tokens': max_tokens,
#                     'response_mime_type': 'application/json',
#                     'temperature': 0,
#                 },
#             )
#             repaired = _extract_gemini_text(response)
#             return _parse_json_from_text(repaired)
#         except Exception as exc:
#             last_error = exc
# 
#     raise RuntimeError(str(last_error) if last_error else 'Gemini JSON repair failed')


def _get_bedrock_client():
    # In Lambda, boto3 picks credentials/region from IAM role.
    # For local, it picks from environment variables.
    return boto3.client(
        service_name='bedrock-runtime',
        region_name=os.getenv('AWS_REGION', 'us-east-1')
    )


# def _invoke_gemini_json(prompt, max_tokens=600):
#     if genai is None:
#         raise RuntimeError('google-generativeai dependency is not installed')
# 
#     api_key = os.getenv('GEMINI_API_KEY', '').strip()
#     if not api_key:
#         raise RuntimeError('GEMINI_API_KEY is missing')
# 
#     genai.configure(api_key=api_key)
# 
#     response = None
#     last_error = None
#     for model_name in _gemini_model_candidates():
#         try:
#             model = genai.GenerativeModel(model_name=model_name)
#             response = model.generate_content(
#                 prompt,
#                 generation_config={
#                     'max_output_tokens': max_tokens,
#                     'response_mime_type': 'application/json',
#                     'temperature': 0.0,
#                 },
#             )
#             break
#         except Exception as exc:
#             last_error = exc
# 
#     if response is None:
#         raise RuntimeError(str(last_error) if last_error else 'Gemini model invocation failed')
# 
#     text = _extract_gemini_text(response)
#     if not text:
#         raise RuntimeError('Gemini returned empty response')
# 
#     try:
#         return _parse_json_from_text(text)
#     except json.JSONDecodeError:
#         return _repair_json_with_gemini(text, max_tokens=max_tokens)


# def _invoke_gemini_text(prompt, max_tokens=1200):
#     if genai is None:
#         raise RuntimeError('google-generativeai dependency is not installed')
# 
#     api_key = os.getenv('GEMINI_API_KEY', '').strip()
#     if not api_key:
#         raise RuntimeError('GEMINI_API_KEY is missing')
# 
#     genai.configure(api_key=api_key)
# 
#     response = None
#     last_error = None
#     for model_name in _gemini_model_candidates():
#         try:
#             model = genai.GenerativeModel(model_name=model_name)
#             response = model.generate_content(
#                 prompt,
#                 generation_config={
#                     'max_output_tokens': max_tokens,
#                     'temperature': 0.1,
#                 },
#             )
#             break
#         except Exception as exc:
#             last_error = exc
# 
#     if response is None:
#         raise RuntimeError(str(last_error) if last_error else 'Gemini model invocation failed')
#     text = _extract_gemini_text(response)
#     if not text:
#         raise RuntimeError('Gemini returned empty response')
#     return text


def _json_response(status_code, payload):
    return {
        "statusCode": status_code,
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": True,
        },
        "body": json.dumps(payload),
    }


def _parse_body(event):
    body_str = event.get('body', '{}')
    if not body_str:
        body_str = '{}'
    return json.loads(body_str) if isinstance(body_str, str) else body_str


def _invoke_bedrock_json(prompt, max_tokens=600):
    request_body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}]
            }
        ]
    })

    bedrock = _get_bedrock_client()
    bedrock_response = bedrock.invoke_model(
        modelId='us.anthropic.claude-sonnet-4-5-20250929-v1:0',
        contentType='application/json',
        accept='application/json',
        body=request_body
    )
    response_body = json.loads(bedrock_response['body'].read())
    content_items = response_body.get('content') or []
    first_item = content_items[0] if isinstance(content_items, list) and content_items else {}
    content = first_item.get('text', '{}') if isinstance(first_item, dict) else '{}'

    try:
        return json.loads(content)
    except json.JSONDecodeError:
        clean_text = content.replace("```json", "").replace("```", "").strip()
        return json.loads(clean_text)


def _invoke_bedrock_text(prompt, max_tokens=1200):
    request_body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": max_tokens,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": prompt}]
            }
        ]
    })

    bedrock = _get_bedrock_client()
    bedrock_response = bedrock.invoke_model(
        modelId='us.anthropic.claude-sonnet-4-5-20250929-v1:0',
        contentType='application/json',
        accept='application/json',
        body=request_body
    )
    response_body = json.loads(bedrock_response['body'].read())
    content_items = response_body.get('content') or []
    first_item = content_items[0] if isinstance(content_items, list) and content_items else {}
    text = first_item.get('text', '') if isinstance(first_item, dict) else ''
    return text.strip()


def _invoke_nvidia_json(prompt, max_tokens=2000):
    if not nvidia_api_key:
        raise RuntimeError('NVIDIA_API_KEY is missing')

    headers = {
        "Authorization": f"Bearer {nvidia_api_key}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    payload = {
        "model": nvidia_model,
        "messages": [
            {"role": "system", "content": "You are a strict SageArmor API that ONLY outputs perfectly valid JSON. No conversation, no markdown fences, no preamble."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": max_tokens,
        "temperature": 0,
        "top_p": 0.7,
        "seed": 42
    }
    
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code != 200:
        raise RuntimeError(f"NVIDIA API request failed: {response.status_code} - {response.text}")
    
    result = response.json()
    text = result['choices'][0]['message']['content']
    return _parse_json_from_text(text)


def _invoke_nvidia_text(prompt, max_tokens=2000):
    if not nvidia_api_key:
        raise RuntimeError('NVIDIA_API_KEY is missing')

    headers = {
        "Authorization": f"Bearer {nvidia_api_key}",
        "Content-Type": "application/json",
        "accept": "application/json"
    }
    
    payload = {
        "model": nvidia_model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.2
    }
    
    url = "https://integrate.api.nvidia.com/v1/chat/completions"
    response = requests.post(url, headers=headers, json=payload)
    
    if response.status_code != 200:
        raise RuntimeError(f"NVIDIA API request failed: {response.status_code} - {response.text}")
    
    result = response.json()
    return result['choices'][0]['message']['content'].strip()


def _invoke_model_json(prompt, max_tokens=600):
    provider = _get_model_provider()
    if provider == 'nvidia':
        return _invoke_nvidia_json(prompt, max_tokens=max_tokens)
    # elif provider == 'gemini':
    #     return _invoke_gemini_json(prompt, max_tokens=max_tokens)
    return _invoke_bedrock_json(prompt, max_tokens=max_tokens)


def _invoke_model_text(prompt, max_tokens=1200):
    provider = _get_model_provider()
    if provider == 'nvidia':
        return _invoke_nvidia_text(prompt, max_tokens=max_tokens)
    # elif provider == 'gemini':
    #     return _invoke_gemini_text(prompt, max_tokens=max_tokens)
    return _invoke_bedrock_text(prompt, max_tokens=max_tokens)


def _local_static_review(code_snippet):
    """Use real SAST scanner instead of mock findings."""
    text = code_snippet or ''
    
    # Use real SAST scanner to detect actual vulnerabilities
    sast_findings = SASTScanner.scan_code(text, file_path='<input>')
    
    # Convert SAST findings to the expected response format
    vulnerabilities = []
    for finding in sast_findings:
        vulnerabilities.append({
            'severity': finding['severity'],
            'issue': finding['issue'],
            'attack_vector': finding['attack_vector'],
            'explanation': finding['explanation'],
            'poc_exploit_scenario': finding['poc_exploit_scenario'],
            'remediation': finding['remediation'],
            'suggested_fix': finding['suggested_fix'],
            'matched_code': finding.get('matched_code', ''),
            'line': finding.get('line', 0),
        })
    
    return {
        'vulnerabilities': vulnerabilities,
        'analysis_mode': 'sast-local',
        'note': 'Real static analysis performed; pattern-based vulnerability detection.',
    }



def _local_copilot_answer(question, intelligence, vulnerabilities=None):
    risk_ranking = intelligence.get('risk_ranking', []) if isinstance(intelligence, dict) else []
    vulnerabilities = vulnerabilities if isinstance(vulnerabilities, list) else []
    q = (question or '').lower()

    def _match_vuln(issue_name):
        target = (issue_name or '').strip().lower()
        for vuln in vulnerabilities:
            if str(vuln.get('issue', '')).strip().lower() == target:
                return vuln
        return vulnerabilities[0] if vulnerabilities else {}

    if risk_ranking:
        target_index = 0
        import re
        match = re.search(r'(\d+)(?:st|nd|rd|th)?|first|second|third|fourth|fifth', q)
        if match:
            group = match.group(0).lower()
            word_to_num = {'first': 0, 'second': 1, 'third': 2, 'fourth': 3, 'fifth': 4}
            if group in word_to_num:
                target_index = word_to_num[group]
            else:
                num = ''.join(filter(str.isdigit, group))
                if num:
                    target_index = int(num) - 1

        target_index = max(0, min(target_index, len(risk_ranking) - 1))
        top = risk_ranking[target_index]
        
        issue = top.get('issue', 'unknown issue')
        score = top.get('priority_score', 'n/a')
        severity = top.get('severity', 'Unknown')
        exploit = top.get('exploitability', {}).get('level', 'Unknown')
        matched_vuln = _match_vuln(issue)
        patch = (
            matched_vuln.get('remediation', {}).get('patch')
            or matched_vuln.get('suggested_fix')
            or 'Apply the remediation patch shown in Findings and re-run scan.'
        )
        reason = matched_vuln.get('explanation') or 'This issue has a high combined risk score in the current context.'

        if 'fix' in q or 'what should i' in q or 'priority' in q:
            prefix = "Fix this first" if target_index == 0 else "For this issue"
            return (
                f"{prefix}: {issue}.\n"
                f"Why: severity {severity}, exploitability {exploit}, priority score {score}/10.\n"
                f"Action: {patch}\n"
                "Then re-run scan and move to the next highest ranked issue in the Risk Panel."
            )

        if 'why' in q or 'risk' in q or 'explain' in q:
            return (
                f"{issue} is a significant risk because it combines {severity} severity with {exploit} exploitability (score {score}/10).\n"
                f"Why it matters: {reason}\n"
                f"Next fix action: {patch}"
            )

        return (
            f"Regarding '{issue}' (severity: {severity}, exploitability: {exploit}, priority score: {score}/10). "
            f"Recommended next action: {patch}"
        )

    return (
        "No high-confidence exploitable issue was ranked in local fallback mode. "
        "Next action: review Findings, patch obvious input validation and secret-handling issues, and re-run scan. "
        "For deeper context, enable model-powered analysis."
    )


def _extract_vulnerabilities_for_advanced(body):
    vulnerabilities = body.get('vulnerabilities')
    if isinstance(vulnerabilities, list):
        return vulnerabilities

    code_snippet = body.get('code', '')
    language = body.get('language', 'python')
    if not code_snippet:
        return []

    prompt = build_security_prompt(code_snippet, language)
    try:
        analysis_result = _invoke_model_json(prompt)
    except Exception as err:
        print(f"[handler] Advanced endpoints using local fallback: {str(err)}")
        analysis_result = _local_static_review(code_snippet)
    
    if isinstance(analysis_result, list):
        return analysis_result
    return analysis_result.get('vulnerabilities', []) if isinstance(analysis_result, dict) else []

def verify_signature(event):
    secret = os.getenv('GITHUB_WEBHOOK_SECRET')
    if not secret:
        return True # Skip if not configured
    
    headers = {k.lower(): v for k, v in event.get('headers', {}).items()}
    signature = headers.get('x-hub-signature-256')
    if not signature:
        return True # Skip if not present
    
    body = event.get('body', '{}')
    
    # Needs the raw byte string.
    mac = hmac.new(secret.encode('utf-8'), body.encode('utf-8'), hashlib.sha256)
    expected_sig = "sha256=" + mac.hexdigest()
    
    return hmac.compare_digest(expected_sig, signature)

def review_code(event, context):
    try:
        # Validate webhook if signature is present
        if not verify_signature(event):
            return {"statusCode": 401, "headers": {"Access-Control-Allow-Origin": "*"}, "body": json.dumps({"error": "Invalid GitHub webhook signature"})}

        # Load the body
        body_str = event.get('body', '{}')
        if not body_str:
            body_str = '{}'
        body = json.loads(body_str) if isinstance(body_str, str) else body_str
        # Determine language context from dashboard toggle or fallback 
        language = body.get('language', 'python')
        is_webhook = 'pull_request' in body
        
        # 1. Check if it's a GitHub Webhook event
        if 'pull_request' in body:
            action = body.get('action')
            if action and action not in ['opened', 'synchronize']:
                return {"statusCode": 200, "headers": {"Access-Control-Allow-Origin": "*"}, "body": json.dumps({"msg": f"Skipping action {action}"})}
            
            diff_url = body['pull_request']['diff_url']
            headers = {}
            if os.getenv('GITHUB_TOKEN'):
                headers['Authorization'] = f"token {os.getenv('GITHUB_TOKEN')}"
                
            resp = requests.get(diff_url, headers=headers)
            if resp.status_code != 200:
                raise Exception(f"Failed to fetch PR diff: {resp.status_code}")
                
            code_snippet = resp.text
            
            # Enhanced heuristic for Cloud Configuration Analysis (Code + Config)
            has_cloud = any(ext in code_snippet for ext in ['.tf', '.yml', '.yaml', 'serverless', 'dockerfile'])
            has_code = any(ext in code_snippet for ext in ['.py', '.js', '.ts', '.go', '.java'])
            
            if has_cloud and has_code:
                language = 'mixed'
            elif has_cloud:
                language = 'terraform'
            elif '.js' in code_snippet or '.ts' in code_snippet:
                language = 'javascript'

            # Store PR metadata for auto-commenting after analysis
            repo_full_name = body.get('repository', {}).get('full_name', '')
            pr_number = body['pull_request'].get('number')
                
        else:
            # 2. Direct code snippet testing (from Frontend Dashboard)
            code_snippet = body.get('code', '')
            repo_full_name = None
            pr_number = None
            
        if not code_snippet:
            return {"statusCode": 400, "headers": {"Access-Control-Allow-Origin": "*"}, "body": json.dumps({"error": "No code snippet provided."})}

        # Step 1: Function slicing & fingerprint caching
        selective_scanner = SelectiveFunctionScanner()
        partition = selective_scanner.partition_functions(code_snippet, language=language)

        cached_vulns = partition.get("cached_vulnerabilities", [])
        funcs_to_scan = partition.get("functions_to_scan", [])
        telemetry = {
            "total_functions": partition.get("total_functions", 0),
            "cache_hits": partition.get("cache_hits", 0),
            "cache_misses": partition.get("cache_misses", 0),
            "tokens_saved": partition.get("tokens_saved", 0),
            "partition_time_ms": partition.get("partition_time_ms", 0.0),
        }

        # If everything is already cached, reuse cached findings directly
        if partition.get("total_functions", 0) > 0 and len(funcs_to_scan) == 0:
            analysis_result = {
                "vulnerabilities": cached_vulns,
                "analysis_mode": "cached",
                "telemetry": telemetry,
            }
        else:
            # Step 2: Deterministic Fast-First Cascade (Cheap check first, AI second)
            cascade = CascadeEngine(cache=selective_scanner.cache)
            triage = cascade.filter_and_triage(funcs_to_scan)
            flagged_functions = triage.get("flagged_functions", [])
            clean_functions = triage.get("clean_functions", [])

            telemetry["cascade_clean_functions"] = len(clean_functions)
            telemetry["cascade_flagged_functions"] = len(flagged_functions)

            # If all newly submitted functions are clean (no SAST match, no dangerous sinks)
            if len(flagged_functions) == 0 and partition.get("total_functions", 0) > 0:
                analysis_result = {
                    "vulnerabilities": cached_vulns,
                    "analysis_mode": "cascade-clean" if not cached_vulns else "cached",
                    "telemetry": telemetry,
                    "note": f"Classified {len(clean_functions)} functions as safe without invoking LLM.",
                }
            else:
                # LLM is invoked only for the flagged functions
                if flagged_functions and partition.get("total_functions", 0) > 0:
                    targeted_code = CascadeEngine.build_targeted_prompt_context(flagged_functions, full_code=code_snippet)
                else:
                    targeted_code = code_snippet

                prompt = build_security_prompt(targeted_code, language)
                start_scan_time = time.time()
                scan_mode = "model"

                # Call AI model using unified invoker
                try:
                    analysis_result = _invoke_model_json(prompt, max_tokens=2048)
                except Exception as e:
                    print(f"[handler] AI invocation failed, using local fallback: {str(e)}")
                    analysis_result = _local_static_review(code_snippet)
                    scan_mode = analysis_result.get("analysis_mode", "sast-local")

                # Normalize: Llama 3 may return a bare array or a dict with 'vulnerabilities' key
                if isinstance(analysis_result, list):
                    analysis_result = {'vulnerabilities': analysis_result}
                elif isinstance(analysis_result, dict) and 'vulnerabilities' not in analysis_result:
                    # Could be a single vuln object or malformed — wrap it
                    analysis_result = {'vulnerabilities': [analysis_result] if analysis_result else []}

                analysis_result.setdefault("analysis_mode", scan_mode)
                scan_duration_ms = round((time.time() - start_scan_time) * 1000, 2)
                new_vulns = analysis_result.get('vulnerabilities', [])

                # Ensure SAST findings from triage are included as ground-truth anchor
                for f_entry in flagged_functions:
                    for sf in f_entry.get("sast_findings", []):
                        if not any(v.get("line") == sf.get("line") for v in new_vulns):
                            new_vulns.append(sf)

                # Step 3: Dynamic Sandbox Exploit Gate (Prove it's real)
                verified_count = 0
                unconfirmed_count = 0
                verified_vulns_all = []

                # Verify each flagged function in sandbox with execution tracing
                for func in flagged_functions:
                    func_vulns = [
                        v for v in new_vulns
                        if func.get("start_line", 1) <= v.get("line", 0) <= func.get("end_line", 999999)
                    ]
                    if func_vulns:
                        func_vulns = apply_verification_gate(
                            vulnerabilities=func_vulns,
                            function_code=func["code"],
                            function_name=func["name"],
                        )
                        for fv in func_vulns:
                            if fv.get("verified"):
                                verified_count += 1
                            else:
                                unconfirmed_count += 1
                        verified_vulns_all.extend(func_vulns)

                    selective_scanner.cache.set(
                        function_hash=func["hash"],
                        function_name=func["name"],
                        language=language,
                        scan_result={"vulnerabilities": func_vulns},
                        original_start_line=func["start_line"],
                        tokens_used=150 if scan_mode == "model" else 0,
                        scan_duration_ms=scan_duration_ms,
                        provider=scan_mode,
                    )

                # Catch any findings outside partitioned functions
                for v in new_vulns:
                    if not any(vf.get('issue') == v.get('issue') and vf.get('line') == v.get('line') for vf in verified_vulns_all):
                        verified_vulns_all.append(v)

                telemetry["verified_findings"] = verified_count
                telemetry["unconfirmed_findings"] = unconfirmed_count

                # Combine any cached findings with new findings
                combined_vulns = list(cached_vulns)
                for v in verified_vulns_all:
                    if not any(cv.get('issue') == v.get('issue') and cv.get('line') == v.get('line') for cv in combined_vulns):
                        combined_vulns.append(v)

                # Verified findings rank before unconfirmed findings
                combined_vulns.sort(key=lambda x: (0 if x.get("verified") else 1))

                analysis_result['vulnerabilities'] = combined_vulns
                analysis_result['telemetry'] = telemetry

        # Fire-and-forget: post findings back to GitHub PR (webhook path only)
        if is_webhook and repo_full_name and pr_number:
            try:
                post_pr_review(
                    repo_full_name,
                    pr_number,
                    analysis_result.get('vulnerabilities', [])
                )
            except Exception as comment_err:
                # Never block the response if commenting fails
                print(f"[handler] PR comment failed (non-fatal): {str(comment_err)}")

        return _json_response(200, analysis_result)
    except Exception as e:
        print(f"review_code error: {str(e)}")
        import traceback
        traceback.print_exc()
        return _json_response(500, {"error": str(e)})


def attack_path(event, context):
    try:
        body = _parse_body(event)
        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        if not vulnerabilities:
            return _json_response(400, {"error": "No vulnerabilities or code provided for attack path generation"})

        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)
        graph = intelligence.get('attack_graph', {})
        return _json_response(200, {
            "attack_graph": {
                "nodes": graph.get('nodes', []),
                "edges": graph.get('edges', []),
            },
            "attack_paths": graph.get('attack_paths', []),
            "summary": intelligence.get('summary', {}),
        })
    except Exception as e:
        print(f"attack_path error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def risk_score(event, context):
    try:
        body = _parse_body(event)
        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        if not vulnerabilities:
            return _json_response(400, {"error": "No vulnerabilities or code provided for risk scoring"})

        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)
        return _json_response(200, {
            "risk_ranking": intelligence.get('risk_ranking', []),
            "summary": intelligence.get('summary', {}),
        })
    except Exception as e:
        print(f"risk_score error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def simulate(event, context):
    try:
        body = _parse_body(event)
        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        if not vulnerabilities:
            return _json_response(400, {"error": "No vulnerabilities or code provided for simulation"})

        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)
        return _json_response(200, {
            "breach_simulation": intelligence.get('breach_simulation', {}),
            "summary": intelligence.get('summary', {}),
        })
    except Exception as e:
        print(f"simulate error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def copilot_chat(event, context):
    try:
        body = _parse_body(event)
        question = body.get('question', '')
        if not question:
            return _json_response(400, {"error": "No question provided"})

        vulnerabilities = _extract_vulnerabilities_for_advanced(body)
        context_text = body.get('code', '')
        intelligence = build_attack_intelligence(vulnerabilities, context_text)

        prompt = build_copilot_prompt(question, intelligence)
        try:
            answer = _invoke_model_text(prompt)
            mode = "model"
            note = None
        except Exception as err:
            print(f"[handler] Copilot using local fallback: {str(err)}")
            answer = _local_copilot_answer(question, intelligence, vulnerabilities)
            mode = "local-fallback"
            note = "Model-powered copilot unavailable; returned local fallback explanation."

        payload = {
            "answer": answer,
            "summary": intelligence.get('summary', {}),
            "analysis_mode": mode,
        }
        if note:
            payload["note"] = note

        return _json_response(200, payload)
    except Exception as e:
        print(f"copilot_chat error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def repo_scan(event, context):
    """Synchronous repo scan for direct API clients and integration tests."""
    try:
        body = _parse_body(event)
        repo_url = (body.get('repo_url') or '').strip()
        if not repo_url:
            return _json_response(400, {"error": "repo_url is required"})

        query = body.get('query', '')
        branch = body.get('branch')
        top_k = body.get('top_k', 3)

        try:
            top_k = int(top_k)
        except (TypeError, ValueError):
            return _json_response(400, {"error": "top_k must be an integer"})

        token = body.get('github_token') or os.getenv('GITHUB_TOKEN')
        scan_bundle = selective_repo_scan(
            repo_url=repo_url,
            query=query,
            token=token,
            branch=branch,
            top_k=top_k,
        )

        selected_files = scan_bundle.get('selected_files', [])
        if not selected_files:
            return _json_response(422, {
                "error": "No relevant source files found for analysis",
                "repo_stats": scan_bundle.get('repo_stats', {}),
            })

        combined_context = "\n\n".join(
            [
                f"# FILE: {item.get('path', 'unknown')}\n{item.get('excerpt', '')}"
                for item in selected_files
            ]
        )

        prompt = build_security_prompt(combined_context, 'python')
        try:
            analysis_result = _invoke_model_json(prompt)
        except Exception as err:
            print(f"[handler] Repo scan using local fallback: {str(err)}")
            analysis_result = _local_static_review(combined_context)

        vulnerabilities = analysis_result.get('vulnerabilities', []) if isinstance(analysis_result, dict) else []
        intelligence = build_attack_intelligence(vulnerabilities, combined_context)

        return _json_response(200, {
            "repo_stats": scan_bundle.get('repo_stats', {}),
            "keywords": scan_bundle.get('keywords', []),
            "selected_files": [
                {
                    "path": item.get('path'),
                    "hit_count": item.get('hit_count'),
                }
                for item in selected_files
            ],
            "vulnerabilities": vulnerabilities,
            "risk_ranking": intelligence.get('risk_ranking', []),
            "attack_graph": intelligence.get('attack_graph', {}),
            "breach_simulation": intelligence.get('breach_simulation', {}),
            "summary": intelligence.get('summary', {}),
            "analysis_mode": analysis_result.get('analysis_mode', 'model') if isinstance(analysis_result, dict) else 'model',
            "note": analysis_result.get('note') if isinstance(analysis_result, dict) else None,
        })
    except Exception as e:
        print(f"repo_scan error: {str(e)}")
        return _json_response(500, {"error": str(e)})


def repo_scan_start(event, context):
    try:
        body = _parse_body(event)
        repo_url = (body.get('repo_url') or '').strip()
        if not repo_url:
            return _json_response(400, {"error": "repo_url is required"})

        query = body.get('query', '')
        branch = body.get('branch')
        top_k = body.get('top_k', 3)

        try:
            top_k = int(top_k)
        except (TypeError, ValueError):
            return _json_response(400, {"error": "top_k must be an integer"})

        token = body.get('github_token') or os.getenv('GITHUB_TOKEN')
        
        job_id = body.get('job_id')
        from .job_manager import create_job
        from .repo_scan_engine import start_progressive_scan
        
        job_id = create_job(job_id)
        
        start_progressive_scan(
            job_id=job_id,
            repo_url=repo_url,
            query=query,
            token=token,
            branch=branch,
            top_k=top_k,
            invoke_fn=_invoke_model_json
        )

        return _json_response(200, {"job_id": job_id, "status": "started"})
    except Exception as e:
        print(f"repo_scan_start error: {str(e)}")
        return _json_response(500, {"error": str(e)})

def repo_scan_status(event, context):
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        job_id = query_params.get('job_id')
        
        if not job_id:
            return _json_response(400, {"error": "job_id query parameter is required"})

        from .job_manager import get_job
        job = get_job(job_id)
        
        if not job:
            return _json_response(404, {"error": "Job not found"})
            
        return _json_response(200, job)
        
    except Exception as e:
        print(f"repo_scan_status error: {str(e)}")
        import traceback
        traceback.print_exc()
        return _json_response(500, {"error": str(e)})


def repo_autofix_start(event, context):
    try:
        body = _parse_body(event)
        repo_url = body.get('repo_url')
        code = body.get('code')
        vulnerabilities = body.get('vulnerabilities', [])
        mode = body.get('mode', 'suggest')
        token = body.get('github_token') or os.getenv('GITHUB_TOKEN')
        branch = body.get('branch')
        language = body.get('language', 'python')

        if not vulnerabilities:
            return _json_response(400, {"error": "vulnerabilities list is required"})

        from .job_manager import create_job
        from .autofix_engine import start_autofix_job

        job_id = create_job()

        def autofix_llm_callback(file_content, file_vulns, file_path):
            prompt = build_autofix_prompt(file_content, file_vulns, file_path)
            return _invoke_model_json(prompt, max_tokens=3000)

        start_autofix_job(job_id, repo_url, code, vulnerabilities, token, branch, mode, language, autofix_llm_callback)

        return _json_response(200, {"job_id": job_id, "status": "started"})
        
    except Exception as e:
        print(f"repo_autofix_start error: {str(e)}")
        import traceback
        traceback.print_exc()
        return _json_response(500, {"error": str(e)})


def repo_autofix_status(event, context):
    try:
        query_params = event.get('queryStringParameters', {}) or {}
        job_id = query_params.get('job_id')
        
        if not job_id:
            return _json_response(400, {"error": "job_id query parameter is required"})

        from .job_manager import get_job
        job = get_job(job_id)
        
        if not job:
            return _json_response(404, {"error": "Job not found"})
            
        return _json_response(200, job)
        
    except Exception as e:
        print(f"repo_autofix_status error: {str(e)}")
        return _json_response(500, {"error": str(e)})
