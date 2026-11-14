import json
import os

def build_autofix_prompt(file_content: str, vulnerabilities: list, file_path: str) -> str:
    """
    Constructs a prompt for Llama 3 to fix vulnerabilities in a specific file.
    """
    vulns_json = json.dumps(vulnerabilities, indent=2)
    
    prompt = f"""You are SageArmor AutoFix AI. You MUST respond ONLY with a single JSON object. No chat, no preamble, no markdown fences.

### TARGET FILE
Path: {file_path}

### SOURCE CODE
{file_content}

### DETECTED VULNERABILITIES
{vulns_json}

### REQUIRED OUTPUT FORMAT
{{
  "summary": "Brief summary of changes",
  "fixes": [
    {{
      "issue": "Title of the issue",
      "severity": "High/Medium/Low",
      "before_code": "The exact vulnerable snippet from original code",
      "after_code": "The safe, fixed version of that snippet",
      "explanation": "Why this fix works",
      "confidence": "High"
    }}
  ],
  "modified_content": "THE COMPLETE, VALID SOURCE CODE OF THE ENTIRE FILE AFTER ALL FIXES ARE APPLIED. DO NOT USE PLACEHOLDERS. DO NOT SAY 'REST OF CODE HERE'. THE RESPONSE IS INVALID IF THIS FIELD DOES NOT CONTAIN THE FULL FILE CONTENT."
}}

STRICT: Return ONLY the JSON object. Do not include ```json or any other text.
"""
    return prompt
