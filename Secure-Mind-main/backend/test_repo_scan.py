import os
import json
from src.repo_selective_scan import selective_repo_scan

def run_test():
    try:
        print("Testing selective_repo_scan...")
        result = selective_repo_scan("https://github.com/OWASP/NodeGoat", "mongodb injection")
        print("Repo Stats:", json.dumps(result["repo_stats"], indent=2))
        print("Selected Files:", json.dumps([f["path"] for f in result["selected_files"]], indent=2))
        print("Keywords used:", json.dumps(result["keywords"], indent=2))
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    run_test()
