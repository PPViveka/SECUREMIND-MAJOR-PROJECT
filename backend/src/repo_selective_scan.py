import os
import re
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse

IGNORED_DIRS = {
    '.git',
    'node_modules',
    'venv',
    '.venv',
    '__pycache__',
    'dist',
    'build',
    '.next',
    '.idea',
    '.vscode',
}

TEXT_FILE_EXTENSIONS = {
    '.py', '.js', '.ts', '.tsx', '.jsx', '.go', '.java', '.kt', '.rb', '.php', '.cs',
    '.tf', '.hcl', '.yaml', '.yml', '.json', '.toml', '.ini', '.cfg', '.conf',
    '.md', '.txt', '.sql', '.sh', '.ps1', '.dockerfile', '.gradle', '.xml', '.html', '.css',
}

SECURITY_KEYWORDS = [
    'auth', 'token', 'secret', 'password', 'jwt', 'session', 'sql', 'injection',
    's3', 'bucket', 'iam', 'policy', 'permission', 'encryption', 'cors', 'xss',
    'subprocess', 'exec', 'deserialize', 'admin', 'database', 'credential',
    'terraform', 'aws', 'serverless', 'docker', 'security_group', 'k8s', 'azure', 'gcp',
]

STOPWORDS = {
    'the', 'and', 'with', 'from', 'that', 'this', 'into', 'your', 'have', 'has',
    'for', 'not', 'are', 'was', 'were', 'will', 'would', 'should', 'can', 'could',
    'when', 'what', 'where', 'which', 'about', 'scan', 'repository', 'github',
}


def _run_cmd(args, cwd=None, env=None):
    if env is None:
        env = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
            'HOME': os.environ.get('HOME', tempfile.gettempdir()),
            'LANG': 'C.UTF-8',
            'GIT_TERMINAL_PROMPT': '0',
        }
    return subprocess.run(
        args,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _is_allowed_repo_url(repo_url):
    parsed = urlparse(repo_url)
    if parsed.scheme != 'https' or parsed.username or parsed.password:
        return False
    if parsed.port not in (None, 443):
        return False
    return parsed.hostname.lower() in {'github.com', 'www.github.com'} if parsed.hostname else False


def _clone_repository(repo_url, target_dir, token=None, branch=None):
    if not _is_allowed_repo_url(repo_url):
        raise ValueError('Only https://github.com repositories are allowed')

    cmd = ['git']
    if token:
        cmd += ['-c', f'http.extraheader=Authorization: Bearer {token}']

    cmd += ['clone', '--depth', '1']
    if branch:
        cmd += ['--branch', branch, '--single-branch']
    cmd += [repo_url, target_dir]

    env = {
        'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
        'HOME': os.environ.get('HOME', tempfile.gettempdir()),
        'LANG': 'C.UTF-8',
        'GIT_TERMINAL_PROMPT': '0',
    }

    result = _run_cmd(cmd, env=env)
    if result.returncode != 0:
        raise RuntimeError(f'git clone failed: {result.stderr.strip() or result.stdout.strip()}')


def _is_text_candidate(file_name, size_bytes):
    if size_bytes > 1_000_000:
        return False

    lower_name = file_name.lower()
    if lower_name in {'dockerfile', 'makefile'}:
        return True

    _, ext = os.path.splitext(lower_name)
    return ext in TEXT_FILE_EXTENSIONS


def build_repo_map(repo_root, max_files=12000):
    files = []
    total_seen = 0

    for current_root, dirs, names in os.walk(repo_root):
        dirs[:] = [
            d for d in dirs
            if d not in IGNORED_DIRS and not d.startswith('.')
        ]

        for name in names:
            if name.startswith('.'):
                continue
            total_seen += 1
            abs_path = os.path.join(current_root, name)
            rel_path = os.path.relpath(abs_path, repo_root).replace(os.sep, '/')

            try:
                size = os.path.getsize(abs_path)
            except OSError:
                continue

            if not _is_text_candidate(name, size):
                continue

            files.append(
                {
                    'path': rel_path,
                    'size_bytes': size,
                }
            )

            if len(files) >= max_files:
                return {
                    'files': files,
                    'total_seen': total_seen,
                    'truncated': True,
                }

    return {
        'files': files,
        'total_seen': total_seen,
        'truncated': False,
    }


def extract_keywords(text, max_keywords=14, include_security_defaults=True):
    raw_tokens = re.findall(r'[A-Za-z_][A-Za-z0-9_\-]{2,}', text or '')

    seen = set()
    keywords = []
    for token in raw_tokens:
        token_l = token.lower()
        if token_l in STOPWORDS:
            continue
        if token_l in seen:
            continue
        if len(token_l) < 3:
            continue
        seen.add(token_l)
        keywords.append(token_l)

    if include_security_defaults:
        for sec_kw in SECURITY_KEYWORDS:
            if sec_kw not in seen:
                keywords.append(sec_kw)

    return keywords[:max_keywords]


def _search_file_paths(repo_root, keywords):
    if not keywords:
        return []

    if shutil.which('rg'):
        cmd = ['rg', '-l', '-I']
        for kw in keywords:
            cmd += ['-e', kw]
        cmd += ['.']
        result = _run_cmd(cmd, cwd=repo_root)
    else:
        cmd = ['grep', '-rlI']
        for kw in keywords:
            cmd += ['-e', kw]
        cmd += ['.']
        result = _run_cmd(cmd, cwd=repo_root)

    if result.returncode not in (0, 1):
        return []

    matched = []
    for line in result.stdout.splitlines():
        path = line.strip()
        if not path:
            continue

        normalized = path[2:] if path.startswith('./') else path
        parts = normalized.split('/')
        if any(part in IGNORED_DIRS for part in parts):
            continue
        if any(part.startswith('.') for part in parts):
            continue
        matched.append(normalized)

    return sorted(set(matched))


def _score_and_select(repo_root, matched_paths, keywords, top_k=3, max_chars=4000):
    ranked = []
    for rel_path in matched_paths:
        abs_path = os.path.join(repo_root, rel_path)
        if not os.path.isfile(abs_path):
            continue

        try:
            with open(abs_path, 'r', encoding='utf-8', errors='ignore') as handle:
                excerpt = handle.read(max_chars)
        except OSError:
            continue

        text = excerpt.lower()
        hit_count = 0
        for kw in keywords:
            hit_count += len(re.findall(re.escape(kw), text))

        if hit_count <= 0:
            continue

        security_bonus = 0
        path_l = rel_path.lower()
        if any(k in path_l for k in ('auth', 'security', 'iam', 'policy', 'db', 'database', 'api', 'terraform', 'infra')):
            security_bonus = 2

        ranked.append(
            {
                'path': rel_path,
                'hit_count': hit_count + security_bonus,
                'excerpt': excerpt,
            }
        )

    ranked.sort(key=lambda item: item['hit_count'], reverse=True)
    return ranked[:top_k]


# def selective_repo_scan(repo_url, query, token=None, branch=None, top_k=3):
#     top_k = max(1, min(20, int(top_k)))

#     with tempfile.TemporaryDirectory(prefix='sagearmor_repo_scan_') as tmp_dir:
#         repo_dir = os.path.join(tmp_dir, 'repo')
#         _clone_repository(repo_url, repo_dir, token=token, branch=branch)

#         repo_map = build_repo_map(repo_dir)
#         repo_files = repo_map['files']
#         repo_file_set = {item['path'] for item in repo_files}

#         query_keywords = extract_keywords(query, include_security_defaults=False)
#         if query_keywords:
#             keywords = query_keywords
#         else:
#             # Empty/weak query gets baseline security keywords.
#             keywords = extract_keywords('', include_security_defaults=True)

#         matched_paths = _search_file_paths(repo_dir, keywords)

#         if repo_file_set:
#             matched_paths = [p for p in matched_paths if p in repo_file_set]

#         if not matched_paths and not query_keywords:
#             matched_paths = [item['path'] for item in repo_files[: min(80, len(repo_files))]]

#         selected = _score_and_select(repo_dir, matched_paths, keywords, top_k=top_k)

#         return {
#             'repo_stats': {
#                 'total_seen': repo_map['total_seen'],
#                 'text_candidates': len(repo_files),
#                 'matched_files': len(matched_paths),
#                 'selected_files': len(selected),
#                 'truncated_repo_map': repo_map['truncated'],
#             },
#             'keywords': keywords,
#             'selected_files': selected,
#         }


import requests
from urllib.parse import urlparse

def parse_github_url(url):
    if not _is_allowed_repo_url(url):
        raise ValueError('Only exact https://github.com repository URLs are allowed')
    parsed = urlparse(url)
    path = parsed.path.strip('/')
    if path.endswith('.git'):
        path = path[:-4]
    parts = path.split('/')
    if len(parts) >= 2:
        return parts[0], parts[1]
    raise ValueError(f"Invalid GitHub URL: {url}")


def fetch_repo_tree(owner, repo, token=None, branch=None):
    if not branch:
        # Default to fetching the tree for HEAD
        branch = "HEAD"
        
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
    
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"

    res = requests.get(url, headers=headers, allow_redirects=False, timeout=15)
    
    # Fallback to 'main' or 'master' if HEAD fails (sometimes happens on certain repository configurations)
    if res.status_code != 200 and branch == "HEAD":
        res = requests.get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/main?recursive=1", headers=headers, allow_redirects=False, timeout=15)
        if res.status_code != 200:
            res = requests.get(f"https://api.github.com/repos/{owner}/{repo}/git/trees/master?recursive=1", headers=headers, allow_redirects=False, timeout=15)

    if res.status_code != 200:
        raise Exception(f"GitHub API error: {res.text}")

    data = res.json()
    return data.get("tree", [])


def selective_repo_scan(repo_url, query, token=None, branch=None, top_k=3):
    top_k = max(1, min(20, int(top_k)))

    owner, repo = parse_github_url(repo_url)
    tree = fetch_repo_tree(owner, repo, token, branch)

    # Convert to file list, applying our ignore rules and text candidate rules
    repo_files = []
    for item in tree:
        if item["type"] == "blob":
            path = item["path"]
            parts = path.split('/')
            
            if any(part in IGNORED_DIRS for part in parts):
                continue
            if any(part.startswith('.') for part in parts):
                continue
                
            size = item.get("size", 0)
            if not _is_text_candidate(path, size):
                continue
                
            repo_files.append({
                "path": path,
                "sha": item["sha"]
            })

    # Extracted Keywords
    query_keywords = extract_keywords(query, include_security_defaults=False)
    if query_keywords:
        keywords = query_keywords
    else:
        # Empty/weak query gets baseline security keywords.
        keywords = extract_keywords('', include_security_defaults=True)

    # Match files by path (since we don't have file contents yet)
    matched_files = []
    for f in repo_files:
        path_lower = f["path"].lower()
        if any(kw in path_lower for kw in keywords):
            matched_files.append(f)

    # If no files matched by path, fall back to checking the first 80 text files
    # The file contents will be fetched and checked for hit_count below.
    if not matched_files:
        matched_files = repo_files[:80]

    # Limit number of files we download to prevent rate limits / long waits
    # matched_files = matched_files[:50]

    # Fetch file content and score them
    headers = {}
    if token:
        headers["Authorization"] = f"token {token}"
    # Setting Accept header to vnd.github.v3.raw makes the API return the raw file content instead of JSON
    headers["Accept"] = "application/vnd.github.v3.raw"

    import concurrent.futures

    selected = []
    
    def fetch_and_score(file):
        try:
            blob_url = f"https://api.github.com/repos/{owner}/{repo}/git/blobs/{file['sha']}"
            res = requests.get(blob_url, headers=headers, allow_redirects=False, timeout=15)
            
            if res.status_code == 200:
                content = res.text[:4000]
                text_lower = content.lower()
                
                hit_count = 0
                for kw in keywords:
                    hit_count += text_lower.count(kw)

                if hit_count > 0:
                    security_bonus = 0
                    path_l = file["path"].lower()
                    if any(k in path_l for k in ('auth', 'security', 'iam', 'policy', 'db', 'database', 'api', 'terraform', 'infra')):
                        security_bonus = 2
                        
                    return {
                        "path": file["path"],
                        "hit_count": hit_count + security_bonus,
                        "excerpt": content
                    }
        except:
            pass
        return None

    # Fetch files concurrently to drastically improve speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        results = executor.map(fetch_and_score, matched_files)
        for r in results:
            if r is not None:
                selected.append(r)

    selected = sorted(selected, key=lambda x: x["hit_count"], reverse=True)[:top_k]

    return {
        'repo_stats': {
            'total_seen': len(tree),
            'text_candidates': len(repo_files),
            'matched_files': len(matched_files),
            'selected_files': len(selected),
            'truncated_repo_map': False,
        },
        'keywords': keywords,
        'selected_files': selected,
    }