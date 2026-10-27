"""
x1vart Web Recon - JS AST & Endpoint Hunter
Scrapes real target HTML (using Chrome headers & SSL verify=False),
crawls JS bundles (Webpack/Vite/MVC), extracts Hidden API Endpoints,
identifies BOLA/IDOR parameters ({id}, order_id, user_id, studentId, etc.),
and detects Leaked Secrets using Shannon Entropy H(X) >= 3.5 combined with Regex.
Strictly returns empty results if nothing is found on real targets (no mock data injection).
"""

import asyncio
import logging
import math
import re
from collections import Counter
from typing import List, Dict, Any, Set, Tuple
from urllib.parse import urljoin, urlparse
import httpx
from bs4 import BeautifulSoup

logger = logging.getLogger("x1vart.jshunter")

CHROME_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
    "Sec-Ch-Ua": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1"
}

# Regex patterns for Hidden API endpoints (RESTful, GraphQL, MVC, AJAX)
API_REGEX_PATTERNS = [
    # RESTful / Standard APIs: /api/v1/..., /rest/..., /graphql
    r"""(?:["'`])(\/(?:api|v[0-9]+|rest|graphql|admin|auth|internal|config|users|students|orders|accounts|service|webhooks)[a-zA-Z0-9_\-\/{}:$%?&=.+,~!]+)(?:["'`])""",
    # MVC Web actions: /SinhVien/LoginAnonymous, /Account/Login, /User/Profile, etc.
    r"""(?:["'`])(\/[A-Z][a-zA-Z0-9_-]+\/[A-Za-z0-9_-]+[a-zA-Z0-9_\-\/{}:$%?&=.+,~!]*)(?:["'`])""",
    # Full URLs
    r"""(?:["'`])(https?:\/\/[a-zA-Z0-9.-]+(?::\d+)?\/(?:api|v[0-9]+|rest|graphql)[a-zA-Z0-9_\-\/{}:$%?&=.+,~!]+)(?:["'`])""",
    # Template literal paths: `/api/v1/students/${id}/grades`
    r"""`(\/(?:api|v[0-9]+|rest|graphql|admin|auth|internal|[A-Z][a-zA-Z0-9]+)[^`]+)`""",
    # Axios/fetch calls: fetch('/endpoint' or axios.get('/endpoint'
    r"""(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?|\$\.(?:ajax|get|post))\s*\(\s*["'`](\/[a-zA-Z0-9_\-\/{}:$%?&=.+,~!]+)["'`]"""
]

# Sensitive identifier parameter patterns (Potential BOLA/IDOR targets)
PARAM_IDENTIFIERS = [
    r"\{([a-zA-Z0-9_]+)\}",         # {id}, {order_id}, {studentId}
    r":([a-zA-Z0-9_]+)",            # :id, :order_id
    r"\${([a-zA-Z0-9_]+)}",         # ${id}, ${studentId}
    r"[?&]([a-zA-Z0-9_]+)="         # ?user_id=123
]

# Predefined high-confidence secret patterns
SECRET_PATTERNS = [
    {
        "type": "AWS Access Key",
        "regex": r"\b(AKIA[0-9A-Z]{16})\b",
        "min_entropy": 2.8
    },
    {
        "type": "AWS Secret Key",
        "regex": r"""(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["']([A-Za-z0-9\/+=]{40})["']""",
        "min_entropy": 3.8
    },
    {
        "type": "JWT Token",
        "regex": r"\b(eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_.-]{10,})\b",
        "min_entropy": 3.8
    },
    {
        "type": "Stripe Live Secret Key",
        "regex": r"\b(sk_live_[0-9a-zA-Z]{24,})\b",
        "min_entropy": 3.5
    },
    {
        "type": "Firebase API Key",
        "regex": r"\b(AIza[0-9A-Za-z-_]{35})\b",
        "min_entropy": 3.6
    },
    {
        "type": "GitHub Access Token",
        "regex": r"\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b",
        "min_entropy": 3.5
    },
    {
        "type": "Generic Private/API Key",
        "regex": r"""(?:api[-_]?key|secret|token|auth[-_]?key|private[-_]?key)\s*[:=]\s*["']([A-Za-z0-9+/=_\-\.]{20,64})["']""",
        "min_entropy": 3.5
    }
]

# Public third-party CDNs to skip from AST secret scanning (avoid framework noise)
PUBLIC_CDNS = [
    "cdn.tailwindcss.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com"
]

IGNORE_SUBSTRINGS = [
    "--tw-", "--moz-", "-webkit-", "text-decoration", "border-", "padding-", "margin-",
    ".break-", ".force-", "cursor-", "opacity-", "transform-", "transition-",
    "background-", "justify-", "align-", "flex-", "grid-", "scroll-", "font-",
    "xmlns", "http://", "https://", "content-type", "application/"
]


def calculate_shannon_entropy(data: str) -> float:
    """
    Calculate Shannon Entropy H(X) for a given string:
    H(X) = - SUM [ P(x_i) * log2(P(x_i)) ]
    """
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = Counter(data)
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 3)


class JsAstHunter:
    def __init__(self, entropy_threshold: float = 3.5):
        self.entropy_threshold = entropy_threshold

    async def crawl_scripts_from_html(self, target_url: str) -> Tuple[str, List[str], List[Dict[str, Any]]]:
        """
        Fetch target HTML and locate first-party application & chunk JS files.
        Uses Chrome headers and verify=False.
        Also parses HTML forms to discover initial endpoints.
        """
        js_urls: Set[str] = set()
        form_endpoints: List[Dict[str, Any]] = []
        html_content = ""

        try:
            async with httpx.AsyncClient(timeout=12.0, verify=False, follow_redirects=True) as client:
                resp = await client.get(target_url, headers=CHROME_HEADERS)
                html_content = resp.text
                final_url = str(resp.url)
                soup = BeautifulSoup(html_content, "html.parser")

                # 1. Standard <script src="...">
                for script in soup.find_all("script", src=True):
                    src = script["src"].strip()
                    if src and not src.startswith("data:"):
                        full_url = urljoin(final_url, src)
                        if not any(cdn in full_url.lower() for cdn in PUBLIC_CDNS):
                            js_urls.add(full_url)

                # 2. Extract Webpack / Vite dynamic chunks
                chunk_matches = re.findall(r"""["']([^"']+\.(?:js|mjs|cjs)(?:\?[^"']*)?)["']""", html_content)
                for chunk in chunk_matches:
                    chunk = chunk.strip()
                    if any(chunk.endswith(ext) for ext in [".js", ".mjs"]) and not chunk.startswith("http://www.w3.org"):
                        full_url = urljoin(final_url, chunk)
                        if not any(cdn in full_url.lower() for cdn in PUBLIC_CDNS):
                            js_urls.add(full_url)

                # 3. Discover Form Action Endpoints
                for form in soup.find_all("form", action=True):
                    action = form["action"].strip()
                    if action and not action.startswith("#") and not action.startswith("javascript:"):
                        method = form.get("method", "POST").upper()
                        norm_act = action if action.startswith("/") else f"/{action}"
                        form_endpoints.append({
                            "endpoint": norm_act,
                            "raw_match": action,
                            "method": method,
                            "parameters": [inp.get("name") for inp in form.find_all(["input", "select"]) if inp.get("name")],
                            "is_bola_candidate": False,
                            "bola_reason": "",
                            "source_file": f"{target_url} (HTML Form)"
                        })

        except Exception as e:
            logger.error(f"Error crawling HTML from {target_url}: {e}")

        return html_content, list(js_urls), form_endpoints

    async def fetch_js_files(self, js_urls: List[str]) -> Dict[str, str]:
        """
        Asynchronously download JS code for all discovered script URLs
        using Chrome User-Agent and verify=False.
        """
        js_contents: Dict[str, str] = {}
        sem = asyncio.Semaphore(10)

        async def fetch_one(url: str):
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=10.0, verify=False, follow_redirects=True) as client:
                        resp = await client.get(url, headers=CHROME_HEADERS)
                        if resp.status_code == 200:
                            js_contents[url] = resp.text
                except Exception as e:
                    logger.debug(f"Could not fetch JS file {url}: {e}")

        tasks = [fetch_one(u) for u in js_urls]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return js_contents

    def extract_endpoints_from_code(self, code: str, source_file: str) -> List[Dict[str, Any]]:
        """
        Analyze JavaScript code and extract hidden API endpoints with parameter detection
        """
        endpoints_map: Dict[str, Dict[str, Any]] = {}

        for pattern in API_REGEX_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                raw_endpoint = match.group(1).strip()

                if not raw_endpoint or len(raw_endpoint) < 4:
                    continue

                # Normalize template literals ${var} -> {var}
                normalized_endpoint = re.sub(r"\$\{([a-zA-Z0-9_]+)\}", r"{\1}", raw_endpoint)
                # Normalize :param -> {param}
                normalized_endpoint = re.sub(r"(?<=\/):([a-zA-Z0-9_]+)", r"{\1}", normalized_endpoint)

                # Skip static asset files
                if re.search(r"\.(?:png|jpg|jpeg|svg|css|woff|woff2|ttf|eot|ico|map)$", normalized_endpoint.split("?")[0], re.IGNORECASE):
                    continue

                # Extract parameters
                detected_params: List[str] = []
                for p_pattern in PARAM_IDENTIFIERS:
                    found_params = re.findall(p_pattern, normalized_endpoint)
                    for fp in found_params:
                        if fp not in detected_params and not fp.isdigit():
                            detected_params.append(fp)

                # Detect numeric IDs or UUID patterns in path
                path_parts = [p for p in normalized_endpoint.split("?")[0].split("/") if p]
                has_literal_id = False
                for p in path_parts:
                    if p.isdigit() or re.match(r"^[0-9a-fA-F-]{8,}$", p) or p.startswith("ORD-") or p.startswith("USR-"):
                        has_literal_id = True
                        if f"id:{p}" not in detected_params:
                            detected_params.append(f"id:{p}")

                # Guess HTTP method based on path heuristics
                guessed_method = "GET"
                lower_path = normalized_endpoint.lower()
                if any(verb in lower_path for verb in ["/create", "/upload", "/send", "/register", "/login", "/auth/token", "/revoke"]):
                    guessed_method = "POST"
                elif any(verb in lower_path for verb in ["/update", "/modify"]):
                    guessed_method = "PUT"
                elif any(verb in lower_path for verb in ["/delete", "/remove"]):
                    guessed_method = "DELETE"

                # Check BOLA/IDOR candidacy
                is_bola_candidate = False
                bola_reason = ""
                sensitive_keywords = ["id", "user", "order", "account", "student", "uuid", "client", "customer", "invoice", "report"]
                
                param_matches = [p for p in detected_params if any(kw in p.lower() for kw in sensitive_keywords)]
                if param_matches or has_literal_id:
                    is_bola_candidate = True
                    matched_names = param_matches if param_matches else ["literal ID in URI"]
                    bola_reason = f"Contains direct object identifier ({', '.join(matched_names)}) - High BOLA/IDOR Target"

                key = f"{guessed_method}:{normalized_endpoint}"
                if key not in endpoints_map:
                    endpoints_map[key] = {
                        "endpoint": normalized_endpoint,
                        "raw_match": raw_endpoint,
                        "method": guessed_method,
                        "parameters": detected_params,
                        "is_bola_candidate": is_bola_candidate,
                        "bola_reason": bola_reason,
                        "source_file": source_file
                    }

        return list(endpoints_map.values())

    def extract_secrets_from_code(self, code: str, source_file: str) -> List[Dict[str, Any]]:
        """
        Scan JavaScript code for leaked secrets, API keys, tokens using Regex + Shannon Entropy
        """
        leaked_secrets: List[Dict[str, Any]] = []
        seen_secrets: Set[str] = set()

        lines = code.splitlines()

        # 1. Regex pattern-based discovery
        for pat in SECRET_PATTERNS:
            for match in re.finditer(pat["regex"], code, re.IGNORECASE):
                secret_str = match.group(1).strip()
                if secret_str in seen_secrets or len(secret_str) < 16:
                    continue

                entropy = calculate_shannon_entropy(secret_str)
                if entropy >= pat["min_entropy"]:
                    seen_secrets.add(secret_str)
                    
                    start_pos = match.start(1)
                    line_num = code[:start_pos].count("\n") + 1
                    
                    line_text = lines[line_num - 1] if line_num - 1 < len(lines) else secret_str
                    snippet = line_text.strip()
                    if len(snippet) > 120:
                        snippet = snippet[:120] + "..."

                    masked = secret_str[:6] + "*" * (len(secret_str) - 10) + secret_str[-4:] if len(secret_str) > 12 else "****"

                    leaked_secrets.append({
                        "secret_type": pat["type"],
                        "secret_value": secret_str,
                        "masked_value": masked,
                        "entropy": entropy,
                        "threshold": pat["min_entropy"],
                        "line_number": line_num,
                        "snippet": snippet,
                        "source_file": source_file,
                        "confidence": "HIGH" if entropy >= 4.0 else "MEDIUM"
                    })

        # 2. General High-Entropy heuristic for unidentified secret tokens
        if not any(fw in source_file.lower() for fw in ["tailwindcss", "tailwind", "react.production", "react-dom", "jquery"]):
            raw_tokens = re.finditer(r"""(?:["'])([a-zA-Z0-9_\-\.\$\/+=]{24,80})(?:["'])""", code)
            for t_match in raw_tokens:
                token = t_match.group(1).strip()
                if token in seen_secrets:
                    continue

                if any(ign in token.lower() for ign in IGNORE_SUBSTRINGS):
                    continue
                if token.startswith("http") or token.startswith("/") or " " in token:
                    continue

                entropy = calculate_shannon_entropy(token)
                if entropy >= self.entropy_threshold:
                    seen_secrets.add(token)
                    start_pos = t_match.start(1)
                    line_num = code[:start_pos].count("\n") + 1
                    line_text = lines[line_num - 1] if line_num - 1 < len(lines) else token
                    snippet = line_text.strip()
                    if len(snippet) > 120:
                        snippet = snippet[:120] + "..."

                    masked = token[:6] + "*" * (len(token) - 10) + token[-4:] if len(token) > 12 else "****"

                    leaked_secrets.append({
                        "secret_type": "High-Entropy Token (Shannon H >= 3.5)",
                        "secret_value": token,
                        "masked_value": masked,
                        "entropy": entropy,
                        "threshold": self.entropy_threshold,
                        "line_number": line_num,
                        "snippet": snippet,
                        "source_file": source_file,
                        "confidence": "HIGH" if entropy >= 4.2 else "MEDIUM"
                    })

        return leaked_secrets

    async def run_hunt(self, target_url: str) -> Dict[str, Any]:
        """
        Orchestration of 100% live JS AST and Endpoint Hunting
        """
        html_content, js_urls, form_endpoints = await self.crawl_scripts_from_html(target_url)
        js_files_map = await self.fetch_js_files(js_urls)

        # Include inline HTML content for scanning
        if html_content:
            js_files_map[f"{target_url} (inline/DOM)"] = html_content

        all_endpoints: List[Dict[str, Any]] = list(form_endpoints)
        all_secrets: List[Dict[str, Any]] = []

        seen_endpoints = set(e["endpoint"] for e in form_endpoints)

        for source_file, code in js_files_map.items():
            # 1. Extract APIs
            endpoints = self.extract_endpoints_from_code(code, source_file)
            for ep in endpoints:
                if ep["endpoint"] not in seen_endpoints:
                    seen_endpoints.add(ep["endpoint"])
                    all_endpoints.append(ep)

            # 2. Extract Secrets with Shannon Entropy
            secrets = self.extract_secrets_from_code(code, source_file)
            all_secrets.extend(secrets)

        all_secrets.sort(key=lambda s: s["entropy"], reverse=True)

        return {
            "target_url": target_url,
            "total_js_files": len(js_urls),
            "js_urls": js_urls,
            "js_files_map": js_files_map,
            "total_endpoints": len(all_endpoints),
            "endpoints": all_endpoints,
            "total_secrets": len(all_secrets),
            "secrets": all_secrets
        }
