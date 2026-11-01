"""
x1vart - Authenticated Session Engine & Proxy Interceptor Integration
Maintains authenticated HTTP sessions (Bearer Tokens, API Keys, Cookies) across recon engines.
Forwards discovered endpoints/sitemaps to Burp Suite Proxy (127.0.0.1:8080) and exports Burp XML/JSON items.
"""

import asyncio
import base64
import html
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("x1vart.auth_session")


@dataclass
class AuthSessionConfig:
    """Config dataclass for authenticated scanning session."""
    bearer_token: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    api_keys: Dict[str, str] = field(default_factory=dict)  # e.g. {"X-API-Key": "secret123"}
    cookies: Dict[str, str] = field(default_factory=dict)
    proxy_url: Optional[str] = None  # e.g. "http://127.0.0.1:8080"
    timeout_seconds: float = 10.0
    verify_ssl: bool = False

    def get_aggregated_headers(self) -> Dict[str, str]:
        """Merges bearer token, api keys, and custom headers into a unified header dictionary."""
        headers = dict(self.custom_headers)
        if self.bearer_token:
            token = self.bearer_token.strip()
            if not token.lower().startswith("bearer "):
                token = f"Bearer {token}"
            headers["Authorization"] = token

        for key, val in self.api_keys.items():
            if key and val:
                headers[key] = val

        return headers


@dataclass
class ForwardResult:
    total_endpoints: int
    forwarded_success: int
    failed_count: int
    proxy_url: str
    details: List[Dict[str, Any]] = field(default_factory=list)


class AuthSessionManager:
    """
    Centralized HTTP Session Engine that propagates authentication context across recon/crawling modules.
    """

    def __init__(self, config: Optional[AuthSessionConfig] = None):
        self.config = config or AuthSessionConfig()

    def update_bearer_token(self, token: str):
        self.config.bearer_token = token

    def update_cookies(self, cookies: Dict[str, str]):
        self.config.cookies.update(cookies)

    def set_proxy(self, proxy_url: Optional[str]):
        self.config.proxy_url = proxy_url

    def create_async_client(self, override_proxy: Optional[str] = None) -> httpx.AsyncClient:
        """
        Instantiates an httpx.AsyncClient pre-configured with authentication headers, cookies, and proxy.
        """
        proxy = override_proxy or self.config.proxy_url
        headers = self.config.get_aggregated_headers()
        cookies = dict(self.config.cookies)

        return httpx.AsyncClient(
            headers=headers,
            cookies=cookies,
            proxy=proxy,
            verify=self.config.verify_ssl,
            timeout=self.config.timeout_seconds,
            follow_redirects=True
        )

    async def validate_session(self, verify_url: str, expected_status: int = 200) -> bool:
        """
        Pings an authenticated endpoint (e.g. /api/me or /api/user) to verify credential validity.
        """
        try:
            async with self.create_async_client() as client:
                resp = await client.get(verify_url)
                is_valid = resp.status_code == expected_status
                if not is_valid:
                    logger.warning(f"[Auth Session Invalid] {verify_url} returned {resp.status_code} (expected {expected_status})")
                return is_valid
        except Exception as e:
            logger.error(f"[Auth Session Check Failed] {verify_url}: {e}")
            return False


class BurpSuiteForwarder:
    """
    Interoperability engine between x1vart and PortSwigger Burp Suite:
    1. Actively pipes discovered API paths & URLs through Burp Suite upstream proxy (127.0.0.1:8080).
    2. Exports Burp-compatible XML items that can be imported directly into the Target Site map.
    """

    def __init__(self, proxy_url: str = "http://127.0.0.1:8080"):
        self.proxy_url = proxy_url

    async def check_proxy_online(self) -> bool:
        """Checks whether Burp Suite proxy listener is running."""
        try:
            async with httpx.AsyncClient(proxy=self.proxy_url, verify=False, timeout=2.0) as client:
                resp = await client.get("http://burp")
                return resp.status_code in (200, 502, 504) or "burp" in resp.text.lower()
        except Exception:
            return False

    async def forward_endpoints(
        self,
        base_url: str,
        endpoints: List[Dict[str, Any]],
        auth_config: Optional[AuthSessionConfig] = None,
        concurrency: int = 5
    ) -> ForwardResult:
        """
        Pushes discovered endpoints through Burp Proxy to populate Burp's Site map and HTTP History.
        """
        base_url = base_url.rstrip("/")
        headers = (auth_config or AuthSessionConfig()).get_aggregated_headers()
        cookies = (auth_config or AuthSessionConfig()).cookies

        sem = asyncio.Semaphore(concurrency)
        success = 0
        failed = 0
        details = []

        async def _forward_single(ep_obj: Dict[str, Any]):
            nonlocal success, failed
            method = ep_obj.get("method", "GET").upper()
            ep_path = ep_obj.get("endpoint", "/")
            if not ep_path.startswith("/"):
                ep_path = f"/{ep_path}"

            target_url = f"{base_url}{ep_path}"

            async with sem:
                try:
                    async with httpx.AsyncClient(
                        proxy=self.proxy_url,
                        verify=False,
                        timeout=5.0,
                        headers=headers,
                        cookies=cookies
                    ) as client:
                        if method == "POST":
                            resp = await client.post(target_url, json={"x1vart_test": 1})
                        elif method == "PUT":
                            resp = await client.put(target_url, json={"x1vart_test": 1})
                        elif method == "DELETE":
                            resp = await client.delete(target_url)
                        else:
                            resp = await client.get(target_url)

                        success += 1
                        details.append({
                            "url": target_url,
                            "method": method,
                            "status": resp.status_code,
                            "forwarded": True
                        })
                except Exception as ex:
                    failed += 1
                    details.append({
                        "url": target_url,
                        "method": method,
                        "error": str(ex),
                        "forwarded": False
                    })

        tasks = [_forward_single(ep) for ep in endpoints]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        return ForwardResult(
            total_endpoints=len(endpoints),
            forwarded_success=success,
            failed_count=failed,
            proxy_url=self.proxy_url,
            details=details
        )

    @staticmethod
    def export_burp_xml_sitemap(base_url: str, endpoints: List[Dict[str, Any]]) -> str:
        """
        Generates standard Burp Suite XML sitemap export file.
        Can be saved as .xml and inspected or imported into Burp Suite.
        """
        parsed = urlparse(base_url)
        host = parsed.hostname or base_url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        protocol = parsed.scheme or "http"

        xml_parts = ['<?xml version="1.0"?>', '<items burpVersion="2026.1" exportTime="Now">']

        for ep in endpoints:
            method = ep.get("method", "GET").upper()
            ep_path = ep.get("endpoint", "/")
            if not ep_path.startswith("/"):
                ep_path = f"/{ep_path}"

            port_suffix = f":{port}" if not ((protocol == "https" and port == 443) or (protocol == "http" and port == 80)) else ""
            full_url = f"{protocol}://{host}{port_suffix}{ep_path}"
            req_raw = f"{method} {ep_path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: x1vart-Pentest\r\nAccept: */*\r\n\r\n"
            b64_req = base64.b64encode(req_raw.encode("utf-8")).decode("ascii")

            item_xml = f"""  <item>
    <time>2026-10-27T00:00:00Z</time>
    <url>{html.escape(full_url)}</url>
    <host ip="{host}">{html.escape(host)}</host>
    <port>{port}</port>
    <protocol>{protocol}</protocol>
    <method>{method}</method>
    <path>{html.escape(ep_path)}</path>
    <extension>null</extension>
    <request base64="true">{b64_req}</request>
    <status>200</status>
    <responselength>0</responselength>
    <mimetype>JSON</mimetype>
    <comment>x1vart Discovered Endpoint</comment>
  </item>"""
            xml_parts.append(item_xml)

        xml_parts.append("</items>")
        return "\n".join(xml_parts)
