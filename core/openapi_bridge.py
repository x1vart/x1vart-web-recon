"""
x1vart Web Recon - OpenAPI 3.0 Bridge & Burp Suite Proxy Replayer
Converts discovered API endpoints into standard OpenAPI 3.0.3 JSON schema
and replays endpoints through Burp Suite HTTP Proxy (127.0.0.1:8080).
"""

import asyncio
import logging
import re
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, urljoin
import httpx

logger = logging.getLogger("x1vart.openapi_bridge")


class OpenApiBridge:
    @staticmethod
    def generate_openapi_spec(target_url: str, endpoints: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Convert detected endpoints into valid OpenAPI 3.0.3 specification JSON
        ready for Burp Suite OpenAPI Parser / BOLA Hunter extension.
        """
        parsed = urlparse(target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.netloc else target_url

        spec: Dict[str, Any] = {
            "openapi": "3.0.3",
            "info": {
                "title": f"x1vart Discovered Attack Surface - {parsed.netloc or target_url}",
                "description": "Auto-generated OpenAPI 3.0 specification produced by x1vart Web Recon & JS AST Analyzer. Optimized for Burp Suite OpenAPI Parser and BOLA / IDOR Testing.",
                "version": "1.0.0",
                "contact": {
                    "name": "x1vart Security Research Team"
                }
            },
            "servers": [
                {
                    "url": base_url,
                    "description": "Target Host Discovered via JS Recon"
                }
            ],
            "tags": [],
            "paths": {}
        }

        tags_set = set()

        for ep_item in endpoints:
            raw_path = ep_item.get("endpoint", "")
            method = ep_item.get("method", "GET").lower()
            source_file = ep_item.get("source_file", "Unknown bundle")
            is_bola = ep_item.get("is_bola_candidate", False)

            # Strip origin if endpoint contains full URL
            if raw_path.startswith("http://") or raw_path.startswith("https://"):
                url_parts = urlparse(raw_path)
                path_part = url_parts.path
                query_str = url_parts.query
            else:
                if "?" in raw_path:
                    path_part, query_str = raw_path.split("?", 1)
                else:
                    path_part = raw_path
                    query_str = ""

            if not path_part.startswith("/"):
                path_part = "/" + path_part

            # Identify Tag from first path segment
            segments = [s for s in path_part.split("/") if s and s not in ["api", "v1", "v2", "v3", "rest"]]
            tag = segments[0].capitalize() if segments else "General"
            tags_set.add(tag)

            # Parse path parameters like {id}, {studentId}, {orderId}
            path_params = re.findall(r"\{([a-zA-Z0-9_]+)\}", path_part)
            openapi_parameters = []

            for p_name in path_params:
                sample_val = "101"
                p_lower = p_name.lower()
                if "order" in p_lower:
                    sample_val = "ORD-9999"
                elif "account" in p_lower:
                    sample_val = "ACC-8888"
                elif "user" in p_lower:
                    sample_val = "admin"
                elif "uuid" in p_lower or "report" in p_lower:
                    sample_val = "550e8400-e29b-41d4-a716-446655440000"

                openapi_parameters.append({
                    "name": p_name,
                    "in": "path",
                    "required": True,
                    "description": f"Target object identifier ({p_name}) detected in JS bundle. Potential BOLA/IDOR parameter.",
                    "schema": {
                        "type": "string",
                        "example": sample_val
                    }
                })

            # Parse query parameters from query_str
            if query_str:
                parsed_query = parse_qs(query_str)
                for q_key, q_vals in parsed_query.items():
                    openapi_parameters.append({
                        "name": q_key,
                        "in": "query",
                        "required": False,
                        "description": f"Query parameter '{q_key}' extracted by JS AST Hunter",
                        "schema": {
                            "type": "string",
                            "example": q_vals[0] if q_vals else "default"
                        }
                    })

            # Path operation definition
            operation_summary = f"{method.upper()} {path_part}"
            if is_bola:
                operation_summary += " [BOLA Candidate]"

            operation_obj: Dict[str, Any] = {
                "tags": [tag],
                "summary": operation_summary,
                "description": f"Extracted from bundle: {source_file}\nBOLA/IDOR Target: {is_bola}",
                "operationId": f"{method}_{re.sub(r'[^a-zA-Z0-9]', '_', path_part).strip('_')}",
                "parameters": openapi_parameters,
                "responses": {
                    "200": {
                        "description": "Successful API Response",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object"
                                }
                            }
                        }
                    },
                    "401": {
                        "description": "Unauthorized / Missing JWT Bearer"
                    },
                    "403": {
                        "description": "Forbidden / BOLA Access Denied"
                    }
                }
            }

            # If POST / PUT, attach generic JSON request body
            if method in ["post", "put", "patch"]:
                operation_obj["requestBody"] = {
                    "required": False,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "example": {
                                    "id": 101,
                                    "action": "execute",
                                    "payload": "sample_test"
                                }
                            }
                        }
                    }
                }

            if path_part not in spec["paths"]:
                spec["paths"][path_part] = {}

            spec["paths"][path_part][method] = operation_obj

        spec["tags"] = [{"name": t, "description": f"APIs related to {t}"} for t in sorted(tags_set)]
        return spec

    @staticmethod
    async def push_to_burp_proxy(
        target_base: str,
        endpoints: List[Dict[str, Any]],
        proxy_url: str = "http://127.0.0.1:8080"
    ) -> Dict[str, Any]:
        """
        Send HTTP requests for each discovered endpoint through the Burp Suite Proxy
        so that Burp Suite's HTTP History and BOLA Hunter extension capture the traffic.
        """
        results: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(5)

        logger.info(f"Replaying {len(endpoints)} requests through Burp Proxy: {proxy_url}")

        # Ensure base URL format
        parsed_base = urlparse(target_base)
        base_clean = f"{parsed_base.scheme}://{parsed_base.netloc}" if parsed_base.netloc else target_base
        if not base_clean.startswith("http"):
            base_clean = f"http://{base_clean}"

        async def send_single(ep_info: Dict[str, Any]):
            async with sem:
                endpoint = ep_info.get("endpoint", "")
                method = ep_info.get("method", "GET").upper()

                # Replace placeholders with test values for Burp
                test_path = endpoint
                test_path = re.sub(r"\{id\}", "101", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{student_?id\}", "101", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{user_?id\}", "admin", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{order_?id\}", "ORD-9999", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{account_?id\}", "ACC-8888", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{filterRole\}", "admin", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{reportUuid\}", "550e8400-e29b-41d4-a716-446655440000", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{uuid\}", "550e8400-e29b-41d4-a716-446655440000", test_path, flags=re.IGNORECASE)
                test_path = re.sub(r"\{[a-zA-Z0-9_]+\}", "101", test_path)

                full_url = urljoin(base_clean, test_path)

                headers = {
                    "User-Agent": "x1vart-Burp-Replay-Agent/1.0",
                    "X-x1vart-Audit": "Discovered-By-AST-Hunter",
                    "Accept": "application/json, text/plain, */*"
                }

                entry = {
                    "endpoint": endpoint,
                    "target_url": full_url,
                    "method": method,
                    "burp_captured": False,
                    "status_code": None,
                    "error": None
                }

                try:
                    async with httpx.AsyncClient(proxy=proxy_url, verify=False, timeout=6.0) as client:
                        if method == "POST":
                            resp = await client.post(full_url, headers=headers, json={"test": True})
                        elif method == "PUT":
                            resp = await client.put(full_url, headers=headers, json={"test": True})
                        elif method == "DELETE":
                            resp = await client.delete(full_url, headers=headers)
                        else:
                            resp = await client.get(full_url, headers=headers)

                        entry["status_code"] = resp.status_code
                        entry["burp_captured"] = True
                except httpx.ProxyError as pe:
                    entry["error"] = f"Burp Proxy Connection Refused: {pe}"
                except Exception as ex:
                    entry["error"] = f"Request Failed: {ex}"

                return entry

        tasks = [send_single(ep) for ep in endpoints]
        if tasks:
            raw_results = await asyncio.gather(*tasks, return_exceptions=True)
            results = [r for r in raw_results if isinstance(r, dict)]

        success_count = sum(1 for r in results if r.get("burp_captured"))
        proxy_reachable = success_count > 0

        return {
            "proxy_url": proxy_url,
            "target_base": base_clean,
            "total_sent": len(results),
            "successfully_proxied": success_count,
            "proxy_reachable": proxy_reachable,
            "results": results
        }
