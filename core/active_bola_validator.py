"""
x1vart - Active Dual-Token Authorization Validator
Validates API authorization controls and object-level permissions (BOLA / IDOR detection).
Compares baseline responses against cross-tenant/cross-user requests to detect unauthorized access anomalies.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("x1vart.auth_validator")


@dataclass
class UserContext:
    """Security principal representation for authorization boundary testing."""
    name: str
    token: str
    token_type: str = "Bearer"
    custom_headers: Dict[str, str] = field(default_factory=dict)
    resource_ids: List[str] = field(default_factory=list)

    def get_auth_headers(self) -> Dict[str, str]:
        headers = dict(self.custom_headers)
        if self.token:
            prefix = f"{self.token_type} ".strip() if self.token_type else ""
            headers["Authorization"] = f"{prefix} {self.token}".strip()
        return headers


@dataclass
class AuthorizationAuditResult:
    """Result schema for access control verification."""
    endpoint_template: str
    tested_url: str
    method: str
    resource_id: str
    baseline_status: int
    tampered_status: int
    has_authorization_flaw: bool
    confidence: str  # "HIGH", "MEDIUM", "LOW", "SAFE"
    schema_similarity_score: float
    is_false_positive: bool
    evidence_summary: str
    remediation_guidance: str


class ActiveAuthorizationValidator:
    """
    Dual-Identity Access Control Auditor.
    Verifies that User A cannot read or mutate resources owned by User B.
    """

    DENIED_KEYWORDS: List[str] = [
        "access denied", "unauthorized", "forbidden", "permission denied",
        "not permitted", "invalid token", "authentication required",
        "khong co quyen", "truy cap bi tu choi", "chua dang nhap"
    ]

    def __init__(self, timeout_seconds: float = 8.0, verify_ssl: bool = False):
        self.timeout = timeout_seconds
        self.verify_ssl = verify_ssl

    @staticmethod
    def _extract_json_keys(data: Any, max_depth: int = 3, current_depth: int = 0) -> set[str]:
        """Recursively extracts JSON schema property keys for structural similarity comparison."""
        keys = set()
        if current_depth > max_depth:
            return keys

        if isinstance(data, dict):
            for k, v in data.items():
                keys.add(f"{k}")
                if isinstance(v, (dict, list)):
                    sub_keys = ActiveAuthorizationValidator._extract_json_keys(v, max_depth, current_depth + 1)
                    keys.update(f"{k}.{sk}" for sk in sub_keys)
        elif isinstance(data, list) and data:
            if isinstance(data[0], dict):
                sub_keys = ActiveAuthorizationValidator._extract_json_keys(data[0], max_depth, current_depth + 1)
                keys.update(f"[].{sk}" for sk in sub_keys)
        return keys

    @classmethod
    def _compute_jaccard_similarity(cls, keys_a: set[str], keys_b: set[str]) -> float:
        """Computes Jaccard structural similarity index between two response schemas."""
        if not keys_a and not keys_b:
            return 1.0
        if not keys_a or not keys_b:
            return 0.0
        intersection = len(keys_a.intersection(keys_b))
        union = len(keys_a.union(keys_b))
        return round(intersection / union, 3)

    @classmethod
    def _is_denial_message(cls, text: str) -> bool:
        """Detects 200 OK responses that actually contain soft error / access denied messages."""
        text_lower = (text or "").lower()
        return any(keyword in text_lower for keyword in cls.DENIED_KEYWORDS)

    async def verify_endpoint(
        self,
        base_url: str,
        endpoint_template: str,
        user_a: UserContext,
        user_b: UserContext,
        method: str = "GET"
    ) -> List[AuthorizationAuditResult]:
        """
        Executes dual-token authorization verification:
        Step 1: Baseline Request with User B credentials on User B resource ID.
        Step 2: Cross-User Request with User A credentials on User B resource ID.
        Step 3: Response correlation, schema similarity, and false-positive elimination.
        """
        base_url = base_url.rstrip("/")
        method = method.upper()
        results: List[AuthorizationAuditResult] = []

        if not user_b.resource_ids:
            logger.warning("[Auth Audit] User B has no assigned resource IDs to test.")
            return results

        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl, follow_redirects=False) as client:
            for res_id in user_b.resource_ids:
                # Replace route parameter placeholders: {id}, {userId}, {resourceId}, or :id
                resolved_path = endpoint_template
                for placeholder in ("{id}", "{userId}", "{resourceId}", "{accountId}", ":id"):
                    if placeholder in resolved_path:
                        resolved_path = resolved_path.replace(placeholder, str(res_id))

                if resolved_path == endpoint_template and not resolved_path.endswith(f"/{res_id}"):
                    # If no placeholder was matched, append resource id
                    resolved_path = f"{resolved_path.rstrip('/')}/{res_id}"

                full_url = f"{base_url}{resolved_path}"

                # Step 1: Establish baseline with legitimate owner (User B)
                try:
                    baseline_resp = await client.request(
                        method=method,
                        url=full_url,
                        headers=user_b.get_auth_headers()
                    )
                except Exception as ex:
                    logger.debug(f"[Auth Audit] Baseline request failed for {full_url}: {ex}")
                    continue

                if baseline_resp.status_code not in (200, 201, 204):
                    # Owner cannot access their own resource; endpoint not suitable for cross-user test
                    continue

                baseline_json = None
                baseline_keys = set()
                try:
                    baseline_json = baseline_resp.json()
                    baseline_keys = self._extract_json_keys(baseline_json)
                except Exception:
                    pass

                # Step 2: Cross-user test with User A credentials
                try:
                    tampered_resp = await client.request(
                        method=method,
                        url=full_url,
                        headers=user_a.get_auth_headers()
                    )
                except Exception as ex:
                    logger.debug(f"[Auth Audit] Tampered request failed for {full_url}: {ex}")
                    continue

                tampered_json = None
                tampered_keys = set()
                try:
                    tampered_json = tampered_resp.json()
                    tampered_keys = self._extract_json_keys(tampered_json)
                except Exception:
                    pass

                # Step 3: Correlation & Access Control Evaluation
                similarity = self._compute_jaccard_similarity(baseline_keys, tampered_keys)
                has_flaw = False
                confidence = "SAFE"
                is_false_positive = False
                evidence = ""
                remediation = ""

                # Compliant rejection codes
                if tampered_resp.status_code in (401, 403, 404):
                    confidence = "SAFE"
                    evidence = f"Endpoint correctly rejected User A with HTTP {tampered_resp.status_code}."
                elif tampered_resp.status_code in (200, 201):
                    # Check for 200 OK soft denial (False Positive filter)
                    if self._is_denial_message(tampered_resp.text):
                        is_false_positive = True
                        confidence = "SAFE"
                        evidence = f"Returned HTTP 200 but response body indicated access rejection ('{tampered_resp.text[:80]}')."
                    elif similarity >= 0.70 and len(tampered_keys) > 0:
                        has_flaw = True
                        confidence = "HIGH"
                        evidence = (
                            f"User A successfully retrieved User B's resource ({res_id}) with HTTP 200. "
                            f"Response schema match: {int(similarity * 100)}% (Keys: {sorted(list(tampered_keys))[:6]})."
                        )
                        remediation = (
                            f"Enforce server-side object ownership verification in endpoint handler '{endpoint_template}'. "
                            f"Validate that requesting session user ID matches the owner of resource '{res_id}' before returning data."
                        )
                    elif tampered_resp.text == baseline_resp.text and len(tampered_resp.text.strip()) > 10:
                        has_flaw = True
                        confidence = "HIGH"
                        evidence = f"Exact body match returned to User A for User B's private resource (Size: {len(tampered_resp.text)} bytes)."
                        remediation = "Implement strict data access control layer (ABAC/RBAC) on resource retrieval."
                    else:
                        confidence = "MEDIUM"
                        evidence = f"Returned HTTP 200 but structural similarity was low ({int(similarity * 100)}%). Requires manual inspection."
                else:
                    confidence = "SAFE"
                    evidence = f"Unexpected response status HTTP {tampered_resp.status_code}."

                results.append(AuthorizationAuditResult(
                    endpoint_template=endpoint_template,
                    tested_url=full_url,
                    method=method,
                    resource_id=str(res_id),
                    baseline_status=baseline_resp.status_code,
                    tampered_status=tampered_resp.status_code,
                    has_authorization_flaw=has_flaw,
                    confidence=confidence,
                    schema_similarity_score=similarity,
                    is_false_positive=is_false_positive,
                    evidence_summary=evidence,
                    remediation_guidance=remediation
                ))

        return results
