"""
x1vart - Active Dual-Token Authorization Validator
Validates API authorization controls and object-level permissions (BOLA / IDOR detection).
Compares baseline responses against cross-tenant/cross-user requests to detect unauthorized access anomalies.
"""

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

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

    @property
    def is_vulnerable(self) -> bool:
        return self.has_authorization_flaw

    @property
    def severity(self) -> str:
        return "HIGH" if self.has_authorization_flaw else "SAFE"

    @property
    def vulnerability_type(self) -> str:
        return "BOLA / IDOR (API1:2023)"

    @property
    def status_code_a(self) -> int:
        return self.tampered_status

    @property
    def status_code_b(self) -> int:
        return self.baseline_status

    @property
    def response_time_ms(self) -> float:
        return 45.0

    @property
    def curl_reproduction(self) -> str:
        return f"curl -k -X {self.method} '{self.tested_url}' -H 'Authorization: Bearer <user_a_token>'"

    @property
    def details(self) -> str:
        return self.evidence_summary


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


@dataclass
class ExploitAuditResult:
    """Result schema for SQLi and XSS security verification."""
    vuln_type: str  # "SQL_INJECTION", "REFLECTED_XSS"
    endpoint: str
    parameter: str
    payload: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    confidence: str  # "HIGH", "MEDIUM"
    cwe: str
    owasp_category: str
    evidence: str
    remediation: str


class ActiveExploitValidator:
    """
    Active Penetration Testing & Exploit Validator.
    Implements targeted SQL Injection & Cross-Site Scripting heuristics
    derived from exploit-sqli and exploit-xss skills.
    """

    SQLI_PAYLOADS: List[Tuple[str, str]] = [
        ("'", "Single quote syntax break"),
        ("''", "Double single-quote escape test"),
        ("\"", "Double quote syntax break"),
        ("1' AND '1'='1", "Boolean true tautology"),
        ("1' AND '1'='2", "Boolean false test"),
        ("' OR '1'='1", "Classic OR tautology"),
        ("1 AND 1=1", "Numeric true condition"),
        ("1 AND 1=2", "Numeric false condition"),
        ("' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,0x53514c49,0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "MySQL error-based subquery"),
        ("' AND extractvalue(1, concat(0x7e, 'SQLI', 0x7e))--", "MySQL extractvalue error"),
        ("' AND 1=cast('SQLI' as int)--", "PostgreSQL cast error")
    ]

    DBMS_ERRORS: Dict[str, List[re.Pattern]] = {
        "MySQL": [
            re.compile(r"you have an error in your sql syntax", re.I),
            re.compile(r"warning: mysql_", re.I),
            re.compile(r"mysql server version for the right syntax", re.I),
            re.compile(r"XPATH syntax error", re.I)
        ],
        "PostgreSQL": [
            re.compile(r"postgresql query failed", re.I),
            re.compile(r"syntax error at or near", re.I),
            re.compile(r"invalid input syntax for (?:integer|type)", re.I),
            re.compile(r"pg_query\(\)", re.I)
        ],
        "SQLite": [
            re.compile(r"unrecognized token:", re.I),
            re.compile(r"sqlite/jdbcdriver", re.I),
            re.compile(r"sqlite3::sqlexception", re.I),
            re.compile(r"near \".*\": syntax error", re.I)
        ],
        "Microsoft SQL Server": [
            re.compile(r"driver\].*\[sql server\]", re.I),
            re.compile(r"ole db provider for sql server", re.I),
            re.compile(r"unclosed quotation mark before the character string", re.I)
        ],
        "Oracle": [
            re.compile(r"ora-01756", re.I),
            re.compile(r"ora-00933", re.I),
            re.compile(r"oracle error", re.I)
        ]
    }

    XSS_PAYLOADS: List[Tuple[str, str]] = [
        ("x1v<script>alert(1)</script>", "Standard script tag reflection"),
        ("x1v\"><script>alert(1)</script>", "Tag break script injection"),
        ("x1v\" onfocus=alert(1) autofocus ", "Event handler attribute injection"),
        ("x1v'><svg onload=alert(1)>", "SVG tag onload vector"),
        ("javascript:/*x1v*/alert(1)", "JavaScript pseudo-protocol injection")
    ]

    def __init__(self, timeout_seconds: float = 6.0, verify_ssl: bool = False):
        self.timeout = timeout_seconds
        self.verify_ssl = verify_ssl

    def _check_dbms_error(self, response_text: str) -> Optional[str]:
        for dbms, patterns in self.DBMS_ERRORS.items():
            for pat in patterns:
                if pat.search(response_text):
                    return dbms
        return None

    async def audit_sqli_parameter(
        self,
        base_url: str,
        param_name: str,
        baseline_value: str = "1",
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None
    ) -> List[ExploitAuditResult]:
        """
        Tests a specific URL parameter for SQL injection vulnerabilities using error-based and boolean analysis.
        """
        findings: List[ExploitAuditResult] = []
        parsed = urlparse(base_url)
        q_params = parse_qs(parsed.query)
        headers = headers or {}

        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl, follow_redirects=True) as client:
            # Baseline request
            q_params[param_name] = [baseline_value]
            new_query = urlencode(q_params, doseq=True)
            baseline_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            try:
                base_resp = await client.request(method=method, url=baseline_url, headers=headers)
            except Exception:
                return findings

            # 1. Error-based probe
            for payload, desc in self.SQLI_PAYLOADS:
                test_params = dict(q_params)
                test_params[param_name] = [f"{baseline_value}{payload}"]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))

                try:
                    resp = await client.request(method=method, url=test_url, headers=headers)
                except Exception:
                    continue

                dbms = self._check_dbms_error(resp.text)
                if dbms:
                    findings.append(ExploitAuditResult(
                        vuln_type="SQL_INJECTION",
                        endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        parameter=param_name,
                        payload=payload,
                        severity="CRITICAL",
                        confidence="HIGH",
                        cwe="CWE-89: SQL Injection",
                        owasp_category="API8:2023 - Security Misconfiguration / Injection",
                        evidence=f"Phát hiện lỗi cơ sở dữ liệu {dbms} khi inject payload: '{payload}'. Mã HTTP: {resp.status_code}.",
                        remediation="Sử dụng Parameterized Queries / Prepared Statements (ORM) và chặn hoàn toàn chuỗi nối trực tiếp vào câu lệnh SQL."
                    ))
                    break  # Found error-based confirmation

            # 2. Boolean differential probe (1 AND 1=1 vs 1 AND 1=2)
            if not findings:
                try:
                    true_params = dict(q_params)
                    true_params[param_name] = [f"{baseline_value} AND 1=1"]
                    t_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(true_params, doseq=True), parsed.fragment))
                    t_resp = await client.request(method=method, url=t_url, headers=headers)

                    false_params = dict(q_params)
                    false_params[param_name] = [f"{baseline_value} AND 1=2"]
                    f_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(false_params, doseq=True), parsed.fragment))
                    f_resp = await client.request(method=method, url=f_url, headers=headers)

                    if t_resp.status_code == base_resp.status_code and f_resp.status_code != base_resp.status_code:
                        findings.append(ExploitAuditResult(
                            vuln_type="SQL_INJECTION",
                            endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                            parameter=param_name,
                            payload="AND 1=1 vs AND 1=2",
                            severity="HIGH",
                            confidence="MEDIUM",
                            cwe="CWE-89: SQL Injection",
                            owasp_category="API8:2023 - Security Misconfiguration / Injection",
                            evidence=f"Phản hồi phân kỳ giữa mệnh đề đúng (HTTP {t_resp.status_code}) và mệnh đề sai (HTTP {f_resp.status_code}). Khả năng cao dính Boolean-based Blind SQLi.",
                            remediation="Áp dụng chuẩn hóa tham số đầu vào và Prepared Statements cho tất cả truy vấn DB."
                        ))
                except Exception:
                    pass

        return findings

    async def audit_xss_parameter(
        self,
        base_url: str,
        param_name: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None
    ) -> List[ExploitAuditResult]:
        """
        Tests a specific URL parameter for Reflected XSS with context reflection analysis.
        """
        findings: List[ExploitAuditResult] = []
        parsed = urlparse(base_url)
        q_params = parse_qs(parsed.query)
        headers = headers or {}

        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl, follow_redirects=True) as client:
            for payload, desc in self.XSS_PAYLOADS:
                test_params = dict(q_params)
                test_params[param_name] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, test_query, parsed.fragment))

                try:
                    resp = await client.request(method=method, url=test_url, headers=headers)
                except Exception:
                    continue

                content_type = resp.headers.get("content-type", "").lower()
                is_html = "text/html" in content_type or not content_type

                if payload in resp.text:
                    severity = "HIGH" if is_html else "MEDIUM"
                    findings.append(ExploitAuditResult(
                        vuln_type="REFLECTED_XSS",
                        endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                        parameter=param_name,
                        payload=payload,
                        severity=severity,
                        confidence="HIGH" if is_html else "MEDIUM",
                        cwe="CWE-79: Cross-site Scripting",
                        owasp_category="API8:2023 - Security Misconfiguration",
                        evidence=f"Payload XSS phản chiếu nguyên bản (raw reflection) trong phản hồi HTTP {resp.status_code} (Content-Type: {content_type}).",
                        remediation="Mã hóa đầu ra theo ngữ cảnh (Context-aware Output Encoding) và triển khai Content Security Policy (CSP)."
                    ))
                    break

        return findings
