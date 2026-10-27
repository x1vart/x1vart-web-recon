"""
x1vart Web Recon - OWASP API Security Top 10 (2023) Threat Analyzer & Risk Scorer
Maps discovered attack surfaces to OWASP API Top 10 categories, computes exposure risk scores (0-100),
letter grades (A-F), and produces actionable remediation guidance.
Incorporates Active Vulnerability Scanner results (Files, CORS, Ports & SSL).
"""

from typing import Dict, Any, List, Optional


class OwaspApiAnalyzer:
    @staticmethod
    def analyze_attack_surface(
        subdomains: Dict[str, Any],
        js_data: Dict[str, Any],
        tech_data: Dict[str, Any],
        sourcemaps: List[Dict[str, Any]],
        vuln_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluate full reconnaissance data against OWASP API Security Top 10 (2023)
        """
        findings: List[Dict[str, Any]] = []
        score = 100

        endpoints = js_data.get("endpoints", [])
        secrets = js_data.get("secrets", [])
        sec_headers = tech_data.get("security_headers", [])
        takeovers = [s for s in subdomains.get("subdomains", []) if s.get("takeover", {}).get("vulnerable")]

        vuln_data = vuln_data or {}
        sensitive_files = vuln_data.get("sensitive_files", [])
        cors_audit = vuln_data.get("cors_audit", {})
        open_ports = vuln_data.get("open_ports", [])
        ssl_audit = vuln_data.get("ssl_audit", {})

        # 1. API1:2023 - Broken Object Level Authorization (BOLA)
        bola_endpoints = [e for e in endpoints if e.get("is_bola_candidate")]
        if bola_endpoints:
            deduction = min(len(bola_endpoints) * 5, 25)
            score -= deduction
            findings.append({
                "owasp_id": "API1:2023",
                "title": "Broken Object Level Authorization (BOLA / IDOR)",
                "severity": "CRITICAL",
                "count": len(bola_endpoints),
                "description": f"Found {len(bola_endpoints)} endpoints exposing user/object identifier parameters (e.g. {{id}}, {{orderId}}, {{userId}}).",
                "affected_items": [e["endpoint"] for e in bola_endpoints[:5]],
                "remediation": "Enforce object-level authorization checks validating current user session against the requested object ID on the server side."
            })

        # 2. API2:2023 - Broken Authentication (Secrets & Exposed Auth Files)
        jwt_or_api_keys = [s for s in secrets if s.get("secret_type") in ["JWT Token", "Generic Private/API Key", "AWS Access Key", "Stripe Live Secret Key"]]
        env_files = [f for f in sensitive_files if f.get("name", "").startswith("Environment")]
        if jwt_or_api_keys or env_files:
            score -= 25
            items = [f"{s['secret_type']} (Entropy: {s['entropy']})" for s in jwt_or_api_keys[:4]]
            if env_files:
                items.append("Exposed Environment Configuration (.env)")
            findings.append({
                "owasp_id": "API2:2023",
                "title": "Broken Authentication & Hardcoded Credentials Leakage",
                "severity": "CRITICAL",
                "count": len(items),
                "description": f"Discovered credentials or secret tokens exposed in client frontend bundles or publicly accessible configuration files.",
                "affected_items": items,
                "remediation": "Immediately revoke and rotate all leaked keys. Restrict access to .env files and use Backend-for-Frontend (BFF) architecture."
            })

        # 3. API4:2023 - Unrestricted Resource Consumption
        export_endpoints = [e for e in endpoints if any(w in e["endpoint"].lower() for w in ["export", "all", "dump", "reports"])]
        if export_endpoints:
            score -= 10
            findings.append({
                "owasp_id": "API4:2023",
                "title": "Unrestricted Resource Consumption (Mass Data Export)",
                "severity": "MEDIUM",
                "count": len(export_endpoints),
                "description": f"Detected {len(export_endpoints)} endpoints for bulk data export or reporting without mandatory pagination / rate limiting guarantees.",
                "affected_items": [e["endpoint"] for e in export_endpoints[:5]],
                "remediation": "Apply strict rate limits, max page size restrictions, and async job queues for heavy export operations."
            })

        # 4. API5:2023 - Broken Function Level Authorization (BFLA)
        admin_endpoints = [e for e in endpoints if any(w in e["endpoint"].lower() for w in ["/admin", "/internal", "/sys", "/system", "/root"])]
        if admin_endpoints:
            score -= 15
            findings.append({
                "owasp_id": "API5:2023",
                "title": "Broken Function Level Authorization (BFLA - Admin Routes)",
                "severity": "HIGH",
                "count": len(admin_endpoints),
                "description": f"Discovered {len(admin_endpoints)} privileged administrative / internal endpoints exposed in client-facing JavaScript bundles.",
                "affected_items": [e["endpoint"] for e in admin_endpoints[:5]],
                "remediation": "Ensure administrative endpoints enforce strict role-based access control (RBAC) and are segregated from public API gateways."
            })

        # 5. API8:2023 - Security Misconfiguration (Headers + Files + CORS + Source Maps + Ports + Takeover)
        missing_headers = [h for h in sec_headers if not h.get("present")]
        risky_ports = [p for p in open_ports if p.get("is_risky")]
        misconfig_items = []

        if sensitive_files:
            score -= min(len(sensitive_files) * 8, 20)
            misconfig_items.extend([f"Exposed File: {f['path']}" for f in sensitive_files[:4]])

        if cors_audit.get("vulnerable"):
            score -= 15
            misconfig_items.append("CORS Misconfiguration (Arbitrary Origin Allowed)")

        if sourcemaps:
            score -= 10
            misconfig_items.append(f"Exposed Source Maps ({len(sourcemaps)} maps found)")

        if takeovers:
            score -= 15
            misconfig_items.append(f"Subdomain Takeover Risk ({len(takeovers)} hosts)")

        if missing_headers:
            score -= min(len(missing_headers) * 2, 10)
            misconfig_items.append(f"Missing {len(missing_headers)} Security Headers (CSP, HSTS, X-Frame-Options)")

        if risky_ports:
            score -= 10
            misconfig_items.append(f"Exposed Database/Internal Ports: {', '.join(str(p['port']) for p in risky_ports)}")

        if ssl_audit.get("is_expired"):
            score -= 15
            misconfig_items.append(f"Expired SSL Certificate ({ssl_audit.get('expires_on')})")

        if misconfig_items:
            findings.append({
                "owasp_id": "API8:2023",
                "title": "Security Misconfiguration & Attack Surface Exposure",
                "severity": "CRITICAL" if any("Exposed File: /.env" in it or "CORS" in it for it in misconfig_items) else ("HIGH" if sourcemaps or takeovers else "MEDIUM"),
                "count": len(misconfig_items),
                "description": "Detected insecure build, network, or server configurations: " + ", ".join(misconfig_items),
                "affected_items": misconfig_items,
                "remediation": "Block access to sensitive files (/.env, /.git). Fix CORS allow-origin policy. Close public database ports. Enforce strict CSP, HSTS, and X-Frame-Options headers."
            })

        # 6. API9:2023 - Improper Inventory Management (Shadow / Legacy APIs)
        api_versions = set()
        for e in endpoints:
            if "/v1/" in e["endpoint"]:
                api_versions.add("v1")
            if "/v2/" in e["endpoint"]:
                api_versions.add("v2")
            if "/v3/" in e["endpoint"]:
                api_versions.add("v3")
        if len(api_versions) >= 2:
            score -= 10
            findings.append({
                "owasp_id": "API9:2023",
                "title": "Improper Inventory Management (Concurrent API Versions)",
                "severity": "LOW",
                "count": len(api_versions),
                "description": f"Target exposes multiple API major versions simultaneously ({', '.join(sorted(api_versions))}), increasing legacy attack surface.",
                "affected_items": list(api_versions),
                "remediation": "Decommission and sunset deprecated API versions. Maintain an updated API catalog and enforce version retirement policies."
            })

        score = max(0, min(100, score))

        # Determine Letter Grade & Risk Level
        if score >= 85:
            grade = "A"
            level = "LOW RISK"
            color = "#10b981"
        elif score >= 70:
            grade = "B"
            level = "MODERATE RISK"
            color = "#06b6d4"
        elif score >= 55:
            grade = "C"
            level = "ELEVATED RISK"
            color = "#f59e0b"
        elif score >= 40:
            grade = "D"
            level = "HIGH RISK"
            color = "#f97316"
        else:
            grade = "F"
            level = "CRITICAL RISK"
            color = "#ef4444"

        return {
            "exposure_score": score,
            "security_grade": grade,
            "risk_level": level,
            "color": color,
            "total_threats": len(findings),
            "findings": findings
        }
