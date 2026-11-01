"""
Self-check for x1vart Attack Surface & Continuous EASM Platform.
No frameworks. Pure assert statements.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.db_manager import db_manager
from core.asset_diff_notifier import AssetDiffEngine

def main():
    # 1. DB Schedule & Settings Check
    db_manager.set_setting("discord_webhook", "https://discord.com/api/webhooks/check")
    assert db_manager.get_setting("discord_webhook") == "https://discord.com/api/webhooks/check"

    sched_id = db_manager.create_schedule("example.com", "example.com", interval_hours=24)
    assert sched_id.startswith("sched_")
    assert db_manager.toggle_schedule(sched_id, False) is True
    assert db_manager.delete_schedule(sched_id) is True

    # 2. Asset Diffing Engine Check
    base = {
        "domain": "target.corp",
        "subdomain_recon": {"subdomains": [{"subdomain": "a.target.corp"}]},
        "vulnerabilities": {"open_ports": [{"port": 80}]},
        "js_hunter": {"secrets": []},
        "owasp_analysis": {"exposure_score": 90, "security_grade": "A"}
    }
    new = {
        "domain": "target.corp",
        "subdomain_recon": {
            "subdomains": [
                {"subdomain": "a.target.corp"},
                {"subdomain": "leak.target.corp", "takeover": {"vulnerable": True}}
            ]
        },
        "vulnerabilities": {"open_ports": [{"port": 80}, {"port": 8080}]},
        "js_hunter": {"secrets": [{"secret_type": "AWS Key", "entropy": 3.8, "secret_value": "KEY123"}]},
        "owasp_analysis": {"exposure_score": 60, "security_grade": "D"}
    }
    diff = AssetDiffEngine.compute_diff(base, new)
    assert diff["has_changes"] is True
    assert diff["has_critical_alerts"] is True
    assert "leak.target.corp" in diff["new_subdomains"]
    assert 8080 in diff["new_ports"]
    assert len(diff["new_secrets"]) == 1
    assert len(diff["new_takeovers"]) == 1
    assert diff["score_change"]["delta"] == -30

    # 3. Static UI Innovations Verification
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    assert os.path.exists(html_path)
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()

    # 1. Cyber Threat Radar
    assert "threat-radar-canvas" in html
    assert "renderThreatRadar" in html

    # 2. Command Palette
    assert "command-palette-modal" in html
    assert "openCommandPalette" in html
    assert "filterCommandPalette" in html

    # 3. Interactive Attack Path
    assert "btn-attack-path" in html
    assert "hud-killchain" in html
    assert "toggleAttackPathSimulation" in html
    assert "node-attack-path" in html

    # 4. Dual-Node Terminal HUD
    assert "kali-terminal-content" in html
    assert "master-terminal-content" in html
    assert "renderDualTerminalLogs" in html

    # 5. Source Map Mini IDE
    assert "ide-file-tree" in html
    assert "ide-code-viewer" in html
    assert "renderSourceMaps" in html
    assert "loadFileInIde" in html

    # 4. Anti-XSS Defense Verification
    assert "DOMPurify" in html
    assert "escapeHtml" in html
    assert "sanitizePayload" in html

    # 5. Kali SSH Command Injection Prevention Check
    from core.kali_ssh_bridge import KaliSSHBridge
    assert KaliSSHBridge.sanitize_target("example.com") == "example.com"
    assert KaliSSHBridge.sanitize_target("192.168.1.1") == "192.168.1.1"
    assert KaliSSHBridge.sanitize_target("sub-domain.co.uk") == "sub-domain.co.uk"
    
    for malicious_input in [
        "example.com; id",
        "example.com && rm -rf /",
        "$(whoami)",
        "`id`",
        "example.com | cat /etc/passwd",
        "target.com\nrm -rf /",
        "target.com<script>",
        "target.com' OR '1'='1"
    ]:
        try:
            KaliSSHBridge.sanitize_target(malicious_input)
            assert False, f"Sanitizer failed to reject malicious input: {malicious_input}"
        except ValueError:
            pass  # Expected rejection

    # 6. Local Subdomain Engine Fallback Verification
    import asyncio
    from app import subdomain_engine, get_ssh_settings
    assert subdomain_engine is not None

    # 7. Masked SSH Password Verification
    ssh_settings = asyncio.run(get_ssh_settings())
    assert "password" in ssh_settings
    assert ssh_settings["password"] in ("********", "")
    assert "kali" not in ssh_settings["password"]

    # 8. Kali 1-Liner & Smart Diagnostics Verification
    assert "sudo apt update && sudo apt install -y" in KaliSSHBridge.ONE_LINER_COMMAND
    assert "ffuf" in KaliSSHBridge.REQUIRED_TOOLS
    assert "sslscan" in KaliSSHBridge.REQUIRED_TOOLS
    assert "wafw00f" in KaliSSHBridge.REQUIRED_TOOLS

    unreachable_bridge = KaliSSHBridge("127.0.0.1", user="kali", password="wrongpassword", port=1)
    diag_res = unreachable_bridge.test_connection()
    assert diag_res["reachable"] is False
    assert diag_res["error_code"] in ("HOST_UNREACHABLE", "NETWORK_ERROR", "PORT_22_REFUSED", "AUTH_FAILED")
    assert "guidance" in diag_res
    assert "one_liner" in diag_res

    # 9. Asynchronous DNS Resolution & Stage 2 Windows Decoupling Verification
    from app import resolve_host_async, ReconRequest
    resolved_ips = asyncio.run(resolve_host_async("127.0.0.1", timeout=0.5))
    assert isinstance(resolved_ips, list)

    req_fast = ReconRequest(target="example.com", scan_profile="fast")
    req_deep = ReconRequest(target="example.com", scan_profile="deep")
    assert req_fast.scan_profile == "fast"
    assert req_deep.scan_profile == "deep"

    # 10. Pentester Tools & UI Elements Verification
    assert "exportSubdomainsTxt" in html
    assert "copyCurl" in html
    assert "copyBurpCurl" in html
    assert "scan-profile-fast" in html
    assert "scan-profile-deep" in html
    assert "renderDualTerminalLogs" in html

    # 11. PoC & Evidence Section in Report Generator Verification
    from core.report_generator import ReportGenerator
    dummy_scan = {
        "domain": "target.corp",
        "timestamp": "2026-10-27T12:00:00",
        "subdomain_recon": {"subdomains": [{"subdomain": "api.target.corp", "ip": "1.2.3.4"}]},
        "vulnerabilities": {
            "open_ports": [{"port": 22, "service": "ssh"}, {"port": 3306, "service": "mysql"}],
            "sensitive_files": [{"url": "http://target.corp/.env", "status": 200, "description": "Environment Configuration File"}]
        },
        "js_hunter": {
            "secrets": [{"secret_type": "AWS Access Key", "secret_value": "AKIAIOSFODNN7EXAMPLE", "source_file": "app.js"}],
            "endpoints": [{"endpoint": "/api/v1/users/1337", "method": "GET", "is_bola_candidate": True}]
        },
        "owasp_analysis": {"exposure_score": 50, "security_grade": "F", "top_recommendations": []}
    }
    report_html = ReportGenerator.generate_html_report(dummy_scan)
    assert "Proof of Concept (PoC) & Bằng Chứng Khai Thác (Evidence)" in report_html
    assert "127.0.0.1:8080" in report_html
    assert "poc-card" in report_html
    assert "curl -i -k" in report_html

    # 12. Enterprise Specification Modules Check
    from core.scope_validator import ScopeValidator
    from core.spa_crawler import DynamicSpaCrawler
    from core.auth_session_manager import AuthSessionConfig, AuthSessionManager, BurpSuiteForwarder
    from core.active_bola_validator import UserContext, ActiveAuthorizationValidator

    # Scope Validator
    scope = ScopeValidator(
        whitelist_domains=["*.example.com", "example.com"],
        out_of_scope_domains=["dev.example.com"],
        allow_private_ips=True
    )
    assert asyncio.run(scope.is_in_scope("api.example.com")) is True
    assert asyncio.run(scope.is_in_scope("dev.example.com")) is False
    assert asyncio.run(scope.is_in_scope("bucket.s3.amazonaws.com")) is False

    # SPA Crawler Definitions
    spa = DynamicSpaCrawler()
    assert "image" in spa.BLOCKED_RESOURCE_TYPES

    # Auth & Burp Sitemap
    cfg = AuthSessionConfig(bearer_token="tok123", custom_headers={"X-Test": "1"})
    assert cfg.get_aggregated_headers()["Authorization"] == "Bearer tok123"
    sitemap = BurpSuiteForwarder.export_burp_xml_sitemap("https://corp.com", [{"endpoint": "/api", "method": "GET"}])
    assert "<url>https://corp.com/api</url>" in sitemap

    # Dual-Token Authorization Validator
    user_a = UserContext(name="A", token="tokA", resource_ids=["res1"])
    user_b = UserContext(name="B", token="tokB", resource_ids=["res2"])
    assert user_a.get_auth_headers()["Authorization"] == "Bearer tokA"
    assert ActiveAuthorizationValidator._is_denial_message("Forbidden access") is True

    print("[+] All core assertions, 5 UI features, Smart Diagnostics, Scan Profiles, PoC Engine, and 4 Advanced Modules passed successfully.")

if __name__ == "__main__":
    main()
