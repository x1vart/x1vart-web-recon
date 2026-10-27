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

    print("[+] All core assertions & 5 UI features passed successfully.")

if __name__ == "__main__":
    main()
