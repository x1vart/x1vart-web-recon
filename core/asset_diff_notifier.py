"""
========================================================================================
x1vart Continuous Asset Diffing Engine & Discord Notification Webhook
========================================================================================
Computes attack surface deltas between scans:
- New subdomains discovered / decommissioned
- Newly exposed ports and services
- New Dangling CNAMEs & Subdomain Takeover risks
- Newly leaked secrets & credentials in JS AST
- OWASP API risk score and grade degradation
Sends formatted Discord alerts with colored embeds.
========================================================================================
"""

import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("x1vart.diff_notifier")


class AssetDiffEngine:
    @staticmethod
    def compute_diff(old_scan: Optional[Dict[str, Any]], new_scan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compares two scan datasets and returns a granular breakdown of changes.
        """
        diff = {
            "is_initial_scan": old_scan is None,
            "has_changes": False,
            "has_critical_alerts": False,
            "new_subdomains": [],
            "removed_subdomains": [],
            "new_ports": [],
            "removed_ports": [],
            "new_takeovers": [],
            "new_secrets": [],
            "score_change": {
                "old_score": 100,
                "new_score": 100,
                "old_grade": "A",
                "new_grade": "A",
                "delta": 0,
                "degraded": False
            }
        }

        # Extract new scan items
        new_sub_data = new_scan.get("subdomain_recon", {})
        new_subs_list = [s.get("subdomain") for s in new_sub_data.get("subdomains", []) if s.get("subdomain")]
        new_subs_set = set(new_subs_list)

        new_vulns = new_scan.get("vulnerabilities", {})
        new_ports_list = [p.get("port") for p in new_vulns.get("open_ports", []) if p.get("port")]
        new_ports_set = set(new_ports_list)

        new_takeovers = [
            s.get("subdomain") for s in new_sub_data.get("subdomains", [])
            if s.get("takeover", {}).get("vulnerable")
        ]

        new_secrets_raw = new_scan.get("js_hunter", {}).get("secrets", [])
        new_secrets = [f"{s.get('secret_type')} (Entropy {s.get('entropy')})" for s in new_secrets_raw[:10]]

        new_owasp = new_scan.get("owasp_analysis", {})
        diff["score_change"]["new_score"] = new_owasp.get("exposure_score", 100)
        diff["score_change"]["new_grade"] = new_owasp.get("security_grade", "A")

        if old_scan is None:
            # Baseline scan
            diff["has_changes"] = bool(new_subs_set or new_ports_set or new_takeovers or new_secrets)
            diff["has_critical_alerts"] = bool(new_takeovers or new_secrets)
            diff["new_subdomains"] = list(new_subs_set)
            diff["new_ports"] = list(new_ports_set)
            diff["new_takeovers"] = new_takeovers
            diff["new_secrets"] = new_secrets
            return diff

        # Extract old scan items
        old_sub_data = old_scan.get("subdomain_recon", {})
        old_subs_set = set([s.get("subdomain") for s in old_sub_data.get("subdomains", []) if s.get("subdomain")])

        old_vulns = old_scan.get("vulnerabilities", {})
        old_ports_set = set([p.get("port") for p in old_vulns.get("open_ports", []) if p.get("port")])

        old_takeovers = set([
            s.get("subdomain") for s in old_sub_data.get("subdomains", [])
            if s.get("takeover", {}).get("vulnerable")
        ])

        old_secrets_raw = old_scan.get("js_hunter", {}).get("secrets", [])
        old_secrets_set = set([s.get("secret_value", "") for s in old_secrets_raw if s.get("secret_value")])

        old_owasp = old_scan.get("owasp_analysis", {})
        diff["score_change"]["old_score"] = old_owasp.get("exposure_score", 100)
        diff["score_change"]["old_grade"] = old_owasp.get("security_grade", "A")

        score_delta = diff["score_change"]["new_score"] - diff["score_change"]["old_score"]
        diff["score_change"]["delta"] = score_delta
        diff["score_change"]["degraded"] = score_delta < 0

        # Calculations
        new_subs = list(new_subs_set - old_subs_set)
        removed_subs = list(old_subs_set - new_subs_set)
        new_ports = list(new_ports_set - old_ports_set)
        removed_ports = list(old_ports_set - new_ports_set)
        fresh_takeovers = [t for t in new_takeovers if t not in old_takeovers]
        fresh_secrets = [
            f"{s.get('secret_type')} (Entropy {s.get('entropy')})"
            for s in new_secrets_raw
            if s.get("secret_value") and s.get("secret_value") not in old_secrets_set
        ]

        diff["new_subdomains"] = new_subs
        diff["removed_subdomains"] = removed_subs
        diff["new_ports"] = new_ports
        diff["removed_ports"] = removed_ports
        diff["new_takeovers"] = fresh_takeovers
        diff["new_secrets"] = fresh_secrets

        has_change = bool(
            new_subs or removed_subs or new_ports or removed_ports or
            fresh_takeovers or fresh_secrets or diff["score_change"]["degraded"]
        )
        diff["has_changes"] = has_change
        diff["has_critical_alerts"] = bool(fresh_takeovers or fresh_secrets or new_ports or (score_delta <= -15))

        return diff


class DiscordNotifier:
    @staticmethod
    async def send_diff_alert(
        webhook_url: str,
        domain: str,
        diff: Dict[str, Any],
        scan_id: str,
        target_url: str = ""
    ) -> bool:
        """
        Sends an alert embed to Discord Webhook channel.
        """
        if not webhook_url or not webhook_url.startswith("http"):
            return False

        has_critical = diff.get("has_critical_alerts", False)
        # Red: 0xEF4444 (Critical), Amber: 0xF59E0B (Warnings), Cyan: 0x06B6D4 (Normal)
        embed_color = 0xEF4444 if has_critical else 0xF59E0B

        fields = []

        # 1. New Subdomains
        new_subs = diff.get("new_subdomains", [])
        if new_subs:
            subs_str = "\n".join([f"• `{s}`" for s in new_subs[:8]])
            if len(new_subs) > 8:
                subs_str += f"\n*... và {len(new_subs) - 8} subdomains khác*"
            fields.append({
                "name": f"🌐 Subdomain mới phát hiện (+{len(new_subs)})",
                "value": subs_str,
                "inline": False
            })

        # 2. New Open Ports
        new_ports = diff.get("new_ports", [])
        if new_ports:
            ports_str = ", ".join([f"`Port {p}`" for p in new_ports[:10]])
            fields.append({
                "name": f"⚡ Cổng dịch vụ mới mở (+{len(new_ports)})",
                "value": ports_str,
                "inline": False
            })

        # 3. New Dangling CNAME / Takeovers
        new_takeovers = diff.get("new_takeovers", [])
        if new_takeovers:
            t_str = "\n".join([f"🚨 `{t}` (Dangling CNAME / Potential Takeover)" for t in new_takeovers[:5]])
            fields.append({
                "name": "🔥 CẢNH BÁO SUBDOMAIN TAKEOVER MỚI",
                "value": t_str,
                "inline": False
            })

        # 4. Leaked Secrets
        new_secrets = diff.get("new_secrets", [])
        if new_secrets:
            sec_str = "\n".join([f"🔑 `{s}`" for s in new_secrets[:5]])
            fields.append({
                "name": "🗝️ RÒ RỈ SECRET / API KEY MỚI",
                "value": sec_str,
                "inline": False
            })

        # 5. OWASP Score Change
        sc = diff.get("score_change", {})
        delta_str = f"{sc.get('delta', 0):+d} điểm" if not diff.get("is_initial_scan") else "Khởi tạo Baseline"
        score_info = f"Điểm rủi ro: **{sc.get('new_score')}/100** (Hạng **{sc.get('new_grade')}**) [{delta_str}]"
        fields.append({
            "name": "📊 Điểm đánh giá OWASP API Top 10",
            "value": score_info,
            "inline": False
        })

        # Fallback if no specific fields but has changes
        if not fields:
            fields.append({
                "name": "Thông tin quét",
                "value": "Phát hiện biến động thông số cấu hình bề mặt tấn công.",
                "inline": False
            })

        payload = {
            "username": "x1vart EASM Guardian",
            "avatar_url": "https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/nmap.png",
            "embeds": [
                {
                    "title": f"🚨 [x1vart EASM] Phát hiện thay đổi bề mặt tấn công: {domain}",
                    "description": f"Hệ thống giám sát định kỳ phát hiện tài sản mạng và rủi ro mới trên mục tiêu **{domain}**.\n**Target URL**: {target_url or domain}",
                    "color": embed_color,
                    "fields": fields,
                    "footer": {
                        "text": f"x1vart Continuous Attack Surface Monitor • Scan ID: {scan_id}"
                    }
                }
            ]
        }

        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                resp = await client.post(webhook_url, json=payload)
                if resp.status_code in (200, 204):
                    logger.info(f"Discord alert dispatched successfully to webhook for {domain}")
                    return True
                else:
                    logger.warning(f"Discord webhook rejected with status {resp.status_code}: {resp.text}")
                    return False
        except Exception as e:
            logger.error(f"Failed to send Discord alert: {e}")
            return False

    @staticmethod
    async def test_webhook(webhook_url: str) -> bool:
        """
        Sends a test ping message to verify Discord Webhook configuration.
        """
        if not webhook_url or not webhook_url.startswith("http"):
            return False

        payload = {
            "username": "x1vart EASM Guardian",
            "embeds": [
                {
                    "title": "✅ Kết nối Discord Webhook thành công!",
                    "description": "Kênh này đã được liên kết với hệ thống **x1vart Continuous Attack Surface Monitor**.\nMọi phát hiện về Subdomain mới, Cổng mở, Rò rỉ Secret và Subdomain Takeover sẽ tự động gửi tới đây.",
                    "color": 0x10B981,
                    "footer": {
                        "text": "x1vart Autonomous Recon Engine"
                    }
                }
            ]
        }
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                r = await client.post(webhook_url, json=payload)
                return r.status_code in (200, 204)
        except Exception as e:
            logger.error(f"Webhook test failed: {e}")
            return False
