"""
x1vart Web Recon - Executive Security Audit Report Generator
Produces a self-contained, beautifully formatted HTML report ready for project defense and executive review.
Includes OWASP API Top 10, Exposed Sensitive Files, CORS, Ports & SSL Audit.
"""

from datetime import datetime
from typing import Dict, Any


class ReportGenerator:
    @staticmethod
    def generate_html_report(scan_data: Dict[str, Any]) -> str:
        def _l(v): return v if isinstance(v, list) else []
        def _d(v): return v if isinstance(v, dict) else {}

        scan_data = _d(scan_data)
        target = scan_data.get("target") or scan_data.get("domain") or "Target"
        owasp = _d(scan_data.get("owasp_analysis"))
        summary = _d(scan_data.get("summary"))
        sub_recon = _d(scan_data.get("subdomain_recon"))
        subdomains = _l(scan_data.get("subdomains") or sub_recon.get("subdomains"))
        js_data = _d(scan_data.get("js_hunter"))
        endpoints = _l(scan_data.get("hidden_apis") or js_data.get("endpoints"))
        secrets = _l(scan_data.get("secrets") or js_data.get("secrets"))
        sourcemaps = _l(scan_data.get("source_maps") or scan_data.get("sourcemaps"))
        tech_data = _d(scan_data.get("tech_fingerprint"))
        techs = _l(tech_data.get("technologies"))
        headers = _l(tech_data.get("security_headers"))
        
        vuln = _d(scan_data.get("vulnerabilities"))
        sensitive_files = _l(scan_data.get("exposed_files") or vuln.get("sensitive_files"))
        cors_audit = _d(scan_data.get("cors_audit") or vuln.get("cors_audit"))
        open_ports = _l(scan_data.get("open_ports") or vuln.get("open_ports"))
        ssl_audit = _d(scan_data.get("ssl_info") or vuln.get("ssl_audit"))

        grade = owasp.get("security_grade", "N/A")
        score = owasp.get("exposure_score", 0)
        risk_level = owasp.get("risk_level", "UNKNOWN")
        grade_color = owasp.get("color", "#ef4444")
        findings = owasp.get("findings", [])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html = f"""<!DOCTYPE html>
<html lang="vi">
<head>
    <meta charset="UTF-8">
    <title>Báo Cáo Kiểm Toán Bề Mặt Tấn Công - {target}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Inter', sans-serif; background: #0f172a; color: #e2e8f0; line-height: 1.6; padding: 40px 20px; }}
        .container {{ max-width: 1000px; margin: 0 auto; background: #1e293b; border-radius: 16px; border: 1px solid #334155; padding: 40px; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5); }}
        .header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #334155; padding-bottom: 24px; margin-bottom: 30px; }}
        .brand {{ font-size: 24px; font-weight: 800; color: #38bdf8; letter-spacing: 1px; }}
        .badge {{ font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 4px 8px; border-radius: 6px; background: #0c4a6e; color: #7dd3fc; border: 1px solid #0284c7; }}
        .score-box {{ display: flex; align-items: center; background: #0f172a; border: 1px solid #334155; border-radius: 12px; padding: 20px; margin-bottom: 30px; gap: 30px; }}
        .grade-circle {{ width: 90px; height: 90px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 42px; font-weight: 800; color: #fff; background: {grade_color}; box-shadow: 0 0 20px {grade_color}66; }}
        .score-info h2 {{ font-size: 20px; font-weight: 700; color: #f8fafc; margin-bottom: 4px; }}
        .score-info p {{ font-size: 13px; color: #94a3b8; }}
        .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 35px; }}
        .kpi-card {{ background: #0f172a; border: 1px solid #334155; border-radius: 10px; padding: 15px; }}
        .kpi-title {{ font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: 600; }}
        .kpi-value {{ font-size: 24px; font-weight: 700; color: #f8fafc; margin-top: 5px; }}
        .section-title {{ font-size: 18px; font-weight: 700; color: #38bdf8; margin: 30px 0 15px 0; border-left: 4px solid #38bdf8; padding-left: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 25px; font-size: 13px; }}
        th {{ background: #0f172a; color: #94a3b8; text-align: left; padding: 12px; font-weight: 600; border-bottom: 2px solid #334155; font-family: 'JetBrains Mono', monospace; font-size: 11px; }}
        td {{ padding: 12px; border-bottom: 1px solid #334155; color: #cbd5e1; }}
        tr:hover td {{ background: #243248; }}
        .font-mono {{ font-family: 'JetBrains Mono', monospace; }}
        .sev-crit {{ color: #f87171; font-weight: 700; }}
        .sev-high {{ color: #fb923c; font-weight: 700; }}
        .sev-med {{ color: #facc15; font-weight: 700; }}
        .sev-low {{ color: #38bdf8; }}
        .remed-box {{ background: #022c22; border: 1px solid #059669; border-radius: 8px; padding: 15px; margin-top: 20px; }}
        .remed-box h4 {{ color: #34d399; font-size: 14px; margin-bottom: 8px; }}
        .remed-box ul {{ padding-left: 20px; font-size: 13px; color: #a7f3d0; }}
        .btn-print {{ display: inline-block; background: #0284c7; color: white; padding: 8px 18px; border-radius: 8px; font-weight: 600; font-size: 13px; text-decoration: none; cursor: pointer; border: none; }}
        @media print {{ body {{ background: #fff; color: #000; padding: 0; }} .container {{ border: none; box-shadow: none; padding: 0; background: #fff; color: #000; }} .btn-print {{ display: none; }} td, th {{ color: #000 !important; }} }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">x1vart ATTACK SURFACE REPORT</div>
                <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Hệ thống Quản lý Bề mặt Tấn công & Kiểm toán An toàn API (Community Edition)</div>
            </div>
            <div style="text-align: right;">
                <button class="btn-print" onclick="window.print()">In / Xuất PDF Báo Cáo</button>
                <div style="font-size: 11px; color: #64748b; margin-top: 6px;">Ngày lập: {timestamp}</div>
            </div>
        </div>

        <div class="score-box">
            <div class="grade-circle">{grade}</div>
            <div class="score-info">
                <h2>Mục tiêu: <span class="font-mono text-cyan-400">{target}</span></h2>
                <p>Điểm phơi nhiễm bề mặt: <b style="color: {grade_color}; font-size: 16px;">{score}/100</b> | Mức độ rủi ro: <b style="color: {grade_color};">{risk_level}</b></p>
                <p style="margin-top: 6px;">Đánh giá dựa trên tiêu chuẩn OWASP API Security Top 10 (2023), Shannon Entropy và Quét Lỗ Hổng Chủ Động.</p>
            </div>
        </div>

        <div class="kpi-grid">
            <div class="kpi-card">
                <div class="kpi-title">Tên miền phụ</div>
                <div class="kpi-value">{len(subdomains)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Hidden API Endpoints</div>
                <div class="kpi-value">{len(endpoints)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">Khóa bí mật rò rỉ</div>
                <div class="kpi-value" style="color: #f87171;">{len(secrets)}</div>
            </div>
            <div class="kpi-card">
                <div class="kpi-title">File nhạy cảm / Lỗ hổng</div>
                <div class="kpi-value" style="color: #fb923c;">{len(sensitive_files)}</div>
            </div>
        </div>

        <div class="section-title">1. Đánh giá Mối đe dọa theo OWASP API Security Top 10 (2023)</div>
        <table>
            <thead>
                <tr>
                    <th width="12%">Mã OWASP</th>
                    <th width="28%">Mối Đe Dọa</th>
                    <th width="12%">Mức Độ</th>
                    <th width="48%">Mô Tả & Khuyến Nghị Khắc Phục</th>
                </tr>
            </thead>
            <tbody>
        """

        for f in findings:
            sev_class = "sev-crit" if f["severity"] == "CRITICAL" else ("sev-high" if f["severity"] == "HIGH" else "sev-med")
            html += f"""
                <tr>
                    <td class="font-mono">{f['owasp_id']}</td>
                    <td><b>{f['title']}</b></td>
                    <td class="{sev_class}">{f['severity']}</td>
                    <td>
                        <div>{f['description']}</div>
                        <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;"><b>Khắc phục:</b> {f['remediation']}</div>
                    </td>
                </tr>
            """

        html += f"""
            </tbody>
        </table>

        <div class="section-title">2. Lỗ hổng File Nhạy Cảm & Cấu Hình CORS (Active Scanner)</div>
        <table>
            <thead>
                <tr>
                    <th width="30%">Hạng Mục Kiểm Tra</th>
                    <th width="15%">Mức Độ</th>
                    <th width="35%">Đường Dẫn / Chi Tiết</th>
                    <th width="20%">Bằng Chứng / Snippet</th>
                </tr>
            </thead>
            <tbody>
        """

        if not sensitive_files and not cors_audit.get("vulnerable"):
            html += """<tr><td colspan="4" style="text-align: center; color: #64748b;">Không phát hiện file nhạy cảm hay lỗi CORS công khai.</td></tr>"""
        else:
            for sf in sensitive_files:
                sev_cls = "sev-crit" if sf["severity"] == "CRITICAL" else ("sev-high" if sf["severity"] == "HIGH" else "sev-med")
                html += f"""
                    <tr>
                        <td><b>{sf.get('name')}</b></td>
                        <td class="{sev_cls}">{sf.get('severity')}</td>
                        <td class="font-mono text-cyan-400">{sf.get('url')}</td>
                        <td class="font-mono" style="font-size: 11px;">{sf.get('snippet', '')[:60]}...</td>
                    </tr>
                """
            if cors_audit.get("vulnerable"):
                html += f"""
                    <tr>
                        <td><b>CORS Misconfiguration</b></td>
                        <td class="sev-crit">CRITICAL</td>
                        <td>Reflects arbitrary Origin with Credentials</td>
                        <td class="font-mono" style="font-size: 11px;">Origin: evil-attacker.com</td>
                    </tr>
                """

        html += f"""
            </tbody>
        </table>

        <div class="section-title">3. Danh mục Khóa bí mật bị rò rỉ (Shannon Entropy H &ge; 3.5)</div>
        <table>
            <thead>
                <tr>
                    <th width="25%">Loại Khóa</th>
                    <th width="20%">Shannon Entropy</th>
                    <th width="30%">Mã Bí Mật (Masked)</th>
                    <th width="25%">Tệp Nguồn & Dòng</th>
                </tr>
            </thead>
            <tbody>
        """

        if not secrets:
            html += """<tr><td colspan="4" style="text-align: center; color: #64748b;">Không phát hiện chuỗi khóa bí mật nào.</td></tr>"""
        else:
            for s in secrets:
                html += f"""
                    <tr>
                        <td><b>{s.get('secret_type')}</b></td>
                        <td class="font-mono sev-crit">{s.get('entropy')} bit/char</td>
                        <td class="font-mono">{s.get('masked_value')}</td>
                        <td class="font-mono" style="font-size: 11px;">{s.get('source_file', '').split('/')[-1]}:L{s.get('line_number', 1)}</td>
                    </tr>
                """

        html += f"""
            </tbody>
        </table>

        <div class="section-title">4. Cổng Dịch Vụ Mở & Trạng Thái Chứng Chỉ SSL/TLS</div>
        <table>
            <thead>
                <tr>
                    <th width="15%">Cổng (Port)</th>
                    <th width="25%">Dịch Vụ Phát Hiện</th>
                    <th width="30%">Trạng Thái & Rủi Ro</th>
                    <th width="30%">Chứng Chỉ SSL/TLS</th>
                </tr>
            </thead>
            <tbody>
        """

        if not open_ports:
            html += f"""<tr><td colspan="4" style="text-align: center; color: #64748b;">Không phát hiện cổng mở bất thường. SSL Status: {ssl_audit.get('protocol', 'N/A')} ({'Hợp lệ' if ssl_audit.get('valid') else ssl_audit.get('advisory', 'N/A')})</td></tr>"""
        else:
            for p in open_ports[:8]:
                risk_badge = '<span class="sev-crit">RỦI RO CAO</span>' if p.get("is_risky") else '<span class="sev-low">Normal</span>'
                ssl_info = f"{ssl_audit.get('protocol', 'TLS')} (Còn {ssl_audit.get('days_until_expiration', 'N/A')} ngày)" if p.get('port') in [443, 8443] else "-"
                html += f"""
                    <tr>
                        <td class="font-mono"><b>{p.get('port')}</b></td>
                        <td>{p.get('service')}</td>
                        <td>{risk_badge} - {p.get('risk_note')}</td>
                        <td>{ssl_info}</td>
                    </tr>
                """

        html += f"""
            </tbody>
        </table>

        <div class="section-title">5. Danh mục Hidden API Endpoints & Tham số BOLA / IDOR</div>
        <table>
            <thead>
                <tr>
                    <th width="10%">Method</th>
                    <th width="40%">Endpoint Path</th>
                    <th width="25%">Tham số Phát hiện</th>
                    <th width="25%">Phân loại BOLA</th>
                </tr>
            </thead>
            <tbody>
        """

        if not endpoints:
            html += """<tr><td colspan="4" style="text-align: center; color: #64748b;">Không tìm thấy API endpoints.</td></tr>"""
        else:
            for ep in endpoints:
                bola_badge = '<span class="sev-crit">BOLA TARGET</span>' if ep.get("is_bola_candidate") else '<span style="color: #64748b;">Normal</span>'
                params = ", ".join(ep.get("parameters", [])) or "-"
                html += f"""
                    <tr>
                        <td class="font-mono"><b>{ep.get('method')}</b></td>
                        <td class="font-mono" style="color: #38bdf8;">{ep.get('endpoint')}</td>
                        <td class="font-mono">{params}</td>
                        <td>{bola_badge}</td>
                    </tr>
                """

        html += f"""
            </tbody>
        </table>

        <div class="remed-box">
            <h4>Kế hoạch Khắc phục & Khuyến nghị Bảo mật Ưu tiên:</h4>
            <ul>
                <li>Thu hồi và thay thế ngay lập tức tất cả các Access Key và Secret Token đã bị lộ.</li>
                <li>Chặn truy cập công khai vào các file cấu hình nhạy cảm (<code>/.env</code>, <code>/.git</code>, Spring Boot <code>/actuator</code>).</li>
                <li>Cấu hình chặt chẽ chính sách CORS, không phản hồi tùy tiện header <code>Access-Control-Allow-Origin</code> cùng <code>Access-Control-Allow-Credentials: true</code>.</li>
                <li>Tắt tính năng sinh Source Map (<code>productionSourceMap: false</code>) trong cấu hình Webpack/Vite khi build production.</li>
                <li>Bổ sung kiểm tra quyền sở hữu đối tượng (Object-Level Authorization) đối với các endpoints có tham số định danh <code>{{id}}</code>, <code>{{userId}}</code>.</li>
                <li>Đóng hoặc đặt tường lửa hạn chế đối với các cổng cơ sở dữ liệu mở công khai (3306, 5432, 6379, 27017).</li>
            </ul>
        </div>
    </div>
</body>
</html>
"""
        return html
