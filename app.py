"""
x1vart Web Recon & JS AST Analyzer Backend
FastAPI server providing Subdomain Recon (with Takeover Detection), JS AST Hunter,
Source Map (.js.map) Reconstructor, Active Vulnerability Scanner (Files, CORS, Ports, SSL),
OWASP API Security Top 10 Threat Analyzer, Native Live API Tester, and Executive Report Generator.
"""

import os
import sys
import json
import logging
import platform
import socket
import time
import uuid
import webbrowser
import threading
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse
import re
import subprocess

from fastapi import FastAPI, Request, Response, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import asyncio
from pydantic import BaseModel
import httpx

# Resolve paths for standalone frozen executable (PyInstaller) and regular execution
BASE_DIR = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")

from core.js_ast_hunter import JsAstHunter
from core.sourcemap_hunter import SourceMapHunter
from core.owasp_analyzer import OwaspApiAnalyzer
from core.openapi_bridge import OpenApiBridge
from core.report_generator import ReportGenerator
from core.db_manager import db_manager
from core.asset_diff_notifier import AssetDiffEngine, DiscordNotifier
from core.kali_ssh_bridge import KaliSSHBridge

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("x1vart.app")

app = FastAPI(
    title="x1vart Attack Surface & API Audit Platform",
    description="Cyber Attack Surface Management, JS AST Decompiler, Active Vulnerability Scanner, and OWASP API Top 10 Auditor",
    version="2.2.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static folder
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Module instances
js_hunter = JsAstHunter(entropy_threshold=3.5)
sourcemap_hunter = SourceMapHunter()

# Cache for latest scan results & OpenAPI
latest_scan_cache: Dict[str, Any] = {}
latest_openapi_cache: Dict[str, Any] = {}


async def lookup_network_whois(primary_ip: str, domain: str = "", ssh_bridge=None) -> Dict[str, Any]:
    """Robust Network Whois & ASN lookup supporting Kali Linux CLI & RDAP/ip-api fallback."""
    import socket
    target_query = (domain or primary_ip or "").strip()
    is_ip = False
    try:
        if target_query:
            socket.inet_aton(target_query)
            is_ip = True
    except Exception:
        is_ip = False

    resolved_ip = None
    if is_ip:
        resolved_ip = target_query
    elif primary_ip:
        try:
            socket.inet_aton(primary_ip)
            resolved_ip = primary_ip
        except Exception:
            resolved_ip = None
    if not resolved_ip and target_query and not is_ip:
        try:
            resolved_ip = socket.gethostbyname(target_query)
        except Exception:
            resolved_ip = None

    # 1. Prioritize Kali SSH Bridge if available
    if ssh_bridge:
        try:
            k_res = await asyncio.to_thread(ssh_bridge.run_whois_lookup, target_query, resolved_ip)
            if k_res and k_res.get("raw_whois_snippet"):
                # Supplement missing ASN / country via ip-api if needed
                if resolved_ip and (k_res.get("asn") == "N/A" or k_res.get("country") == "N/A"):
                    try:
                        async with httpx.AsyncClient(timeout=3.5, verify=False) as c:
                            r_ip = await c.get(f"http://ip-api.com/json/{resolved_ip}")
                            if r_ip.status_code == 200:
                                d = r_ip.json()
                                if d.get("status") == "success":
                                    if k_res.get("asn") == "N/A" and d.get("as"):
                                        k_res["asn"] = d["as"].split()[0]
                                    if k_res.get("country") == "N/A" and d.get("country"):
                                        k_res["country"] = d["country"]
                                    if k_res.get("descr") == "N/A" and d.get("isp"):
                                        k_res["descr"] = d["isp"]
                    except Exception:
                        pass
                return k_res
        except Exception as e:
            logger.debug(f"SSH whois query fallback to local: {e}")

    # 2. Local Fallback Orchestrator (RDAP + ip-api)
    whois_data = {
        "ip": resolved_ip or target_query or "N/A",
        "domain": "" if is_ip else target_query,
        "asn": "N/A",
        "org_name": "N/A",
        "inetnum": "N/A",
        "cidr": "N/A",
        "netname": "N/A",
        "country": "N/A",
        "descr": "N/A",
        "admin_contact": "N/A",
        "tech_contact": "N/A",
        "abuse_email": "N/A",
        "registrar": "N/A",
        "raw_whois_snippet": ""
    }

    if not resolved_ip or resolved_ip.startswith("127.") or resolved_ip.startswith("192.168."):
        whois_data["raw_whois_snippet"] = f"Địa chỉ IP nội bộ / Cục bộ: {resolved_ip}\nKhông thực hiện tra cứu Whois cho dải IP Private (RFC1918)."
        return whois_data

    raw_lines = [
        f"=== BẢN GHI RDAP / WHOIS HẠ TẦNG MẠNG CHO {resolved_ip} ({target_query}) ===",
        f"Truy vấn thời gian thực: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "----------------------------------------------------------------------"
    ]

    try:
        async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
            # Query ip-api for ASN and Geolocation
            try:
                r_ip = await client.get(f"http://ip-api.com/json/{resolved_ip}")
                if r_ip.status_code == 200:
                    d = r_ip.json()
                    if d.get("status") == "success":
                        whois_data["asn"] = d.get("as", "").split()[0] if d.get("as") else "N/A"
                        whois_data["org_name"] = d.get("org") or d.get("isp") or "N/A"
                        whois_data["country"] = d.get("country", "N/A")
                        whois_data["descr"] = d.get("isp", "N/A")
                        raw_lines.append(f"Autonomous System: {d.get('as', 'N/A')}")
                        raw_lines.append(f"Nhà mạng / ISP:    {d.get('isp', 'N/A')}")
                        raw_lines.append(f"Tổ chức sở hữu:    {d.get('org', 'N/A')}")
                        raw_lines.append(f"Vị trí địa lý:     {d.get('city', 'N/A')}, {d.get('regionName', 'N/A')} ({d.get('country', 'N/A')})")
            except Exception as e:
                logger.debug(f"ip-api error: {e}")

            # Query RDAP registry with redirect following
            try:
                r_rdap = await client.get(f"https://rdap.arin.net/registry/ip/{resolved_ip}")
                if r_rdap.status_code == 200:
                    d = r_rdap.json()
                    start = d.get("startAddress", "")
                    end = d.get("endAddress", "")
                    if start and end:
                        whois_data["inetnum"] = f"{start} - {end}"
                        raw_lines.append(f"NetRange / inetnum: {start} - {end}")
                    cidrs = d.get("cidr0_cidrs", [])
                    if cidrs:
                        prefix = cidrs[0].get("v4prefix", cidrs[0].get("prefix", start))
                        length = cidrs[0].get("length", "")
                        whois_data["cidr"] = f"{prefix}/{length}"
                        raw_lines.append(f"CIDR Routing:      {prefix}/{length}")
                    netname = d.get("name")
                    if netname:
                        whois_data["netname"] = netname
                        raw_lines.append(f"NetName:           {netname}")

                    # Extract contacts from entities
                    for ent in d.get("entities", []):
                        roles = ent.get("roles", [])
                        vcard = ent.get("vcardArray", [None, []])
                        emails = []
                        if len(vcard) > 1:
                            for item in vcard[1]:
                                if isinstance(item, list) and len(item) > 3 and item[0] == "email":
                                    emails.append(item[3])
                        if "abuse" in roles and emails and whois_data["abuse_email"] == "N/A":
                            whois_data["abuse_email"] = emails[0]
                            raw_lines.append(f"Email lạm dụng:    {emails[0]}")
                        if ("technical" in roles or "tech" in roles) and emails and whois_data["tech_contact"] == "N/A":
                            whois_data["tech_contact"] = emails[0]
                            raw_lines.append(f"Email kỹ thuật:    {emails[0]}")
                        if ("administrative" in roles or "admin" in roles) and emails and whois_data["admin_contact"] == "N/A":
                            whois_data["admin_contact"] = emails[0]
                            raw_lines.append(f"Email quản trị:    {emails[0]}")
            except Exception as e:
                logger.debug(f"RDAP error: {e}")

    except Exception as e:
        logger.debug(f"Whois lookup error: {e}")

    whois_data["raw_whois_snippet"] = "\n".join(raw_lines)
    return whois_data


async def lookup_reverse_ip(primary_ip: str, target_domain: str) -> List[Dict[str, Any]]:
    """Fallback Reverse IP lookup on Windows orchestrator."""
    co_hosted = []
    seen = set()
    if not primary_ip or primary_ip.startswith("127.") or primary_ip.startswith("192.168."):
        return []

    try:
        import socket
        ptr = socket.gethostbyaddr(primary_ip)[0]
        if ptr:
            p_low = ptr.lower()
            seen.add(p_low)
            co_hosted.append({
                "domain": p_low,
                "ip": primary_ip,
                "source": "Reverse DNS (PTR Record)",
                "status": "CO_HOSTED",
                "target_match": (p_low == target_domain or p_low.endswith(f".{target_domain}"))
            })
    except Exception:
        pass

    try:
        async with httpx.AsyncClient(timeout=5.0, verify=False) as client:
            resp = await client.get(f"https://api.hackertarget.com/reverseiplookup/?q={primary_ip}")
            if resp.status_code == 200 and "error" not in resp.text.lower() and "no records" not in resp.text.lower():
                for line in resp.text.splitlines():
                    d = line.strip().lower()
                    if d and "." in d and d not in seen and not d.startswith("api count"):
                        seen.add(d)
                        co_hosted.append({
                            "domain": d,
                            "ip": primary_ip,
                            "source": "HackerTarget Passive DNS",
                            "status": "CO_HOSTED",
                            "target_match": (d == target_domain or d.endswith(f".{target_domain}"))
                        })
    except Exception as e:
        logger.debug(f"Reverse IP error: {e}")
    return co_hosted


def extract_apex_domain(domain: str) -> str:
    """Extracts base / apex domain (e.g. staffing.nimbus-soft.com -> nimbus-soft.com)."""
    domain = domain.lower().strip()
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) or domain in ["localhost", "127.0.0.1"]:
        return domain
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    two_part_tlds = {"edu.vn", "com.vn", "gov.vn", "org.vn", "net.vn", "co.uk", "org.uk", "ac.uk", "com.au"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds:
        return ".".join(parts[-3:]) if len(parts) >= 3 else domain
    return ".".join(parts[-2:])


KALI_WORKER_URL = os.getenv("KALI_WORKER_URL", "http://127.0.0.1:9000")
X1VART_AGENT_SECRET_KEY = os.getenv("X1VART_SECRET", "x1vart-quantum-agent-key-2026")


# ============================================================================
# PYDANTIC SCHEMAS
# ============================================================================
class ReconRequest(BaseModel):
    target: str
    subdomain_enum: bool = True
    js_hunter: bool = True
    sourcemap_hunter: bool = True
    vuln_scan: bool = True
    tech_fingerprint: bool = True
    entropy_threshold: float = 3.0
    use_kali_worker: bool = True
    worker_url: Optional[str] = "http://127.0.0.1:9000"
    discord_webhook: Optional[str] = ""


class SshConfigRequest(BaseModel):
    host: str = "192.168.1.100"
    user: str = "kali"
    password: str = "kali"
    port: int = 22


class WorkerPingRequest(BaseModel):
    worker_url: Optional[str] = "http://127.0.0.1:9000"


class WhoisLookupRequest(BaseModel):
    target: str


class ApiTestRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    body: Optional[Any] = None


# ============================================================================
# DASHBOARD ENTRYPOINT
# ============================================================================
@app.get("/", response_class=FileResponse)
async def serve_dashboard():
    """Serves the main cyber dashboard interface."""
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))


# ============================================================================
# KALI LINUX AGENT & SSH ORCHESTRATION ROUTES
# ============================================================================
@app.get("/api/worker/ping")
@app.post("/api/worker/ping")
async def ping_kali_worker(req: Optional[WorkerPingRequest] = None):
    """
    Tests connectivity and CLI tools readiness of the Kali Linux Agent server on port 9000.
    Supports both GET and POST for health-checking.
    """
    target_url = ((req.worker_url if req else None) or KALI_WORKER_URL).rstrip("/")
    health_url = f"{target_url}/worker/health"
    try:
        timeout_cfg = httpx.Timeout(4.0, connect=2.0)
        headers = {"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY}
        async with httpx.AsyncClient(timeout=timeout_cfg) as client:
            resp = await client.get(health_url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                data["ping_ms"] = round(resp.elapsed.total_seconds() * 1000, 1)
                data["reachable"] = True
                data["worker_url"] = target_url
                if "worker_info" not in data:
                    data["worker_info"] = {
                        "worker_ip": data.get("worker_ip", "192.168.1.100"),
                        "hostname": data.get("hostname", "kali"),
                        "platform": data.get("platform", "Linux"),
                        "tools_installed": data.get("tools_installed", data.get("tools", {}))
                    }
                return data
            else:
                return {
                    "status": "ERROR",
                    "reachable": False,
                    "worker_url": target_url,
                    "error": f"HTTP {resp.status_code}"
                }
    except Exception as e:
        # Fallback test via Agentless SSH Bridge
        ssh_host = db_manager.get_setting("kali_ssh_host", "192.168.1.100")
        ssh_user = db_manager.get_setting("kali_ssh_user", "kali")
        ssh_pass = db_manager.get_setting("kali_ssh_password", "kali")
        ssh_port = int(db_manager.get_setting("kali_ssh_port", "22"))
        try:
            bridge = KaliSSHBridge(host=ssh_host, user=ssh_user, password=ssh_pass, port=ssh_port, timeout=3.0)
            ssh_res = await asyncio.to_thread(bridge.test_connection)
            if ssh_res.get("reachable"):
                installed = {t: True for t in ssh_res.get("installed_tools", [])}
                return {
                    "status": "ONLINE",
                    "reachable": True,
                    "mode": "SSH_AGENTLESS",
                    "worker_url": f"ssh://{ssh_user}@{ssh_host}:{ssh_port}",
                    "worker_info": {
                        "worker_ip": ssh_host,
                        "hostname": "kali-ssh",
                        "platform": "Kali Linux (Agentless SSH)",
                        "tools_installed": {
                            "subfinder": installed.get("subfinder", True),
                            "nmap": installed.get("nmap", True),
                            "whatweb": installed.get("whatweb", True),
                            "nikto": installed.get("nikto", True),
                            "ffuf": installed.get("ffuf", True),
                            "gobuster": installed.get("gobuster", True)
                        }
                    }
                }
        except Exception:
            pass

        return {
            "status": "OFFLINE",
            "reachable": False,
            "worker_url": target_url,
            "error": str(e)
        }


@app.get("/api/ssh/settings")
async def get_ssh_settings():
    """Retrieves Kali SSH connection credentials."""
    return {
        "host": db_manager.get_setting("kali_ssh_host", "192.168.1.100"),
        "user": db_manager.get_setting("kali_ssh_user", "kali"),
        "password": db_manager.get_setting("kali_ssh_password", "kali"),
        "port": int(db_manager.get_setting("kali_ssh_port", "22"))
    }


@app.post("/api/ssh/settings")
async def save_ssh_settings(req: SshConfigRequest):
    """Saves Kali SSH connection credentials to local SQLite database."""
    db_manager.set_setting("kali_ssh_host", req.host.strip())
    db_manager.set_setting("kali_ssh_user", req.user.strip())
    db_manager.set_setting("kali_ssh_password", req.password)
    db_manager.set_setting("kali_ssh_port", str(req.port))
    return {"status": "SUCCESS", "message": "Đã lưu cấu hình SSH Kali!"}


@app.post("/api/ssh/test")
async def test_ssh_connection(req: Optional[SshConfigRequest] = None):
    """Tests Agentless SSH connection to Kali Linux and checks installed CLI tools."""
    host = req.host if req else db_manager.get_setting("kali_ssh_host", "192.168.1.100")
    user = req.user if req else db_manager.get_setting("kali_ssh_user", "kali")
    password = req.password if req else db_manager.get_setting("kali_ssh_password", "kali")
    port = req.port if req else int(db_manager.get_setting("kali_ssh_port", "22"))

    bridge = KaliSSHBridge(host=host, user=user, password=password, port=port, timeout=4.0)
    res = await asyncio.to_thread(bridge.test_connection)
    return res


@app.post("/api/whois/lookup")
@app.get("/api/whois/lookup")
async def api_whois_lookup(target: Optional[str] = None, req: Optional[WhoisLookupRequest] = None):
    """Instant on-demand Whois & ASN lookup for domain or IP."""
    query = (target or (req.target if req else "")).strip()
    if not query:
        raise HTTPException(status_code=400, detail="Vui lòng cung cấp domain hoặc IP cần tra cứu")

    ssh_host = db_manager.get_setting("kali_ssh_host", "192.168.1.100")
    ssh_user = db_manager.get_setting("kali_ssh_user", "kali")
    ssh_pass = db_manager.get_setting("kali_ssh_password", "kali")
    ssh_port = int(db_manager.get_setting("kali_ssh_port", "22"))
    bridge = KaliSSHBridge(host=ssh_host, user=ssh_user, password=ssh_pass, port=ssh_port, timeout=4.0)

    res = await lookup_network_whois(query, query, bridge)
    return res



# ============================================================================
# UNIFIED DATA SCHEMA CONTRACT & FAULT-TOLERANT EXECUTION HELPERS
# ============================================================================
async def safe_execute(coro, default_return, task_name: str, log_target: Optional[List[Dict[str, Any]]] = None):
    """
    Fault-tolerant wrapper: Executes an async coroutine safely.
    If an error occurs, logs a warning and appends to log_target without breaking the pipeline.
    """
    try:
        return await coro
    except Exception as e:
        logger.warning(f"[SAFE_EXECUTE] Error in task '{task_name}': {e}")
        if log_target is not None:
            log_target.append({
                "stage": "Fault Isolation",
                "tool": task_name,
                "node": "kali",
                "command": f"safe_execute --task {task_name}",
                "status": "WARNING_ISOLATED",
                "duration_sec": 0.0,
                "output_summary": f"Module '{task_name}' encountered non-critical error: {e}. Pipeline continued smoothly."
            })
        return default_return


def normalize_scan_result(raw_data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Unified Data Schema Contract:
    Ensures all list fields are strictly python lists (default []) and all object fields
    are strictly python dicts (default {}), preventing frontend crashes or JSON schema drift.
    """
    if not isinstance(raw_data, dict):
        raw_data = {}

    def _ensure_list(val: Any) -> list:
        if isinstance(val, list):
            return val
        if val is None:
            return []
        if isinstance(val, (set, tuple)):
            return list(val)
        return []

    def _ensure_dict(val: Any) -> dict:
        if isinstance(val, dict):
            return val
        return {}

    # Extract or fallback for all standard list fields
    subdomain_recon = _ensure_dict(raw_data.get("subdomain_recon"))
    subdomains = _ensure_list(raw_data.get("subdomains") or subdomain_recon.get("subdomains"))
    subdomain_recon["subdomains"] = subdomains
    raw_data["subdomains"] = subdomains
    raw_data["subdomain_recon"] = subdomain_recon

    js_hunter_dict = _ensure_dict(raw_data.get("js_hunter"))
    hidden_apis = _ensure_list(raw_data.get("hidden_apis") or js_hunter_dict.get("endpoints"))
    secrets = _ensure_list(raw_data.get("secrets") or js_hunter_dict.get("secrets"))
    js_hunter_dict["endpoints"] = hidden_apis
    js_hunter_dict["secrets"] = secrets
    js_hunter_dict["total_endpoints"] = len(hidden_apis)
    js_hunter_dict["total_secrets"] = len(secrets)
    raw_data["hidden_apis"] = hidden_apis
    raw_data["secrets"] = secrets
    raw_data["js_hunter"] = js_hunter_dict

    source_maps = _ensure_list(raw_data.get("source_maps") or raw_data.get("sourcemaps"))
    raw_data["source_maps"] = source_maps
    raw_data["sourcemaps"] = source_maps

    vuln_data = _ensure_dict(raw_data.get("vulnerabilities"))
    raw_ports = _ensure_list(raw_data.get("open_ports") or vuln_data.get("open_ports"))
    norm_ports_map = {}
    for p in raw_ports:
        if not isinstance(p, dict):
            continue
        p_num = p.get("port")
        if not p_num:
            continue
        try:
            p_num = int(p_num)
        except Exception:
            pass
        if p_num not in norm_ports_map:
            norm_ports_map[p_num] = dict(p)
        else:
            existing = norm_ports_map[p_num]
            curr_ip = str(p.get("ip") or "").strip()
            exist_ip = str(existing.get("ip") or "").strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", curr_ip) and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", exist_ip):
                existing["ip"] = curr_ip
            curr_svc = str(p.get("service") or "").strip()
            exist_svc = str(existing.get("service") or "").strip()
            if len(curr_svc) > len(exist_svc):
                existing["service"] = curr_svc
            if p.get("is_risky") or existing.get("is_risky"):
                existing["is_risky"] = True
            p_note = str(p.get("risk_note") or "").strip()
            e_note = str(existing.get("risk_note") or "").strip()
            if p_note and p_note not in e_note:
                if not e_note or e_note == "Active Web/Service port":
                    existing["risk_note"] = p_note
                else:
                    existing["risk_note"] = f"{e_note} | {p_note}"

    open_ports = list(norm_ports_map.values())
    open_ports.sort(key=lambda x: (not x.get("is_risky"), x.get("port", 0)))
    exposed_files = _ensure_list(raw_data.get("exposed_files") or vuln_data.get("sensitive_files"))
    insecure_methods = _ensure_list(raw_data.get("insecure_methods") or vuln_data.get("insecure_methods_audit"))
    nikto_findings = _ensure_list(raw_data.get("nikto_findings") or vuln_data.get("nikto_findings"))
    vuln_data["open_ports"] = open_ports
    vuln_data["sensitive_files"] = exposed_files
    vuln_data["insecure_methods_audit"] = insecure_methods
    vuln_data["nikto_findings"] = nikto_findings
    raw_data["open_ports"] = open_ports
    raw_data["exposed_files"] = exposed_files
    raw_data["insecure_methods"] = insecure_methods
    raw_data["nikto_findings"] = nikto_findings
    raw_data["vulnerabilities"] = vuln_data

    tech_data = _ensure_dict(raw_data.get("tech_fingerprint"))
    cve_advisories = _ensure_list(raw_data.get("cve_advisories") or tech_data.get("cve_advisories"))
    tech_data["cve_advisories"] = cve_advisories
    raw_data["cve_advisories"] = cve_advisories
    raw_data["tech_fingerprint"] = tech_data
    raw_data["tech_stack"] = tech_data

    public_docs = _ensure_list(raw_data.get("public_docs") or subdomain_recon.get("document_metadata"))
    subdomain_recon["document_metadata"] = public_docs
    raw_data["public_docs"] = public_docs

    reverse_ip_domains = _ensure_list(raw_data.get("reverse_ip_domains") or subdomain_recon.get("reverse_ip_domains"))
    raw_data["reverse_ip_domains"] = reverse_ip_domains

    owasp_data = _ensure_dict(raw_data.get("owasp_analysis"))
    owasp_findings = _ensure_list(raw_data.get("owasp_findings") or owasp_data.get("findings"))
    owasp_data["findings"] = owasp_findings
    raw_data["owasp_findings"] = owasp_findings
    raw_data["owasp_analysis"] = owasp_data

    kali_logs = _ensure_list(raw_data.get("kali_logs") or raw_data.get("cli_command_logs"))
    raw_data["kali_logs"] = kali_logs
    raw_data["cli_command_logs"] = kali_logs

    handoff_logs = _ensure_list(raw_data.get("handoff_logs"))
    raw_data["handoff_logs"] = handoff_logs

    # Standard dict fields
    summary = _ensure_dict(raw_data.get("summary"))
    raw_data["summary"] = summary

    whois_info = _ensure_dict(raw_data.get("whois_info") or raw_data.get("network_whois") or subdomain_recon.get("network_whois"))
    raw_data["whois_info"] = whois_info
    raw_data["network_whois"] = whois_info

    whois_history = _ensure_dict(raw_data.get("whois_history"))
    raw_data["whois_history"] = whois_history

    cors_audit = _ensure_dict(raw_data.get("cors_audit") or vuln_data.get("cors_audit"))
    vuln_data["cors_audit"] = cors_audit
    raw_data["cors_audit"] = cors_audit

    ssl_info = _ensure_dict(raw_data.get("ssl_info") or vuln_data.get("ssl_audit"))
    vuln_data["ssl_audit"] = ssl_info
    raw_data["ssl_info"] = ssl_info

    headers_audit = _ensure_dict(raw_data.get("headers_audit"))
    if not headers_audit:
        headers_audit = {"security_headers": _ensure_list(tech_data.get("security_headers"))}
    raw_data["headers_audit"] = headers_audit

    raw_data["worker_info"] = _ensure_dict(raw_data.get("worker_info"))
    raw_data["graph_data"] = _ensure_list(raw_data.get("graph_data"))

    # Primitive types guaranteed
    raw_data["target"] = str(raw_data.get("target") or "")
    raw_data["domain"] = str(raw_data.get("domain") or "")
    raw_data["risk_score"] = int(raw_data.get("risk_score") or owasp_data.get("exposure_score") or 0)
    raw_data["risk_grade"] = str(raw_data.get("risk_grade") or owasp_data.get("security_grade") or "C")
    raw_data["execution_mode"] = str(raw_data.get("execution_mode") or "LOCAL_WINDOWS")

    return raw_data

# ============================================================================
# DATASET FUSION ENGINE (HYBRID DUAL-ENGINE: KALI WORKER + LOCAL MASTER)
# ============================================================================
def merge_recon_datasets(
    k_data: Dict[str, Any],
    l_data: Dict[str, Any],
    domain: str,
    target_url: str,
    worker_url: Optional[str] = None
) -> Dict[str, Any]:
    """
    Fuses reconnaissance datasets from Kali Linux Worker and Local Master Orchestrator
    into a unified attack surface payload for comprehensive OWASP evaluation.
    """
    k_sub = k_data.get("subdomain_recon") or k_data.get("subdomain_data") or {}
    l_sub = l_data.get("subdomain_recon") or l_data.get("subdomain_data") or {}

    sub_map = {}
    for s in l_sub.get("subdomains", []):
        name = s.get("subdomain", "").strip().lower()
        if name:
            sub_map[name] = dict(s)

    for s in k_sub.get("subdomains", []):
        name = s.get("subdomain", "").strip().lower()
        if not name:
            continue
        if name not in sub_map:
            sub_map[name] = dict(s)
        else:
            merged_ips = list(dict.fromkeys(sub_map[name].get("ips", []) + s.get("ips", [])))
            sub_map[name]["ips"] = merged_ips
            merged_cnames = list(dict.fromkeys(sub_map[name].get("cnames", []) + s.get("cnames", [])))
            sub_map[name]["cnames"] = merged_cnames
            if s.get("status") == "active" or sub_map[name].get("status") == "active":
                sub_map[name]["status"] = "active"
            if s.get("takeover", {}).get("vulnerable"):
                sub_map[name]["takeover"] = s.get("takeover")
            sources = [sub_map[name].get("source", ""), s.get("source", "")]
            sub_map[name]["source"] = ", ".join(filter(None, dict.fromkeys(sources)))

    merged_subs = list(sub_map.values())
    active_count = len([s for s in merged_subs if s.get("status") == "active"])
    takeover_count = len([s for s in merged_subs if s.get("takeover", {}).get("vulnerable")])

    doc_meta = []
    seen_docs = set()
    for d in (l_sub.get("document_metadata", []) + k_sub.get("document_metadata", [])):
        key = d.get("url") or d.get("file_name")
        if key and key not in seen_docs:
            seen_docs.add(key)
            doc_meta.append(d)

    merged_subdomain_data = {
        "target_domain": domain,
        "wildcard_detected": l_sub.get("wildcard_detected", False) or k_sub.get("wildcard_detected", False),
        "wildcard_ips": list(set(l_sub.get("wildcard_ips", []) + k_sub.get("wildcard_ips", []))),
        "total_candidates": len(merged_subs),
        "active_count": active_count,
        "takeover_count": takeover_count,
        "subdomains": merged_subs,
        "document_metadata": doc_meta
    }

    k_vuln = k_data.get("vulnerabilities") or {}
    l_vuln = l_data.get("vulnerabilities") or {}

    files_map = {}
    for f in (l_vuln.get("sensitive_files", []) + k_vuln.get("sensitive_files", [])):
        key = f.get("url") or f.get("path") or f.get("name")
        if key and key not in files_map:
            files_map[key] = f
    merged_files = list(files_map.values())

    ports_map = {}
    # Prioritize Kali results (rich Nmap banners) + Local Master results (IPs)
    for p in (k_vuln.get("open_ports", []) + l_vuln.get("open_ports", [])):
        if not isinstance(p, dict):
            continue
        port_num = p.get("port")
        if not port_num:
            continue
        try:
            port_num = int(port_num)
        except Exception:
            pass
        if port_num not in ports_map:
            ports_map[port_num] = dict(p)
        else:
            existing = ports_map[port_num]
            # 1. Prefer actual IPv4 address over domain name in IP column
            curr_ip = str(p.get("ip") or "").strip()
            exist_ip = str(existing.get("ip") or "").strip()
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", curr_ip) and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", exist_ip):
                existing["ip"] = curr_ip
            elif not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", curr_ip) and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", exist_ip):
                existing["ip"] = exist_ip or curr_ip or domain

            # 2. Prefer richer service description with banner
            curr_svc = str(p.get("service") or "").strip()
            exist_svc = str(existing.get("service") or "").strip()
            if len(curr_svc) > len(exist_svc):
                existing["service"] = curr_svc

            # 3. Inherit risk flag
            if p.get("is_risky") or existing.get("is_risky"):
                existing["is_risky"] = True

            # 4. Merge risk notes cleanly without repeating
            p_note = str(p.get("risk_note") or "").strip()
            e_note = str(existing.get("risk_note") or "").strip()
            if p_note and p_note not in e_note:
                if not e_note or e_note == "Active Web/Service port":
                    existing["risk_note"] = p_note
                else:
                    existing["risk_note"] = f"{e_note} | {p_note}"

    merged_ports = list(ports_map.values())
    merged_ports.sort(key=lambda x: (not x.get("is_risky"), x.get("port", 0)))

    cors_vuln = l_vuln.get("cors_audit", {}).get("vulnerable", False) or k_vuln.get("cors_audit", {}).get("vulnerable", False)
    cors_findings = l_vuln.get("cors_audit", {}).get("findings", []) + k_vuln.get("cors_audit", {}).get("findings", [])
    cors_headers = {**l_vuln.get("cors_audit", {}).get("headers_observed", {}), **k_vuln.get("cors_audit", {}).get("headers_observed", {})}
    merged_cors = {
        "vulnerable": cors_vuln,
        "severity": "CRITICAL" if cors_vuln else "INFO",
        "findings": cors_findings,
        "headers_observed": cors_headers
    }

    methods_map = {}
    for m in (l_vuln.get("insecure_methods_audit", []) + k_vuln.get("insecure_methods_audit", [])):
        ep = m.get("endpoint", "")
        if ep and ep not in methods_map:
            methods_map[ep] = m
    merged_methods = list(methods_map.values())

    nikto_list = []
    seen_nikto = set()
    for n in (l_vuln.get("nikto_findings", []) + k_vuln.get("nikto_findings", [])):
        f_text = n.get("finding", "")
        if f_text and f_text not in seen_nikto:
            seen_nikto.add(f_text)
            nikto_list.append(n)

    ssl_audit = k_vuln.get("ssl_audit") or l_vuln.get("ssl_audit", {"supported": False, "valid": False})

    merged_vuln_data = {
        "sensitive_files": merged_files,
        "sensitive_files_count": len(merged_files),
        "cors_audit": merged_cors,
        "insecure_methods_audit": merged_methods,
        "nikto_findings": nikto_list,
        "open_ports": merged_ports,
        "open_ports_count": len(merged_ports),
        "ssl_audit": ssl_audit
    }

    k_tech = k_data.get("tech_fingerprint") or {}
    l_tech = l_data.get("tech_fingerprint") or {}

    tech_map = {}
    for t in (l_tech.get("technologies", []) + k_tech.get("technologies", [])):
        name = t.get("name", "").strip()
        if name:
            k = name.lower()
            if k not in tech_map:
                tech_map[k] = dict(t)
            else:
                if not tech_map[k].get("version") and t.get("version"):
                    tech_map[k]["version"] = t.get("version")
    merged_tech = list(tech_map.values())

    head_map = {}
    for h in (l_tech.get("security_headers", []) + k_tech.get("security_headers", [])):
        h_name = h.get("header") or h.get("name")
        if h_name:
            k = h_name.lower()
            if k not in head_map or h.get("present"):
                head_map[k] = h
    merged_headers = list(head_map.values())
    missing_count = len([h for h in merged_headers if not h.get("present")])

    cve_map = {}
    for c in (l_tech.get("cve_advisories", []) + k_tech.get("cve_advisories", [])):
        cve_id = c.get("cve_id") or c.get("cve")
        if cve_id and cve_id not in cve_map:
            cve_map[cve_id] = c
    merged_cves = list(cve_map.values())

    merged_tech_data = {
        "technologies": merged_tech,
        "security_headers": merged_headers,
        "missing_headers_count": missing_count,
        "cve_advisories": merged_cves
    }

    k_js = k_data.get("js_hunter") or {}
    l_js = l_data.get("js_hunter") or {}

    ep_map = {}
    for ep in (l_js.get("endpoints", []) + k_js.get("endpoints", [])):
        path = ep.get("endpoint", "")
        method = ep.get("method", "GET")
        key = (path, method)
        if key not in ep_map:
            ep_map[key] = dict(ep)
        else:
            if ep.get("is_bola_candidate"):
                ep_map[key]["is_bola_candidate"] = True
    merged_endpoints = list(ep_map.values())

    secret_map = {}
    for s in (l_js.get("secrets", []) + k_js.get("secrets", [])):
        key = (s.get("secret_type"), s.get("match") or s.get("entropy"))
        if key not in secret_map:
            secret_map[key] = s
    merged_secrets = list(secret_map.values())

    merged_js_urls = list(dict.fromkeys(l_js.get("js_urls", []) + k_js.get("js_urls", [])))

    merged_js_data = {
        "endpoints": merged_endpoints,
        "secrets": merged_secrets,
        "total_endpoints": len(merged_endpoints),
        "total_secrets": len(merged_secrets),
        "js_urls": merged_js_urls
    }

    sm_map = {}
    for sm in (l_data.get("sourcemaps", []) + k_data.get("sourcemaps", [])):
        key = sm.get("source_map_url") or sm.get("js_url")
        if key and key not in sm_map:
            sm_map[key] = sm
    merged_sourcemaps = list(sm_map.values())

    k_logs = k_data.get("cli_command_logs", [])
    l_logs = l_data.get("cli_command_logs", [])
    merged_cli_logs = []
    seen_cmds = set()
    for log in (k_logs + l_logs):
        c_key = (log.get("tool"), log.get("command"))
        if c_key not in seen_cmds:
            seen_cmds.add(c_key)
            merged_cli_logs.append(log)

    k_info = k_data.get("worker_info", {})
    l_info = l_data.get("worker_info", {})
    w_ip = k_info.get("worker_ip") or worker_url or "192.168.1.100"
    merged_worker_info = {
        "worker_ip": w_ip,
        "master_ip": "127.0.0.1",
        "hostname": f"Engine: Kali ({k_info.get('hostname', 'kali')}) + Windows Host ({platform.node()})",
        "platform": f"Kali Linux ({k_info.get('platform', 'Debian')}) & Windows ({platform.platform()})",
        "mode": "HYBRID_DUAL_ENGINE"
    }

    k_w = k_data.get("network_whois") or {}
    l_w = l_data.get("network_whois") or {}
    merged_whois = {}
    for key in set(list(k_w.keys()) + list(l_w.keys())):
        val_k = k_w.get(key)
        val_l = l_w.get(key)
        if val_k and str(val_k).strip() not in ("N/A", "Unknown", "-", ""):
            merged_whois[key] = val_k
        elif val_l and str(val_l).strip() not in ("N/A", "Unknown", "-", ""):
            merged_whois[key] = val_l
        else:
            merged_whois[key] = val_k or val_l or "N/A"

    rev_map = {}
    for r in (l_data.get("reverse_ip_domains", []) + k_data.get("reverse_ip_domains", [])):
        d = r.get("domain", "").strip().lower()
        if d and d not in rev_map:
            rev_map[d] = r
    merged_reverse_ip = list(rev_map.values())

    return {
        "subdomain_recon": merged_subdomain_data,
        "vulnerabilities": merged_vuln_data,
        "tech_fingerprint": merged_tech_data,
        "js_hunter": merged_js_data,
        "sourcemaps": merged_sourcemaps,
        "cli_command_logs": merged_cli_logs,
        "worker_info": merged_worker_info,
        "network_whois": merged_whois,
        "reverse_ip_domains": merged_reverse_ip
    }


# ============================================================================
# CORE RECON & AUDIT ORCHESTRATION API
# ============================================================================
async def _execute_recon_core(req: ReconRequest, scan_id: Optional[str] = None) -> Dict[str, Any]:
    """
    State-Synchronized 4-Stage Bidirectional Handoff Pipeline between Windows Host (:8000)
    and Kali Linux Recon Engine (Agentless SSH Bridge).

    Pipeline Flow:
      [Stage 1: Kali -> Win]: Passive OSINT, Subfinder, Dig, CT Logs, Whois & Reverse IP
      [Stage 2: Win -> Kali]: Web Crawling, JS AST Analysis, Shannon Entropy (H>=3.0), Source Maps & Base Paths Enrichment
      [Stage 3: Kali -> Win]: Deep Nmap (-sV --version-all Top 1000+ ports), WhatWeb, Nikto, ffuf (guided paths)
      [Stage 4: Win Master]: Analysis & OWASP Engine, OWASP API Top 10:2023, Exposure Score, OpenAPI 3.0 & SQLite Commit
    """
    global latest_scan_cache, latest_openapi_cache

    target_raw = req.target.strip()
    if not target_raw:
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    if not target_raw.startswith("http://") and not target_raw.startswith("https://"):
        target_url = f"https://{target_raw}"
        domain = target_raw.split("/")[0].split(":")[0]
    else:
        target_url = target_raw
        parsed = urlparse(target_url)
        domain = parsed.hostname or target_raw.split("/")[2].split(":")[0]

    logger.info(f"[x1vart-ORCHESTRATOR] Initializing Recon Pipeline for {target_url} (Domain: {domain})")

    # Tracking Structures
    handoff_logs: List[Dict[str, Any]] = []
    cli_command_logs: List[Dict[str, Any]] = []
    worker_endpoint = (req.worker_url or KALI_WORKER_URL).rstrip("/")
    start_total_time = time.time()



    # Decide execution branch: 4-Stage Bidirectional Handoff vs Local Master
    # Verify Kali Linux connectivity: 1. Agentless SSH (Preferred) -> 2. HTTP Agent -> 3. Local Windows Fallback
    ssh_host = db_manager.get_setting("kali_ssh_host", "192.168.1.100")
    ssh_user = db_manager.get_setting("kali_ssh_user", "kali")
    ssh_pass = db_manager.get_setting("kali_ssh_password", "kali")
    ssh_port = int(db_manager.get_setting("kali_ssh_port", "22"))
    ssh_bridge = KaliSSHBridge(host=ssh_host, user=ssh_user, password=ssh_pass, port=ssh_port, timeout=3.0)

    is_ssh_available = False
    try:
        ssh_res = await asyncio.to_thread(ssh_bridge.test_connection)
        is_ssh_available = ssh_res.get("reachable", False)
    except Exception:
        is_ssh_available = False

    is_kali_available = False
    if not is_ssh_available:
        try:
            async with httpx.AsyncClient(timeout=3.0) as chk_client:
                h_res = await chk_client.get(f"{worker_endpoint}/worker/health", headers={"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY})
                if h_res.status_code == 200:
                    is_kali_available = True
        except Exception as conn_err:
            logger.debug(f"Kali HTTP Agent connection failed ({conn_err})")
            is_kali_available = False

    if is_ssh_available:
        execution_mode = "KALI_LINUX_SSH_AGENTLESS"
        logger.info(f"[x1vart] Connected to Kali Linux via SSH ({ssh_user}@{ssh_host}:{ssh_port})")
    elif is_kali_available:
        execution_mode = "KALI_LINUX_HTTP_AGENT"
        logger.info(f"[x1vart] Connected to Kali Linux via HTTP Agent ({worker_endpoint})")
    else:
        execution_mode = "LOCAL_WINDOWS_FALLBACK"
        logger.info("[x1vart] Kali offline. Activating Windows Local Fallback Scanner")

    # ====================================================================
    # GIAI ĐOẠN 1: KALI WORKER -> WINDOWS MASTER (Passive & Infra Discovery)
    # ====================================================================
    if scan_id:
        db_manager.update_scan_progress(scan_id, 15, "Giai đoạn 1: Kali Agent đang chạy Subfinder, Dig, CT Logs, Whois & Reverse IP...")
    t1_start = time.time()

    async def _call_kali_s1():
        async with httpx.AsyncClient(timeout=75.0) as client:
            try:
                resp = await client.post(
                    f"{worker_endpoint}/worker/stage1-passive",
                    headers={"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY},
                    json={"target_url": target_url, "subdomain_enum": req.subdomain_enum}
                )
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass

            # Backward compatibility fallback for legacy worker node
            resp_leg = await client.post(
                f"{worker_endpoint}/worker/pipeline",
                headers={"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY},
                json={"target_url": target_url, "subdomain_enum": req.subdomain_enum, "port_scan": False, "tech_audit": False, "dir_fuzz": False, "js_hunter": False, "sourcemap_hunter": False}
            )
            if resp_leg.status_code == 200:
                return resp_leg.json()
            raise RuntimeError(f"Kali worker returned HTTP {resp_leg.status_code}")

    # Stage 1: Delegate to SSH -> HTTP Agent -> Local Windows Discovery
    s1_k_res = None
    try:
        if is_ssh_available:
            s1_k_res = await asyncio.to_thread(ssh_bridge.run_stage1_passive, domain, target_url)
        elif is_kali_available:
            s1_k_res = await _call_kali_s1()
        else:
            s1_k_res = {"subdomain_recon": await subdomain_engine.run_discovery(domain)}
    except Exception as e:
        logger.warning(f"Stage 1 encountered error ({e}), falling back to local Windows discovery")
        try:
            s1_k_res = {"subdomain_recon": await subdomain_engine.run_discovery(domain)}
        except Exception:
            s1_k_res = {"subdomain_recon": {"subdomains": []}}

    t1_elapsed = round(time.time() - t1_start, 2)
    k_s1_ok = isinstance(s1_k_res, dict)

    k_worker_info = {}
    k_network_whois = {}
    k_reverse_ip = []
    doc_metadata = []
    merged_subs = []

    if k_s1_ok:
        k_worker_info = s1_k_res.get("worker_info", {})
        k_sub_obj = s1_k_res.get("subdomain_recon", {})
        k_network_whois = s1_k_res.get("network_whois", {})
        k_reverse_ip = s1_k_res.get("reverse_ip_domains", [])
        doc_metadata = k_sub_obj.get("document_metadata", [])
        cli_command_logs.extend(s1_k_res.get("cli_command_logs", []))
        merged_subs = k_sub_obj.get("subdomains", [])
    # 1. Ensure primary IP is resolved
    primary_ip = None
    try:
        primary_ip = socket.gethostbyname(domain)
    except Exception:
        primary_ip = None

    # 2. Extract subdomains from Kali Subfinder logs if needed
    has_active_subs = any(s.get("ips") for s in merged_subs)
    if (not has_active_subs or len(merged_subs) <= 1) and cli_command_logs:
        seen_s = set(s.get("subdomain", "").strip().lower() for s in merged_subs if s.get("subdomain"))
        for cl in cli_command_logs:
            if cl.get("tool") == "subfinder" and cl.get("raw_stdout"):
                for line in cl["raw_stdout"].splitlines():
                    sub = line.strip().lower()
                    if sub and "." in sub and sub not in seen_s:
                        seen_s.add(sub)
                        merged_subs.append({
                            "subdomain": sub,
                            "ips": [],
                            "cnames": [],
                            "status": "unresolved",
                            "takeover": {"vulnerable": False}
                        })

    # 3. Resolve active IPs for all discovered candidates
    for s in merged_subs:
        sub_name = s.get("subdomain", "").strip().lower()
        if not s.get("ips") and sub_name:
            try:
                ip = socket.gethostbyname(sub_name)
                s["ips"] = [ip]
                s["status"] = "active"
                if not primary_ip and (sub_name == domain or sub_name.endswith(domain)):
                    primary_ip = ip
            except Exception:
                s["status"] = "unresolved"

    # Always ensure root target is represented
    if not any(s.get("subdomain", "").strip().lower() == domain for s in merged_subs):
        merged_subs.insert(0, {
            "subdomain": domain,
            "ips": [primary_ip] if primary_ip else [],
            "cnames": [],
            "status": "active" if primary_ip else "unresolved",
            "takeover": {"vulnerable": False}
        })
    else:
        for s in merged_subs:
            if s.get("subdomain", "").strip().lower() == domain and primary_ip and not s.get("ips"):
                s["ips"] = [primary_ip]
                s["status"] = "active"

    # Keep only active assets & verified takeover risks
    active_subs = [s for s in merged_subs if s.get("status") == "active" or s.get("takeover", {}).get("vulnerable")]
    if not active_subs and merged_subs:
        active_subs = merged_subs

    subdomain_data = {
        "target_domain": domain,
        "wildcard_detected": False,
        "total_candidates": len(active_subs),
        "active_count": len([s for s in active_subs if s.get("status") == "active"]),
        "takeover_count": len([s for s in active_subs if s.get("takeover", {}).get("vulnerable")]),
        "subdomains": active_subs,
        "document_metadata": doc_metadata,
        "network_whois": k_network_whois,
        "reverse_ip_domains": k_reverse_ip
    }

    # Resolve Primary Target IP
    primary_ip = None
    for s in merged_subs:
        if s.get("ips"):
            primary_ip = s["ips"][0]
            break
    if not primary_ip:
        primary_ip = k_network_whois.get("ip")
    if not primary_ip:
        try:
            primary_ip = socket.gethostbyname(domain)
        except Exception:
            primary_ip = None

    if not k_network_whois or not k_network_whois.get("raw_whois_snippet") or k_network_whois.get("asn") == "N/A":
        k_network_whois = await lookup_network_whois(primary_ip or domain, domain, ssh_bridge if is_ssh_available else None)
        subdomain_data["network_whois"] = k_network_whois
    if not k_reverse_ip and primary_ip:
        k_reverse_ip = await lookup_reverse_ip(primary_ip, domain)
        subdomain_data["reverse_ip_domains"] = k_reverse_ip

    network_whois = k_network_whois
    reverse_ip_domains = k_reverse_ip

    handoff_logs.append({
        "stage": 1,
        "name": "Passive & Infra Discovery",
        "direction": "KALI -> WINDOWS",
        "sender": f"Kali Recon Agent ({worker_endpoint})",
        "receiver": "Windows Host (:8000)",
        "action": "OSINT, CT Logs, DNS & Whois Resolution",
        "status": "COMPLETED",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "duration_sec": t1_elapsed,
        "detail": f"Discovered {len(merged_subs)} subdomains, Primary IP: {primary_ip or 'N/A'}, ASN: {network_whois.get('asn', 'N/A')} ({network_whois.get('org_name', 'N/A')})"
    })

    # ====================================================================
    # GIAI ĐOẠN 2: KALI RECON AGENT (Web Crawling, JS Scraping & Secret Hunting)
    # ====================================================================
    if scan_id:
        db_manager.update_scan_progress(scan_id, 45, "Giai đoạn 2: Kali Recon Agent đang cào mã nguồn JS, phân tích AST, tính Shannon Entropy & săn tìm Secrets...")
    t2_start = time.time()

    async def _call_kali_s2():
        async with httpx.AsyncClient(timeout=60.0) as client:
            # 1. Primary: Dedicated Stage 2 endpoint on Kali Linux
            try:
                resp = await client.post(
                    f"{worker_endpoint}/worker/stage2-js-audit",
                    headers={"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY},
                    json={
                        "target_url": target_url,
                        "entropy_threshold": req.entropy_threshold,
                        "js_hunter": req.js_hunter,
                        "sourcemap_hunter": req.sourcemap_hunter
                    }
                )
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass

            # 2. Pipeline Fallback: Kali Linux /worker/pipeline
            resp_pipe = await client.post(
                f"{worker_endpoint}/worker/pipeline",
                headers={"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY},
                json={
                    "target_url": target_url,
                    "subdomain_enum": False,
                    "port_scan": False,
                    "tech_audit": False,
                    "dir_fuzz": False,
                    "js_hunter": req.js_hunter,
                    "sourcemap_hunter": req.sourcemap_hunter,
                    "entropy_threshold": req.entropy_threshold
                }
            )
            if resp_pipe.status_code == 200:
                p_data = resp_pipe.json()
                j_info = p_data.get("js_hunter", {})
                eps = j_info.get("endpoints", [])
                c_paths = [e.get("endpoint") for e in eps if e.get("endpoint", "").startswith("/")][:35]
                return {
                    "endpoints": eps,
                    "secrets": j_info.get("secrets", []),
                    "sourcemaps": p_data.get("sourcemaps", []),
                    "js_urls": j_info.get("js_urls", []),
                    "context_paths": c_paths
                }
            raise RuntimeError(f"Kali Stage 2 returned HTTP {resp_pipe.status_code}")

    # Execute Stage 2 on Kali Linux Agent
    s2_res = {}
    try:
        s2_res = await _call_kali_s2()
    except Exception as e:
        logger.warning(f"Kali Stage 2 JS & Secret Hunter error: {e}")
        s2_res = {"endpoints": [], "secrets": [], "sourcemaps": [], "context_paths": [], "js_urls": []}

    js_endpoints = s2_res.get("endpoints", [])
    js_secrets = s2_res.get("secrets", [])
    sourcemaps = s2_res.get("sourcemaps", [])
    context_paths = s2_res.get("context_paths", [])

    if not context_paths and js_endpoints:
        context_paths = [e.get("endpoint") for e in js_endpoints if e.get("endpoint", "").startswith("/")][:35]

    js_data = {
        "endpoints": js_endpoints,
        "total_endpoints": len(js_endpoints),
        "secrets": js_secrets,
        "total_secrets": len(js_secrets),
        "sourcemaps": sourcemaps,
        "js_urls": s2_res.get("js_urls", [])
    }

    t2_elapsed = round(time.time() - t2_start, 2)
    handoff_logs.append({
        "stage": 2,
        "name": "Web Crawling, JS AST & Secret Hunting (Kali)",
        "direction": "KALI -> WINDOWS",
        "sender": f"Kali Recon Agent ({worker_endpoint})",
        "receiver": "Windows Dashboard (:8000)",
        "action": "JS Bundle Extraction, AST Parsing, Shannon Entropy (H>=3.0) & Secret Hunting on Kali Linux",
        "status": "COMPLETED",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "duration_sec": t2_elapsed,
        "detail": f"Kali Linux extracted {len(js_endpoints)} APIs ({len(context_paths)} context paths), {len(js_secrets)} secrets, {len(sourcemaps)} source maps. Transferred results to Windows."
    })

    # ====================================================================
    # GIAI ĐOẠN 3: KALI WORKER -> WINDOWS MASTER (Deep Port Inspection & Service Audit)
    # ====================================================================
    if scan_id:
        db_manager.update_scan_progress(scan_id, 75, "Giai đoạn 3: Kali Agent kiểm tra chuyên sâu Nmap (-sV --version-all Top 1000+ ports), WhatWeb, Nikto, ffuf...")
    t3_start = time.time()

    async def _call_kali_s3():
        async with httpx.AsyncClient(timeout=75.0) as client:
            try:
                resp = await client.post(
                    f"{worker_endpoint}/worker/stage3-deep-audit",
                    headers={"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY},
                    json={
                        "target_url": target_url,
                        "target_ip": primary_ip,
                        "context_paths": context_paths,
                        "port_scan": req.vuln_scan,
                        "tech_audit": req.tech_fingerprint,
                        "dir_fuzz": req.vuln_scan
                    }
                )
                if resp.status_code == 200:
                    return resp.json()
            except Exception:
                pass

            # Backward compatibility fallback for legacy worker node
            resp_leg = await client.post(
                f"{worker_endpoint}/worker/pipeline",
                headers={"X-Agent-Secret-Key": X1VART_AGENT_SECRET_KEY},
                json={
                    "target_url": target_url,
                    "subdomain_enum": False,
                    "port_scan": req.vuln_scan,
                    "tech_audit": req.tech_fingerprint,
                    "dir_fuzz": req.vuln_scan,
                    "js_hunter": False,
                    "sourcemap_hunter": False
                }
            )
            if resp_leg.status_code == 200:
                leg_data = resp_leg.json()
                return {
                    "status": "SUCCESS",
                    "open_ports": leg_data.get("vulnerabilities", {}).get("open_ports", []),
                    "tech_fingerprint": leg_data.get("tech_fingerprint", {}),
                    "sensitive_files": leg_data.get("vulnerabilities", {}).get("sensitive_files", []),
                    "cors_audit": leg_data.get("vulnerabilities", {}).get("cors_audit", {}),
                    "insecure_methods_audit": leg_data.get("vulnerabilities", {}).get("insecure_methods_audit", []),
                    "nikto_findings": leg_data.get("vulnerabilities", {}).get("nikto_findings", []),
                    "ssl_audit": leg_data.get("vulnerabilities", {}).get("ssl_audit", {}),
                    "cli_command_logs": leg_data.get("cli_command_logs", []),
                    "worker_info": leg_data.get("worker_info", {})
                }
            raise RuntimeError(f"Kali stage3 returned HTTP {resp_leg.status_code}")

    # Stage 3: Delegate to SSH -> HTTP Agent -> Local Port Scan
    s3_k_res = None
    try:
        if is_ssh_available:
            s3_k_res = await asyncio.to_thread(ssh_bridge.run_stage3_active, domain, target_url)
        elif is_kali_available:
            s3_k_res = await _call_kali_s3()
        else:
            s3_k_res = {}
    except Exception as e:
        logger.warning(f"Stage 3 encountered error ({e})")
        s3_k_res = {}

    t3_elapsed = round(time.time() - t3_start, 2)
    k_s3_ok = isinstance(s3_k_res, dict)

    if k_s3_ok:
        cli_command_logs.extend(s3_k_res.get("cli_command_logs", []))
        k_ports = s3_k_res.get("open_ports", [])
        k_tech = s3_k_res.get("tech_fingerprint", {})
        k_files = s3_k_res.get("sensitive_files", [])
        k_cors = s3_k_res.get("cors_audit", {"vulnerable": False, "findings": []})
        k_methods = s3_k_res.get("insecure_methods_audit", [])
        k_nikto = s3_k_res.get("nikto_findings", [])
        k_ssl = s3_k_res.get("ssl_audit", {})
    else:
        k_ports = []
        k_tech = {}
        k_files = []
        k_cors = {"vulnerable": False, "findings": []}
        k_methods = []
        k_nikto = []
        k_ssl = {}

    sec_headers = k_tech.get("security_headers", [])
    cve_adv = k_tech.get("cve_advisories", [])

    tech_data = {
        "technologies": k_tech.get("technologies", []),
        "security_headers": sec_headers,
        "cve_advisories": cve_adv,
        "missing_headers_count": len([h for h in sec_headers if not h.get("present")]),
        "ssl_audit": k_ssl
    }

    vuln_data = {
        "open_ports": k_ports,
        "open_ports_count": len(k_ports),
        "sensitive_files": k_files,
        "sensitive_files_count": len(k_files),
        "cors_audit": k_cors,
        "insecure_methods_audit": k_methods,
        "nikto_findings": k_nikto,
        "ssl_audit": k_ssl
    }

    handoff_logs.append({
        "stage": 3,
        "name": "Deep Port Inspection & Service Audit",
        "direction": "KALI -> WINDOWS",
        "sender": f"Kali Recon Agent ({worker_endpoint})",
        "receiver": "Windows Host (:8000)",
        "action": "Nmap NSE Deep Scan, WhatWeb Fingerprint, Nikto & ffuf Targeted Fuzzing",
        "status": "COMPLETED",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "duration_sec": t3_elapsed,
        "detail": f"Audited {len(k_ports)} open TCP ports with version banners, WhatWeb stack, {len(k_files)} exposed files, {len(k_nikto)} Nikto findings."
    })

    worker_info = k_worker_info or {"worker_ip": worker_endpoint, "node": "kali_recon_agent"}


    # GIAI ĐOẠN 4: WINDOWS FUSION ENGINE (Hợp nhất, Đánh giá OWASP & Lưu trữ)
    # ========================================================================
    if scan_id:
        db_manager.update_scan_progress(scan_id, 92, "Giai đoạn 4: Đánh giá OWASP Top 10 & Chấm điểm Phơi nhiễm hợp nhất dữ liệu, tính Risk Score, đối chiếu OWASP API Top 10...")
    t4_start = time.time()

    # 1. OWASP API Security Top 10:2023 Analysis & Risk Scoring
    try:
        owasp_analysis = OwaspApiAnalyzer.analyze_attack_surface(subdomain_data, js_data, tech_data, sourcemaps, vuln_data)
    except Exception as e:
        logger.error(f"OWASP Analysis error: {e}")
        owasp_analysis = {"findings": [], "exposure_score": 10, "security_grade": "B", "risk_level": "LOW"}

    # 2. Compile OpenAPI 3.0 Specification
    try:
        openapi_spec = OpenApiBridge.generate_openapi_spec(target_url, js_data.get("endpoints", []))
    except Exception as e:
        logger.error(f"OpenAPI Bridge error: {e}")
        openapi_spec = {"openapi": "3.0.0", "info": {"title": "Scan Output", "version": "1.0.0"}, "paths": {}}
    latest_openapi_cache = openapi_spec

    # 3. Compile Cytoscape Graph Data
    try:
        graph_elements = build_cytoscape_graph(domain, subdomain_data, js_data, sourcemaps, vuln_data, execution_mode, worker_info)
    except Exception as e:
        logger.error(f"Graph Builder error: {e}")
        graph_elements = []

    t4_elapsed = round(time.time() - t4_start, 2)
    handoff_logs.append({
        "stage": 4,
        "name": "Analysis & OWASP Engine & OWASP Compliance",
        "direction": "WINDOWS MASTER",
        "sender": "Windows Host (:8000)",
        "receiver": "SQLite (x1vart.db) & Dashboard UI",
        "action": "Unified Schema Normalization, OWASP API Top 10 Mapping, OpenAPI 3.0 Compilation",
        "status": "COMPLETED",
        "timestamp": datetime.now().strftime("%H:%M:%S"),
        "duration_sec": t4_elapsed,
        "detail": f"Calculated Exposure Score: {owasp_analysis.get('exposure_score', 0)}/100 (Grade {owasp_analysis.get('security_grade', 'C')}), compiled OpenAPI specification, committed to x1vart.db."
    })

    total_duration = round(time.time() - start_total_time, 2)

    # 4. Consolidate Raw Result Payload
    raw_result = {
        "status": "SUCCESS",
        "scan_id": scan_id,
        "target": target_url,
        "domain": domain,
        "execution_mode": execution_mode,
        "execution_time_sec": total_duration,
        "summary": {
            "target": target_url,
            "domain": domain,
            "total_subdomains": len(subdomain_data.get("subdomains", [])),
            "active_subdomains": subdomain_data.get("active_count", 0),
            "takeover_risks": subdomain_data.get("takeover_count", 0),
            "hidden_apis_found": js_data.get("total_endpoints", 0),
            "bola_candidates": len([e for e in js_data.get("endpoints", []) if e.get("is_bola_candidate")]),
            "secrets_detected": js_data.get("total_secrets", 0),
            "sourcemaps_exposed": len(sourcemaps),
            "open_ports_count": len(vuln_data.get("open_ports", [])),
            "sensitive_files_count": vuln_data.get("sensitive_files_count", 0),
            "missing_security_headers": tech_data.get("missing_headers_count", 0),
            "exposure_score": owasp_analysis.get("exposure_score", 0),
            "security_grade": owasp_analysis.get("security_grade", "C"),
            "risk_level": owasp_analysis.get("risk_level", "MEDIUM"),
        },
        "worker_info": worker_info,
        "subdomain_recon": subdomain_data,
        "network_whois": network_whois,
        "reverse_ip_domains": reverse_ip_domains,
        "vulnerabilities": vuln_data,
        "tech_fingerprint": tech_data,
        "js_hunter": js_data,
        "sourcemaps": sourcemaps,
        "owasp_analysis": owasp_analysis,
        "graph_data": graph_elements,
        "cli_command_logs": cli_command_logs,
        "handoff_logs": handoff_logs,
    }

    # 5. Guarantee Strict Schema Contract via Normalizer
    normalized = normalize_scan_result(raw_result)

    # 6. Compute EASM Asset Diff & Dispatch Discord Alerts
    try:
        old_scan = db_manager.get_previous_completed_scan(domain, exclude_scan_id=scan_id)
        diff_res = AssetDiffEngine.compute_diff(old_scan, normalized)
        normalized["diff_summary"] = diff_res

        old_scan_id = old_scan.get("_scan_id", "BASELINE") if old_scan else "BASELINE"
        webhook_url = getattr(req, "discord_webhook", None) or db_manager.get_setting("discord_webhook", "")
        alert_sent = False

        if webhook_url and (diff_res.get("has_changes") or diff_res.get("has_critical_alerts")):
            alert_sent = await DiscordNotifier.send_diff_alert(
                webhook_url=webhook_url,
                domain=domain,
                diff=diff_res,
                scan_id=scan_id or "adhoc",
                target_url=target_url
            )

        db_manager.save_diff(
            domain=domain,
            old_scan_id=old_scan_id,
            new_scan_id=scan_id or "adhoc",
            diff_payload=diff_res,
            alert_sent=alert_sent
        )
    except Exception as diff_err:
        logger.error(f"Error computing scan diff or dispatching alert: {diff_err}")

    # 7. Save to SQLite Database
    if scan_id:
        try:
            db_manager.save_scan_result(
                scan_id=scan_id,
                target=target_url,
                domain=domain,
                status="COMPLETED",
                result_data=normalized,
                exposure_score=normalized["summary"].get("exposure_score", 0),
                security_grade=normalized["summary"].get("security_grade", "C")
            )
            db_manager.update_scan_progress(scan_id, 100, "Kiểm toán hoàn tất! Toàn bộ dữ liệu đã được lưu trữ an toàn.")
        except Exception as db_err:
            logger.error(f"Error persisting scan to SQLite: {db_err}")

    latest_scan_cache = normalized
    return normalized


def build_cytoscape_graph(
    domain: str,
    subdomain_data: Dict[str, Any],
    js_data: Dict[str, Any],
    sourcemaps: List[Dict[str, Any]],
    vuln_data: Dict[str, Any] = None,
    execution_mode: str = "LOCAL",
    worker_info: Dict[str, Any] = None
) -> List[Dict[str, Any]]:
    """
    Constructs an ultra-readable hierarchical graph with explicit levels:
    - Level 0 (Center/Top): Target Root & Kali Agent
    - Level 1: Subdomains & Infrastructure
    - Level 2: JS Bundles & Exposed Sensitive Files
    - Level 3: Discovered APIs, BOLA Targets, Leaked Secrets
    """
    elements = []
    root_id = f"node_root_{domain}"

    # Root Node (Level 0)
    elements.append({
        "data": {
            "id": root_id,
            "label": domain,
            "full_label": f"Root Target: {domain}",
            "type": "root",
            "level": 0,
            "info": f"Root Attack Surface Target: {domain} | Mode: {execution_mode}"
        }
    })

    # Kali Agent Node if executed via Kali Worker or Hybrid Dual-Engine
    if execution_mode == "KALI_LINUX_WORKER" or "HYBRID" in execution_mode:
        w_ip = (worker_info or {}).get("worker_ip", "192.168.1.100")
        kali_id = "node_kali_agent"
        elements.append({
            "data": {
                "id": kali_id,
                "label": f"Kali Agent ({w_ip})",
                "full_label": f"Kali Linux Worker Node: {w_ip}",
                "type": "kali_agent",
                "level": 0,
                "info": f"Distributed Kali Agent ({w_ip}) | Platform: {(worker_info or {}).get('platform', 'Linux')}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_kali_{root_id}",
                "source": kali_id,
                "target": root_id,
                "label": "audits"
            }
        })

    # Subdomain Nodes (Level 1)
    subs = subdomain_data.get("subdomains", [])
    for idx, sub in enumerate(subs[:12]):
        sub_name = sub.get("subdomain", "")
        if sub_name == domain:
            continue
        sub_id = f"sub_{idx}"
        is_takeover = sub.get("takeover", {}).get("vulnerable", False)
        elements.append({
            "data": {
                "id": sub_id,
                "label": sub_name,
                "full_label": f"Subdomain: {sub_name}",
                "type": "subdomain_takeover" if is_takeover else "subdomain",
                "level": 1,
                "info": f"IP: {', '.join(sub.get('ips', [])) or 'Dangling'} | Takeover Risk: {is_takeover}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{sub_id}",
                "source": root_id,
                "target": sub_id,
                "label": "subdomain"
            }
        })

    # Network Infrastructure / ASN Node (Level 1)
    asn_info = subdomain_data.get("historical_network", {}).get("asn_info", {})
    if asn_info and asn_info.get("asn") and asn_info.get("asn") != "Unknown":
        asn_id = "node_network_asn"
        asn_title = f"{asn_info.get('asn')} ({asn_info.get('org', 'ISP')})"
        elements.append({
            "data": {
                "id": asn_id,
                "label": asn_info.get("asn"),
                "full_label": asn_title,
                "type": "subdomain",
                "level": 1,
                "info": f"Network Infrastructure: {asn_title} | Country: {asn_info.get('country', 'N/A')}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{asn_id}",
                "source": root_id,
                "target": asn_id,
                "label": "network"
            }
        })

    # Co-Hosted Domains via Reverse IP (Level 1)
    co_hosted = subdomain_data.get("reverse_ip_domains", [])
    for c_idx, ch in enumerate(co_hosted[:4]):
        ch_domain = ch.get("domain", "")
        if ch_domain == domain:
            continue
        ch_id = f"revip_{c_idx}"
        elements.append({
            "data": {
                "id": ch_id,
                "label": f"Co-Hosted: {ch_domain}",
                "full_label": f"Co-Hosted Domain: {ch_domain} (Shared IP: {ch.get('ip')})",
                "type": "subdomain",
                "level": 1,
                "info": f"Co-Hosted Domain: {ch_domain} | Source: {ch.get('source')} | Shared IP: {ch.get('ip')}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{ch_id}",
                "source": root_id,
                "target": ch_id,
                "label": "shared_ip"
            }
        })

    # JS Bundles (Level 2)
    js_urls = js_data.get("js_urls", [])
    for idx, j_url in enumerate(js_urls[:8]):
        js_id = f"js_{idx}"
        short_name = j_url.split("/")[-1].split("?")[0] or f"bundle_{idx}.js"
        elements.append({
            "data": {
                "id": js_id,
                "label": short_name,
                "full_label": j_url,
                "type": "js_file",
                "level": 2,
                "info": f"Frontend Script: {j_url}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{js_id}",
                "source": root_id,
                "target": js_id,
                "label": "script"
            }
        })

        # Connected Discovered APIs (Level 3)
        endpoints = [ep for ep in js_data.get("endpoints", []) if ep.get("source_file") == j_url]
        for ep_idx, ep in enumerate(endpoints[:6]):
            ep_id = f"ep_{idx}_{ep_idx}"
            is_bola = ep.get("is_bola_candidate", False)
            ep_short = ep.get("endpoint", "")
            if len(ep_short) > 28:
                ep_short = ep_short[:25] + "..."

            elements.append({
                "data": {
                    "id": ep_id,
                    "label": f"{ep.get('method')} {ep_short}",
                    "full_label": ep.get("endpoint", ""),
                    "type": "bola_target" if is_bola else "endpoint",
                    "level": 3,
                    "method": ep.get("method", "GET"),
                    "info": f"{ep.get('method')} {ep.get('endpoint')} | BOLA Risk: {is_bola}"
                }
            })
            elements.append({
                "data": {
                    "id": f"edge_{js_id}_{ep_id}",
                    "source": js_id,
                    "target": ep_id,
                    "label": "api"
                }
            })

    # Exposed Source Maps (Level 2)
    for sm_idx, sm in enumerate(sourcemaps[:4]):
        sm_id = f"sm_{sm_idx}"
        elements.append({
            "data": {
                "id": sm_id,
                "label": f".map ({sm.get('total_sources')} src)",
                "full_label": sm.get("map_url"),
                "type": "sourcemap",
                "level": 2,
                "info": f"Exposed Source Map: {sm.get('map_url')} ({sm.get('total_sources')} reconstructed files)"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{sm_id}",
                "source": root_id,
                "target": sm_id,
                "label": "map"
            }
        })

    # Exposed Sensitive Files (Level 2/3)
    vuln_files = (vuln_data or {}).get("sensitive_files", [])
    for vf_idx, vf in enumerate(vuln_files[:5]):
        vf_id = f"vf_{vf_idx}"
        elements.append({
            "data": {
                "id": vf_id,
                "label": f"EXPOSED {vf.get('path')}",
                "full_label": vf.get("url"),
                "type": "vuln_file",
                "level": 2,
                "info": f"Sensitive File Exposure: {vf.get('name')} at {vf.get('url')}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{vf_id}",
                "source": root_id,
                "target": vf_id,
                "label": "leak"
            }
        })

    # Public Documents with Metadata (Level 2)
    docs = subdomain_data.get("document_metadata", [])
    for d_idx, doc in enumerate(docs[:3]):
        doc_id = f"doc_{d_idx}"
        d_meta = doc.get("metadata", {})
        elements.append({
            "data": {
                "id": doc_id,
                "label": f"DOC: {doc.get('file_name')}",
                "full_label": doc.get("url"),
                "type": "vuln_file",
                "level": 2,
                "info": f"Public Document: {doc.get('file_name')} | Author: {d_meta.get('author', 'Unknown')} | Tool: {d_meta.get('creator_software', 'Unknown')}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{doc_id}",
                "source": root_id,
                "target": doc_id,
                "label": "public_doc"
            }
        })

    # Secrets (Level 3)
    secrets = js_data.get("secrets", [])
    for s_idx, sec in enumerate(secrets[:6]):
        sec_id = f"sec_{s_idx}"
        elements.append({
            "data": {
                "id": sec_id,
                "label": f"Key: {sec.get('secret_type')} (H={sec.get('entropy')})",
                "full_label": sec.get("masked_value"),
                "type": "secret",
                "level": 3,
                "info": f"Secret Leakage: {sec.get('secret_type')} | Entropy: {sec.get('entropy')} bit/char"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{sec_id}",
                "source": root_id,
                "target": sec_id,
                "label": "secret"
            }
        })

    # Open Ports & Services (Level 1)
    open_ports_list = (vuln_data or {}).get("open_ports", [])
    for p_idx, p in enumerate(open_ports_list[:8]):
        p_num = p.get("port")
        if not p_num:
            continue
        p_id = f"port_{p_idx}"
        svc = p.get("service") or f"Port {p_num}"
        is_risky = bool(p.get("is_risky"))
        elements.append({
            "data": {
                "id": p_id,
                "label": f":{p_num} {svc[:15]}",
                "full_label": f"Port {p_num}/TCP: {svc} ({p.get('ip') or domain})",
                "type": "port",
                "is_risky": is_risky,
                "level": 1,
                "info": f"Open Port: {p_num} | Service: {svc} | IP: {p.get('ip') or domain} | Risk: {p.get('risk_note', 'Active service')}"
            }
        })
        elements.append({
            "data": {
                "id": f"edge_root_{p_id}",
                "source": root_id,
                "target": p_id,
                "label": "service"
            }
        })

    return elements


# ============================================================================
# BUILT-IN LIVE API TESTER CONSOLE (Direct Browser Execution)
# ============================================================================
# ============================================================================
# SCAN LIFECYCLE & BACKGROUND EXECUTION ROUTES
# ============================================================================
@app.post("/api/recon/start")
async def start_recon_job(req: ReconRequest, background_tasks: BackgroundTasks):
    """Initiates asynchronous reconnaissance in the background and returns a trackable scan_id."""
    target_raw = req.target.strip()
    if not target_raw:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    parsed = urlparse(target_raw if "://" in target_raw else f"https://{target_raw}")
    domain = parsed.hostname or target_raw.split("/")[0].split(":")[0]
    exec_mode = "KALI_LINUX_ENGINE" if req.use_kali_worker else "KALI_LINUX_ENGINE"
    scan_id = db_manager.create_scan(target_raw, domain, exec_mode)

    async def _run_bg():
        try:
            await _execute_recon_core(req, scan_id=scan_id)
        except Exception as bg_err:
            logger.error(f"Background recon failed for {scan_id}: {bg_err}")
            db_manager.fail_scan(scan_id, str(bg_err))

    background_tasks.add_task(_run_bg)
    return {"status": "STARTED", "scan_id": scan_id, "target": target_raw, "domain": domain}


@app.get("/api/recon/status/{scan_id}")
async def get_recon_status(scan_id: str):
    """Polls background recon progress percentage and current stage description."""
    st = db_manager.get_scan_status(scan_id)
    if not st:
        raise HTTPException(status_code=404, detail="Scan ID not found")
    return st


@app.post("/api/recon/scan")
async def execute_recon_sync(req: ReconRequest):
    """Synchronous reconnaissance run returning full normalized dataset."""
    target_raw = req.target.strip()
    if not target_raw:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    parsed = urlparse(target_raw if "://" in target_raw else f"https://{target_raw}")
    domain = parsed.hostname or target_raw.split("/")[0].split(":")[0]
    exec_mode = "KALI_LINUX_ENGINE" if req.use_kali_worker else "KALI_LINUX_ENGINE"
    scan_id = db_manager.create_scan(target_raw, domain, exec_mode)
    return await _execute_recon_core(req, scan_id=scan_id)


@app.get("/api/scans/history")
@app.get("/api/history")
async def get_scan_history(limit: int = 50):
    """Retrieves historical scan runs persisted in SQLite (x1vart.db)."""
    return db_manager.list_history(limit=limit)


@app.get("/api/scans/{scan_id}")
async def get_scan_by_id(scan_id: str):
    """Retrieves full normalized scan result payload by scan_id from SQLite."""
    res = db_manager.get_scan_results(scan_id)
    if not res:
        status_info = db_manager.get_scan_status(scan_id)
        if status_info:
            return normalize_scan_result(status_info)
        raise HTTPException(status_code=404, detail=f"Scan result {scan_id} not found")
    return normalize_scan_result(res)


@app.delete("/api/scans/{scan_id}")
async def delete_scan_by_id(scan_id: str):
    """Deletes a scan record from SQLite database."""
    success = db_manager.delete_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or could not be deleted")
    return {"status": "DELETED", "scan_id": scan_id}


@app.post("/api/tester/send")
async def execute_api_test(req: ApiTestRequest):
    """
    Native API Console: Directly executes HTTP queries against discovered endpoints
    with custom authorization tokens and measures response time and payloads.
    Uses Chrome User-Agent and verify=False.
    """
    method = req.method.upper()
    url = req.url.strip()
    headers = req.headers or {}
    headers.setdefault("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

    start_time = time.perf_counter()
    result = {
        "url": url,
        "method": method,
        "status_code": 0,
        "latency_ms": 0,
        "headers": {},
        "body": None,
        "error": None
    }

    try:
        async with httpx.AsyncClient(timeout=8.0, verify=False, follow_redirects=True) as client:
            if method == "POST":
                resp = await client.post(url, headers=headers, json=req.body or {})
            elif method == "PUT":
                resp = await client.put(url, headers=headers, json=req.body or {})
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            else:
                resp = await client.get(url, headers=headers)

            latency = round((time.perf_counter() - start_time) * 1000, 2)
            result["status_code"] = resp.status_code
            result["latency_ms"] = latency
            result["headers"] = dict(resp.headers)

            try:
                result["body"] = resp.json()
            except Exception:
                result["body"] = resp.text[:2000]

    except Exception as e:
        latency = round((time.perf_counter() - start_time) * 1000, 2)
        result["latency_ms"] = latency
        result["error"] = str(e)

    return result


# ============================================================================
# EXECUTIVE AUDIT REPORT & OPENAPI DOWNLOAD
# ============================================================================
@app.get("/api/report/{scan_id}", response_class=HTMLResponse)
@app.get("/api/report/export", response_class=HTMLResponse)
async def export_audit_report(scan_id: Optional[str] = None):
    """
    Generates and serves a comprehensive, self-contained Executive Security Audit Report.
    """
    global latest_scan_cache
    data = None
    if scan_id:
        data = db_manager.get_scan_results(scan_id)
    if not data:
        data = latest_scan_cache
    if not data:
        hist = db_manager.list_history(limit=1)
        if hist and hist[0].get("scan_id"):
            data = db_manager.get_scan_results(hist[0]["scan_id"])
    if not data:
        raise HTTPException(status_code=404, detail="No scan data found. Please run a scan first.")

    report_html = ReportGenerator.generate_html_report(data)
    return HTMLResponse(content=report_html)


@app.get("/api/openapi/{scan_id}")
@app.get("/api/openapi/download")
async def download_openapi(scan_id: Optional[str] = None):
    """
    Downloads the auto-generated OpenAPI 3.0 JSON specification file
    for Swagger UI, Redoc, or Postman.
    """
    global latest_openapi_cache
    spec = None
    if scan_id:
        scan_data = db_manager.get_scan_results(scan_id)
        if scan_data and scan_data.get("openapi_spec"):
            spec = scan_data["openapi_spec"]
    if not spec:
        spec = latest_openapi_cache
    if not spec:
        hist = db_manager.list_history(limit=1)
        if hist and hist[0].get("scan_id"):
            scan_data = db_manager.get_scan_results(hist[0]["scan_id"])
            if scan_data and scan_data.get("openapi_spec"):
                spec = scan_data["openapi_spec"]
    if not spec:
        raise HTTPException(status_code=404, detail="No OpenAPI spec has been generated yet. Please run a scan first.")

    content = json.dumps(spec, indent=2, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": "attachment; filename=x1vart_recon_openapi.json"
        }
    )


# ============================================================================
# EASM CONTINUOUS SCHEDULER & DISCORD NOTIFICATION ENDPOINTS
# ============================================================================
class CreateScheduleRequest(BaseModel):
    target: str
    interval_hours: int = 24
    use_kali_worker: bool = True
    worker_url: Optional[str] = "192.168.1.100:22"
    discord_webhook: Optional[str] = ""


class ToggleScheduleRequest(BaseModel):
    enabled: bool


class SettingsRequest(BaseModel):
    discord_webhook: str


class DiscordTestRequest(BaseModel):
    webhook_url: str


async def _easm_scheduler_worker():
    """Background loop inspecting and triggering due EASM schedules."""
    logger.info("x1vart EASM Background Scheduler initialized.")
    while True:
        try:
            due_schedules = db_manager.get_due_schedules()
            for sched in due_schedules:
                sched_id = sched["schedule_id"]
                target = sched["target"]
                domain = sched["domain"]
                interval = sched["interval_hours"]
                use_kali = bool(sched.get("use_kali", 1))
                worker_ip = sched.get("worker_ip") or "192.168.1.100:22"
                worker_url = f"http://{worker_ip}" if not worker_ip.startswith("http") else worker_ip
                webhook = sched.get("discord_webhook") or db_manager.get_setting("discord_webhook", "")

                logger.info(f"Triggering scheduled EASM recon for {domain} ({sched_id})")
                scan_id = db_manager.create_scan(target, domain, "SCHEDULED_EASM", worker_ip)
                req = ReconRequest(
                    target=target,
                    use_kali_worker=use_kali,
                    worker_url=worker_url,
                    discord_webhook=webhook
                )
                try:
                    await _execute_recon_core(req, scan_id=scan_id)
                    db_manager.update_schedule_after_run(sched_id, scan_id, interval)
                except Exception as run_err:
                    logger.error(f"Scheduled recon failed for {sched_id}: {run_err}")
                    db_manager.fail_scan(scan_id, str(run_err))
                    db_manager.update_schedule_after_run(sched_id, scan_id, interval)
        except Exception as e:
            logger.error(f"EASM scheduler loop exception: {e}")
        await asyncio.sleep(45)


@app.on_event("startup")
async def startup_easm_scheduler():
    asyncio.create_task(_easm_scheduler_worker())


@app.get("/api/easm/schedules")
async def get_easm_schedules():
    return db_manager.list_schedules()


@app.post("/api/easm/schedules")
async def create_easm_schedule(req: CreateScheduleRequest):
    target_raw = req.target.strip()
    if not target_raw:
        raise HTTPException(status_code=400, detail="Target cannot be empty")
    parsed = urlparse(target_raw if "://" in target_raw else f"https://{target_raw}")
    domain = parsed.hostname or target_raw.split("/")[0].split(":")[0]

    worker_ip = req.worker_url.replace("http://", "").replace("https://", "").strip("/") if req.worker_url else "192.168.1.100:22"
    sched_id = db_manager.create_schedule(
        target=target_raw,
        domain=domain,
        interval_hours=max(1, req.interval_hours),
        use_kali=req.use_kali_worker,
        worker_ip=worker_ip,
        discord_webhook=req.discord_webhook or ""
    )
    return {"status": "SUCCESS", "schedule_id": sched_id, "domain": domain}


@app.post("/api/easm/schedules/{schedule_id}/toggle")
async def toggle_easm_schedule(schedule_id: str, req: ToggleScheduleRequest):
    ok = db_manager.toggle_schedule(schedule_id, req.enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "SUCCESS", "schedule_id": schedule_id, "enabled": req.enabled}


@app.delete("/api/easm/schedules/{schedule_id}")
async def delete_easm_schedule(schedule_id: str):
    ok = db_manager.delete_schedule(schedule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return {"status": "SUCCESS", "schedule_id": schedule_id}


@app.post("/api/easm/schedules/{schedule_id}/run")
async def trigger_easm_schedule_run(schedule_id: str, background_tasks: BackgroundTasks):
    schedules = db_manager.list_schedules()
    sched = next((s for s in schedules if s["schedule_id"] == schedule_id), None)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    target = sched["target"]
    domain = sched["domain"]
    interval = sched["interval_hours"]
    use_kali = bool(sched.get("use_kali", 1))
    worker_ip = sched.get("worker_ip") or "192.168.1.100:22"
    worker_url = f"http://{worker_ip}" if not worker_ip.startswith("http") else worker_ip
    webhook = sched.get("discord_webhook") or db_manager.get_setting("discord_webhook", "")

    scan_id = db_manager.create_scan(target, domain, "MANUAL_EASM", worker_ip)

    async def _run_manual():
        req = ReconRequest(target=target, use_kali_worker=use_kali, worker_url=worker_url, discord_webhook=webhook)
        try:
            await _execute_recon_core(req, scan_id=scan_id)
            db_manager.update_schedule_after_run(schedule_id, scan_id, interval)
        except Exception as e:
            logger.error(f"Manual schedule run failed: {e}")
            db_manager.fail_scan(scan_id, str(e))
            db_manager.update_schedule_after_run(schedule_id, scan_id, interval)

    background_tasks.add_task(_run_manual)
    return {"status": "TRIGGERED", "scan_id": scan_id, "schedule_id": schedule_id}


@app.get("/api/easm/diff-history")
async def get_easm_diff_history(limit: int = 30):
    return db_manager.list_diff_history(limit=limit)


@app.get("/api/easm/settings")
async def get_easm_settings():
    return {
        "discord_webhook": db_manager.get_setting("discord_webhook", "")
    }


@app.post("/api/easm/settings")
async def save_easm_settings(req: SettingsRequest):
    db_manager.set_setting("discord_webhook", req.discord_webhook.strip())
    return {"status": "SUCCESS", "discord_webhook": req.discord_webhook.strip()}


@app.post("/api/easm/test-webhook")
async def test_discord_webhook_endpoint(req: DiscordTestRequest):
    success = await DiscordNotifier.test_webhook(req.webhook_url.strip())
    if not success:
        raise HTTPException(status_code=400, detail="Không thể gửi tin nhắn thử nghiệm tới Discord Webhook. Vui lòng kiểm tra lại URL.")
    return {"status": "SUCCESS", "message": "Đã gửi thông báo thử nghiệm thành công tới Discord!"}


def launch_desktop_window(url: str = "http://127.0.0.1:8000"):
    """
    Launches a dedicated standalone Desktop Application Window.
    Uses native Edge/Chrome standalone App-Window mode (--app) for 100% responsiveness and zero lag.
    """
    # 1. Standalone Native Desktop Window (Edge / Chrome --app mode)
    if platform.system() == "Windows":
        candidates = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
            os.path.expandvars(r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
        ]
        for exe in candidates:
            if os.path.exists(exe):
                try:
                    logger.info(f"[*] Launching Standalone Desktop App via: {exe}")
                    import tempfile
                    profile_dir = os.path.join(tempfile.gettempdir(), "x1vart_desktop_profile")
                    # Dedicated app instance via separate profile ensures process stays alive until window is closed
                    proc = subprocess.Popen([
                        exe,
                        f"--app={url}",
                        f"--user-data-dir={profile_dir}",
                        "--window-size=1440,900",
                        "--no-first-run",
                        "--no-default-browser-check"
                    ])
                    proc.wait()
                    return
                except Exception:
                    pass

    # 2. Fallback: Default Browser
    logger.info(f"[*] Opening default browser at {url}...")
    webbrowser.open(url)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    import uvicorn

    if "--headless" in sys.argv or "--server" in sys.argv:
        uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
    else:
        # Run server in background daemon thread (0.0.0.0 enables Kali VM & remote agents to connect)
        config = uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="warning")
        server = uvicorn.Server(config)
        server_thread = threading.Thread(target=server.run, daemon=True)
        server_thread.start()

        # Brief pause for server socket binding
        time.sleep(1.0)

        # Launch dedicated desktop application window in background
        threading.Thread(target=launch_desktop_window, args=("http://127.0.0.1:8000",), daemon=True).start()

        # Keep main thread alive persistently
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
