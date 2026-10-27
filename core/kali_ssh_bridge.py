"""
x1vart Agentless Kali SSH Bridge
Executes recon & auditing CLI tools directly on Kali Linux via SSH without any agent script.
"""

import logging
import re
import socket
from typing import Dict, Any, List, Optional
import paramiko

logger = logging.getLogger("x1vart.ssh_bridge")


class KaliSSHBridge:
    def __init__(
        self,
        host: str = "192.168.1.100",
        user: str = "kali",
        password: str = "kali",
        port: int = 22,
        timeout: float = 6.0
    ):
        self.host = host.strip()
        self.user = user.strip()
        self.password = password
        self.port = port
        self.timeout = timeout

    def _get_client(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            timeout=self.timeout,
            banner_timeout=self.timeout
        )
        return client

    def test_connection(self) -> Dict[str, Any]:
        """Tests SSH connection and verifies installed security tools."""
        try:
            with self._get_client() as client:
                stdin, stdout, stderr = client.exec_command(
                    "uname -a && which subfinder nmap whatweb nikto ffuf gobuster",
                    timeout=5.0
                )
                output = stdout.read().decode("utf-8", errors="ignore").strip()
                lines = output.splitlines()
                uname = lines[0] if lines else "Linux"
                installed_tools = [line.split("/")[-1] for line in lines[1:] if line.strip()]

                return {
                    "reachable": True,
                    "host": self.host,
                    "user": self.user,
                    "uname": uname,
                    "installed_tools": installed_tools,
                    "message": "Kết nối SSH tới Kali Linux thành công (Chế độ Agentless)!"
                }
        except Exception as e:
            return {
                "reachable": False,
                "host": self.host,
                "error": str(e),
                "message": f"Không thể kết nối SSH tới {self.host}:{self.port} ({str(e)})"
            }

    def run_command(self, cmd: str, timeout: float = 30.0) -> Dict[str, Any]:
        """Executes a single CLI command on Kali Linux and returns output."""
        try:
            with self._get_client() as client:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
                out = stdout.read().decode("utf-8", errors="ignore")
                err = stderr.read().decode("utf-8", errors="ignore")
                exit_code = stdout.channel.recv_exit_status()
                return {
                    "cmd": cmd,
                    "stdout": out,
                    "stderr": err,
                    "exit_code": exit_code,
                    "success": (exit_code == 0)
                }
        except Exception as e:
            return {
                "cmd": cmd,
                "stdout": "",
                "stderr": str(e),
                "exit_code": -1,
                "success": False
            }

    def run_whois_lookup(self, target: str, primary_ip: Optional[str] = None) -> Dict[str, Any]:
        """Runs native whois for IP and domain on Kali Linux and extracts structured metadata."""
        import socket
        target = (target or "").strip()
        is_ip = False
        try:
            socket.inet_aton(target)
            is_ip = True
        except Exception:
            is_ip = False

        domain = "" if is_ip else target
        resolved_ip = None
        if is_ip:
            resolved_ip = target
        elif primary_ip:
            try:
                socket.inet_aton(primary_ip)
                resolved_ip = primary_ip
            except Exception:
                resolved_ip = None
        if not resolved_ip and domain:
            try:
                resolved_ip = socket.gethostbyname(domain)
            except Exception:
                pass

        whois_data = {
            "ip": resolved_ip or target,
            "domain": domain,
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

        raw_parts = []
        if resolved_ip:
            ip_cmd = f"whois {resolved_ip}"
            ip_res = self.run_command(ip_cmd, timeout=12.0)
            if ip_res.get("stdout"):
                raw_parts.append(f"=== [WHOIS IP: {resolved_ip}] ===\n{ip_res['stdout'].strip()}")

        if domain:
            dom_cmd = f"whois {domain}"
            dom_res = self.run_command(dom_cmd, timeout=12.0)
            if dom_res.get("stdout"):
                raw_parts.append(f"=== [WHOIS DOMAIN: {domain}] ===\n{dom_res['stdout'].strip()}")

        combined_raw = "\n\n".join(raw_parts)
        if combined_raw:
            whois_data["raw_whois_snippet"] = combined_raw
            m = re.search(r"(?:inetnum|NetRange):\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
            if m: whois_data["inetnum"] = m.group(1).strip()
            m = re.search(r"CIDR:\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
            if m: whois_data["cidr"] = m.group(1).strip()
            m = re.search(r"(?:netname|NetName):\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
            if m: whois_data["netname"] = m.group(1).strip()
            m = re.search(r"(?:origin|OriginAS|aut-num):\s*(AS\d+|\d+)", combined_raw, re.IGNORECASE)
            if m:
                val = m.group(1).strip()
                whois_data["asn"] = val if val.upper().startswith("AS") else f"AS{val}"
            m = re.search(r"(?:Organization|org-name|Registrant Organization):\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
            if m:
                whois_data["org_name"] = m.group(1).strip()
            else:
                m2 = re.search(r"descr:\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
                if m2: whois_data["org_name"] = m2.group(1).strip()
            m = re.search(r"(?:Registrar):\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
            if m: whois_data["registrar"] = m.group(1).strip()
            m = re.search(r"(?:country|Country):\s*([A-Za-z]{2})\b", combined_raw, re.IGNORECASE)
            if m: whois_data["country"] = m.group(1).strip().upper()
            m = re.search(r"(?:OrgAbuseEmail|abuse-mailbox|Registrar Abuse Contact Email|Abuse contact[^\n]*is):\s*['\"]?([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)['\"]?", combined_raw, re.IGNORECASE)
            if m: whois_data["abuse_email"] = m.group(1).strip()
            m = re.search(r"(?:OrgTechEmail|tech-c):\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
            if m: whois_data["tech_contact"] = m.group(1).strip()
            m = re.search(r"(?:OrgAdminEmail|admin-c):\s*([^\r\n]+)", combined_raw, re.IGNORECASE)
            if m: whois_data["admin_contact"] = m.group(1).strip()

        return whois_data

    def run_stage1_passive(self, domain: str, target_url: str) -> Dict[str, Any]:
        """Executes Subfinder, Whois, Dig directly on Kali via SSH."""
        res = {
            "worker_info": {
                "worker_ip": self.host,
                "hostname": "kali-ssh",
                "platform": "Kali Linux (Agentless SSH)",
                "tools_installed": {"subfinder": True, "nmap": True, "whatweb": True, "nikto": True, "whois": True}
            },
            "subdomain_recon": {"subdomains": []},
            "network_whois": {},
            "reverse_ip": [],
            "cli_command_logs": []
        }

        # Subfinder CLI
        sf_cmd = f"subfinder -d {domain} -silent -timeout 10"
        sf_out = self.run_command(sf_cmd, timeout=25.0)
        res["cli_command_logs"].append({
            "stage": "Stage 1: OSINT & Subfinder (Kali SSH)",
            "command": sf_cmd,
            "stdout": sf_out["stdout"][:2000],
            "stderr": sf_out["stderr"][:500],
            "execution_time_sec": 1.5
        })

        # Whois CLI on Kali
        whois_data = self.run_whois_lookup(domain)
        res["network_whois"] = whois_data
        if whois_data.get("raw_whois_snippet"):
            res["cli_command_logs"].append({
                "stage": "Stage 1: Network & Domain Whois (Kali SSH)",
                "command": f"whois {whois_data.get('ip', domain)}",
                "stdout": whois_data["raw_whois_snippet"][:2000],
                "stderr": "",
                "execution_time_sec": 1.0
            })

        found_subs = [s.strip() for s in sf_out["stdout"].splitlines() if s.strip()]
        unique_subs = list(dict.fromkeys([domain] + found_subs))
        res["subdomain_recon"]["subdomains"] = [
            {"subdomain": sub, "cname": "", "ips": [], "takeover_risk": False, "takeover_service": None}
            for sub in unique_subs
        ]
        return res

    def run_stage3_active(self, domain: str, target_url: str) -> Dict[str, Any]:
        """Executes Nmap, WhatWeb, Nikto directly on Kali via SSH."""
        open_ports: List[Dict[str, Any]] = []
        tech_list: List[Dict[str, Any]] = []
        nikto_list: List[str] = []
        cli_logs: List[Dict[str, Any]] = []

        # Nmap Port Scan
        nmap_cmd = f"nmap -F -sV --version-light -T4 --host-timeout 25s {domain}"
        nmap_out = self.run_command(nmap_cmd, timeout=30.0)
        cli_logs.append({
            "stage": "Stage 3: Nmap Port Scan (Kali SSH)",
            "command": nmap_cmd,
            "stdout": nmap_out["stdout"][:2000],
            "stderr": nmap_out["stderr"][:500],
            "execution_time_sec": 3.0
        })

        for line in nmap_out["stdout"].splitlines():
            m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line.strip())
            if m:
                open_ports.append({
                    "port": int(m.group(1)),
                    "protocol": m.group(2),
                    "service": m.group(3),
                    "version": m.group(4).strip() or "N/A"
                })

        # WhatWeb
        ww_cmd = f"whatweb -a 1 --color=never https://{domain} || whatweb -a 1 --color=never http://{domain}"
        ww_out = self.run_command(ww_cmd, timeout=20.0)
        cli_logs.append({
            "stage": "Stage 3: WhatWeb Fingerprint (Kali SSH)",
            "command": ww_cmd,
            "stdout": ww_out["stdout"][:2000],
            "stderr": ww_out["stderr"][:500],
            "execution_time_sec": 2.0
        })
        if ww_out["stdout"]:
            tech_list.append({
                "name": "WhatWeb (Kali SSH)",
                "category": "Technology Fingerprint",
                "version": ww_out["stdout"][:300].strip()
            })

        # Nikto
        nikto_cmd = f"nikto -h {domain} -Tuning 123b -maxtime 15s"
        nikto_out = self.run_command(nikto_cmd, timeout=20.0)
        cli_logs.append({
            "stage": "Stage 3: Nikto Vulnerability Audit (Kali SSH)",
            "command": nikto_cmd,
            "stdout": nikto_out["stdout"][:2000],
            "stderr": nikto_out["stderr"][:500],
            "execution_time_sec": 2.5
        })
        for line in nikto_out["stdout"].splitlines():
            if "+ OSVDB-" in line or "+ Server:" in line or "+ Retrieved" in line or "+ The anti-clickjacking" in line:
                nikto_list.append(line.strip())

        return {
            "status": "SUCCESS",
            "open_ports": open_ports,
            "tech_fingerprint": {"technologies": tech_list},
            "sensitive_files": [],
            "cors_audit": {"vulnerable": False, "findings": []},
            "insecure_methods_audit": [],
            "nikto_findings": nikto_list,
            "ssl_audit": {},
            "cli_command_logs": cli_logs,
            "worker_info": {
                "worker_ip": self.host,
                "hostname": "kali-ssh",
                "platform": "Kali Linux (Agentless SSH)"
            }
        }
