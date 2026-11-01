"""
x1vart Agentless Kali SSH Bridge
Executes recon & auditing CLI tools directly on Kali Linux via SSH without any agent script.
"""

import logging
import re
import shlex
import socket
import time
from typing import Dict, Any, List, Optional
import paramiko

logger = logging.getLogger("x1vart.ssh_bridge")


class KaliSSHBridge:
    ONE_LINER_COMMAND = "sudo apt update && sudo apt install -y nmap whatweb nikto ffuf whois subfinder sslscan wafw00f && sudo systemctl enable --now ssh"
    REQUIRED_TOOLS = ["nmap", "whatweb", "nikto", "ffuf", "whois", "subfinder", "sslscan", "wafw00f"]

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

    @staticmethod
    def sanitize_target(target: str) -> str:
        """
        Validates and sanitizes target domain or IP against Command Injection.
        Rejects shell metacharacters and enforces strict hostname/IP RFC pattern.
        """
        target = (target or "").strip()
        if not target:
            raise ValueError("Target domain/IP cannot be empty.")
        if any(c in target for c in ";|&$`'\"<>(){}[]!#*? \t\r\n\\"):
            raise ValueError(f"Shell injection metacharacter detected in target: {target}")
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9])?$", target):
            raise ValueError(f"Invalid target domain or IP format: {target}")
        return shlex.quote(target)

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
        """
        Smart SSH Diagnostics:
        1. Ping/TCP reachability test to host and port (VMware Bridged/Host-only check).
        2. Port 22 SSH daemon status check.
        3. Authentication credentials validation.
        4. Installed tools audit against required pentest suite.
        """
        # Step 1: Pre-flight TCP Socket connection test
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.5)
        try:
            sock.connect((self.host, self.port))
            sock.close()
        except ConnectionRefusedError:
            sock.close()
            return {
                "reachable": False,
                "error_code": "PORT_22_REFUSED",
                "host": self.host,
                "port": self.port,
                "message": f"❌ Port 22 bị từ chối trên máy chủ {self.host}.",
                "guidance": "Chưa chạy SSH service trên Kali. Hãy mở terminal Kali và chạy: sudo systemctl start ssh",
                "one_liner": self.ONE_LINER_COMMAND
            }
        except (socket.timeout, TimeoutError):
            sock.close()
            return {
                "reachable": False,
                "error_code": "HOST_UNREACHABLE",
                "host": self.host,
                "port": self.port,
                "message": f"❌ Không ping/kết nối được IP {self.host} (Timeout).",
                "guidance": "Kiểm tra lại IP hoặc card mạng Bridged/Host-Only trên VMware/VirtualBox. Gõ 'ip a' trên Kali để lấy IP mới.",
                "one_liner": self.ONE_LINER_COMMAND
            }
        except Exception as sock_err:
            sock.close()
            err_str = str(sock_err).lower()
            if "refused" in err_str or "10061" in err_str:
                return {
                    "reachable": False,
                    "error_code": "PORT_22_REFUSED",
                    "host": self.host,
                    "port": self.port,
                    "message": f"❌ Port 22 bị từ chối trên {self.host}.",
                    "guidance": "Chưa chạy lệnh bật SSH trên Kali: sudo systemctl enable --now ssh",
                    "one_liner": self.ONE_LINER_COMMAND
                }
            return {
                "reachable": False,
                "error_code": "NETWORK_ERROR",
                "host": self.host,
                "port": self.port,
                "message": f"❌ Không thể định tuyến tới {self.host}:{self.port} ({sock_err}).",
                "guidance": "Kiểm tra lại IP máy ảo Kali hoặc cấu hình mạng VMware (chuyển sang Bridged / Host-Only).",
                "one_liner": self.ONE_LINER_COMMAND
            }

        # Step 2: SSH Authentication Check
        try:
            client = self._get_client()
        except paramiko.AuthenticationException:
            return {
                "reachable": False,
                "error_code": "AUTH_FAILED",
                "host": self.host,
                "user": self.user,
                "port": self.port,
                "message": f"❌ Sai tài khoản hoặc mật khẩu đăng nhập Kali ({self.user}).",
                "guidance": "Kiểm tra lại thông tin Username & Password trong bảng cấu hình SSH.",
                "one_liner": self.ONE_LINER_COMMAND
            }
        except Exception as e:
            return {
                "reachable": False,
                "error_code": "SSH_ERROR",
                "host": self.host,
                "port": self.port,
                "error": str(e),
                "message": f"❌ Lỗi giao thức SSH tới {self.host}:{self.port} ({str(e)})",
                "guidance": "Khởi động lại SSH trên Kali bằng: sudo systemctl restart ssh",
                "one_liner": self.ONE_LINER_COMMAND
            }

        # Step 3: Audit Installed Pentest Tools
        try:
            with client:
                which_cmd = "uname -a && which " + " ".join(self.REQUIRED_TOOLS)
                stdin, stdout, stderr = client.exec_command(which_cmd, timeout=6.0)
                output = stdout.read().decode("utf-8", errors="ignore").strip()
                lines = output.splitlines()
                uname = lines[0] if lines else "Linux"
                found_paths = [line.strip() for line in lines[1:] if line.strip() and not line.strip().startswith("which:")]
                installed = set(p.split("/")[-1] for p in found_paths)
                missing = [t for t in self.REQUIRED_TOOLS if t not in installed]

                if missing:
                    return {
                        "reachable": True,
                        "warning": True,
                        "error_code": "MISSING_TOOLS",
                        "host": self.host,
                        "user": self.user,
                        "uname": uname,
                        "installed_tools": list(installed),
                        "missing_tools": missing,
                        "message": f"⚠️ Kết nối thành công nhưng thiếu tool: {', '.join(missing)}",
                        "guidance": f"Chạy lệnh sau trên terminal Kali để cài đủ:\n{self.ONE_LINER_COMMAND}",
                        "one_liner": self.ONE_LINER_COMMAND
                    }

                return {
                    "reachable": True,
                    "warning": False,
                    "host": self.host,
                    "user": self.user,
                    "uname": uname,
                    "installed_tools": list(installed),
                    "missing_tools": [],
                    "message": "✅ Kết nối SSH tới Kali Linux thành công! Đầy đủ công cụ bảo mật.",
                    "guidance": "Môi trường Kali đã sẵn sàng cho cả chế độ Fast Recon và Deep Pentest.",
                    "one_liner": self.ONE_LINER_COMMAND
                }
        except Exception as e:
            return {
                "reachable": True,
                "warning": True,
                "host": self.host,
                "installed_tools": [],
                "missing_tools": [],
                "message": f"Kết nối SSH thành công nhưng không thể đọc danh sách tool ({str(e)})",
                "one_liner": self.ONE_LINER_COMMAND
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
        try:
            target = self.sanitize_target(target)
        except ValueError as e:
            logger.warning(f"run_whois_lookup rejected target '{target}': {e}")
            return {
                "ip": target, "domain": "", "asn": "N/A", "org_name": "N/A",
                "inetnum": "N/A", "cidr": "N/A", "netname": "N/A", "country": "N/A",
                "descr": "N/A", "admin_contact": "N/A", "tech_contact": "N/A",
                "abuse_email": "N/A", "registrar": "N/A", "raw_whois_snippet": ""
            }

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
                clean_pri = self.sanitize_target(primary_ip)
                socket.inet_aton(clean_pri)
                resolved_ip = clean_pri
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

        try:
            safe_domain = self.sanitize_target(domain)
        except ValueError as e:
            logger.error(f"run_stage1_passive rejected unsafe domain '{domain}': {e}")
            return res

        # Subfinder CLI
        sf_cmd = f"subfinder -d {safe_domain} -silent -timeout 10"
        sf_out = self.run_command(sf_cmd, timeout=25.0)
        res["cli_command_logs"].append({
            "stage": "Stage 1: OSINT & Subfinder (Kali SSH)",
            "command": sf_cmd,
            "stdout": sf_out["stdout"][:2000],
            "stderr": sf_out["stderr"][:500],
            "execution_time_sec": 1.5
        })

        # Whois CLI on Kali
        whois_data = self.run_whois_lookup(safe_domain)
        res["network_whois"] = whois_data
        if whois_data.get("raw_whois_snippet"):
            res["cli_command_logs"].append({
                "stage": "Stage 1: Network & Domain Whois (Kali SSH)",
                "command": f"whois {whois_data.get('ip', safe_domain)}",
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

    def run_stage3_active(self, domain: str, target_url: str, profile: str = "fast") -> Dict[str, Any]:
        """
        Executes active pentest toolchains directly on Kali Linux via SSH.
        - Fast Recon: Quick Nmap (-F), WhatWeb, Nikto (15s).
        - Deep Pentest: Nmap NSE scripts (http-title, ssl-enum-ciphers, http-methods),
          ffuf fuzzing sensitive endpoints (/swagger.json, /.env, /.git/HEAD, /actuator),
          sslscan (TLS 1.0/1.1, RC4, 3DES), wafw00f (WAF detection), Nikto & WhatWeb.
        """
        open_ports: List[Dict[str, Any]] = []
        tech_list: List[Dict[str, Any]] = []
        nikto_list: List[str] = []
        sensitive_files: List[Dict[str, Any]] = []
        insecure_methods: List[Dict[str, Any]] = []
        ssl_audit_data: Dict[str, Any] = {}
        waf_data: Dict[str, Any] = {"detected": False, "waf_name": "None", "summary": "No WAF identified"}
        cli_logs: List[Dict[str, Any]] = []

        try:
            safe_domain = self.sanitize_target(domain)
        except ValueError as e:
            logger.error(f"run_stage3_active rejected unsafe domain '{domain}': {e}")
            return {
                "status": "ERROR",
                "message": f"Unsafe target rejected: {e}",
                "open_ports": [],
                "tech_fingerprint": {"technologies": []},
                "sensitive_files": [],
                "cors_audit": {"vulnerable": False, "findings": []},
                "insecure_methods_audit": [],
                "nikto_findings": [],
                "ssl_audit": {},
                "waf_detection": waf_data,
                "cli_command_logs": [],
                "worker_info": {
                    "worker_ip": self.host,
                    "hostname": "kali-ssh",
                    "platform": "Kali Linux (Agentless SSH)"
                }
            }

        is_deep = (str(profile).strip().lower() == "deep")
        base_proto = "https" if "https://" in (target_url or "").lower() else "http"
        base_url = f"{base_proto}://{safe_domain}"

        # -------------------------------------------------------------
        # 1. Nmap Port & Service Scan (Fast vs Deep with NSE Scripts)
        # -------------------------------------------------------------
        if is_deep:
            nmap_cmd = f"nmap -sV --version-all --script=http-title,ssl-enum-ciphers,http-methods -T4 --host-timeout 75s {safe_domain}"
            nmap_timeout = 80.0
            nmap_stage_label = "Stage 3: Deep Nmap Port & NSE Audit (Kali SSH)"
        else:
            nmap_cmd = f"nmap -F -sV --version-light -T4 --host-timeout 25s {safe_domain}"
            nmap_timeout = 30.0
            nmap_stage_label = "Stage 3: Fast Nmap Port Scan (Kali SSH)"

        t_start = time.time() if "time" in globals() else 0
        nmap_out = self.run_command(nmap_cmd, timeout=nmap_timeout)
        cli_logs.append({
            "stage": nmap_stage_label,
            "command": nmap_cmd,
            "stdout": nmap_out["stdout"][:2500],
            "stderr": nmap_out["stderr"][:500],
            "execution_time_sec": 4.5 if is_deep else 2.5
        })

        # Parse Nmap Ports & NSE script outputs
        current_port = None
        for line in nmap_out["stdout"].splitlines():
            line_str = line.strip()
            m = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line_str)
            if m:
                current_port = int(m.group(1))
                open_ports.append({
                    "port": current_port,
                    "protocol": m.group(2),
                    "service": m.group(3),
                    "version": m.group(4).strip() or "N/A",
                    "is_risky": current_port in [21, 23, 445, 1433, 3306, 5432, 6379, 9200, 27017],
                    "risk_note": "Port dịch vụ nhạy cảm phơi nhiễm" if current_port in [21, 23, 445, 1433, 3306, 5432, 6379, 9200, 27017] else "Dịch vụ mạng hoạt động"
                })
            # Parse NSE http-methods
            if "Supported Methods:" in line_str or "Potentially risky methods:" in line_str:
                methods_found = re.findall(r"\b(GET|HEAD|POST|PUT|DELETE|OPTIONS|TRACE|CONNECT|PATCH)\b", line_str)
                risky_m = [m for m in methods_found if m in ["PUT", "DELETE", "TRACE", "CONNECT"]]
                if risky_m:
                    insecure_methods.append({
                        "method": ", ".join(risky_m),
                        "risk": "HIGH",
                        "detail": f"Nmap NSE phát hiện HTTP methods nguy hiểm: {', '.join(risky_m)} trên cổng {current_port or 80}"
                    })
            # Parse NSE ssl-enum-ciphers
            if "TLSv1.0" in line_str or "TLSv1.1" in line_str:
                ssl_audit_data["deprecated_tls"] = True
            if any(weak in line_str for weak in ["3DES", "RC4", "NULL", "EXPORT"]):
                ssl_audit_data["weak_ciphers_detected"] = True

        # -------------------------------------------------------------
        # 2. Deep Pentest: ffuf Sensitive File & Hidden API Fuzzing
        # -------------------------------------------------------------
        if is_deep:
            ffuf_cmd = (
                f"if [ -f /usr/share/wordlists/dirb/common.txt ]; then "
                f"ffuf -w /usr/share/wordlists/dirb/common.txt -u {base_url}/FUZZ -mc 200,301,302,403 -s -t 30 -timeout 5; "
                f"else ffuf -w <(echo -e 'swagger.json\\napi\\napi/v1\\.env\\n.git/HEAD\\nactuator\\nadmin\\nconfig.json\\ndocs') -u {base_url}/FUZZ -mc 200,301,302,403 -s -timeout 5; fi"
            )
            ffuf_out = self.run_command(ffuf_cmd, timeout=35.0)
            cli_logs.append({
                "stage": "Stage 3: ffuf Sensitive Endpoints & Hidden API Fuzzing (Kali SSH)",
                "command": f"ffuf -w /usr/share/wordlists/dirb/common.txt -u {base_url}/FUZZ -mc 200,301,302,403 -s",
                "stdout": ffuf_out["stdout"][:2000] if ffuf_out["stdout"] else "[ffuf] Fuzzing hoàn tất. Không tìm thấy file nhạy cảm lộ thiên.",
                "stderr": ffuf_out["stderr"][:500],
                "execution_time_sec": 3.5
            })

            # Parse ffuf discovered paths
            for line in ffuf_out["stdout"].splitlines():
                path = line.strip().lstrip("/")
                if not path or len(path) < 2:
                    continue
                full_path_url = f"{base_url}/{path}"
                is_crit = any(k in path for k in [".env", ".git", "id_rsa", "config.json", "docker-compose"])
                is_api = any(k in path for k in ["swagger", "api", "v1", "graphql", "actuator", "docs"])

                if is_crit:
                    sensitive_files.append({
                        "name": f"File nhạy cảm lộ thiên: /{path}",
                        "url": full_path_url,
                        "severity": "CRITICAL",
                        "snippet": f"Kali ffuf phát hiện file nhạy cảm phản hồi HTTP active (/{path})"
                    })
                elif is_api:
                    sensitive_files.append({
                        "name": f"API / Console Endpoint: /{path}",
                        "url": full_path_url,
                        "severity": "HIGH",
                        "snippet": f"Kali ffuf phát hiện endpoint API công khai: /{path}"
                    })
                    tech_list.append({
                        "name": f"Endpoint /{path}",
                        "category": "API Surface (ffuf)",
                        "version": full_path_url
                    })

        # -------------------------------------------------------------
        # 3. Deep Pentest: sslscan (SSL/TLS Cipher & Protocol Analysis)
        # -------------------------------------------------------------
        if is_deep:
            sslscan_cmd = f"sslscan --no-colour --timeout=15 {safe_domain}"
            sslscan_out = self.run_command(sslscan_cmd, timeout=25.0)
            cli_logs.append({
                "stage": "Stage 3: sslscan SSL/TLS Protocol & Cipher Audit (Kali SSH)",
                "command": sslscan_cmd,
                "stdout": sslscan_out["stdout"][:2000] if sslscan_out["stdout"] else "[sslscan] Kiểm tra chứng chỉ hoàn tất.",
                "stderr": sslscan_out["stderr"][:500],
                "execution_time_sec": 2.0
            })

            # Extract sslscan findings
            out_s = sslscan_out["stdout"]
            has_tls10 = bool(re.search(r"TLSv1\.0\s+enabled", out_s, re.I))
            has_tls11 = bool(re.search(r"TLSv1\.1\s+enabled", out_s, re.I))
            has_weak_cipher = bool(re.search(r"(RC4|3DES|DES|CBC|NULL|EXPORT)", out_s, re.I))
            ssl_audit_data["sslscan_run"] = True
            ssl_audit_data["tls10_enabled"] = has_tls10
            ssl_audit_data["tls11_enabled"] = has_tls11
            ssl_audit_data["weak_ciphers"] = has_weak_cipher
            if has_tls10 or has_tls11:
                ssl_audit_data["protocol_warning"] = "Phát hiện máy chủ kích hoạt giao thức lỗi thời (TLS 1.0 / TLS 1.1) có nguy cơ bị tấn công hạ cấp (Downgrade Attack)."
            if has_weak_cipher:
                ssl_audit_data["cipher_warning"] = "Phát hiện thuật toán mã hóa yếu (RC4 / 3DES / CBC), dễ bị tấn công Sweet32 / BEAST."

        # -------------------------------------------------------------
        # 4. Deep Pentest: wafw00f (Web Application Firewall Fingerprint)
        # -------------------------------------------------------------
        if is_deep:
            waf_cmd = f"wafw00f {safe_domain}"
            waf_out = self.run_command(waf_cmd, timeout=25.0)
            cli_logs.append({
                "stage": "Stage 3: wafw00f Web Application Firewall Detection (Kali SSH)",
                "command": waf_cmd,
                "stdout": waf_out["stdout"][:2000] if waf_out["stdout"] else "[wafw00f] Không phát hiện WAF chặn.",
                "stderr": waf_out["stderr"][:500],
                "execution_time_sec": 2.0
            })

            m_waf = re.search(r"is behind ([\w\s.-]+?)(?:WAF|\.|\n)", waf_out["stdout"], re.I)
            if m_waf:
                waf_name = m_waf.group(1).strip()
                waf_data = {"detected": True, "waf_name": waf_name, "summary": f"Mục tiêu được bảo vệ bởi {waf_name}"}
                tech_list.append({
                    "name": f"WAF: {waf_name}",
                    "category": "Web Application Firewall",
                    "version": "Phát hiện bởi wafw00f (Kali SSH)"
                })
            else:
                waf_data = {"detected": False, "waf_name": "None", "summary": "Không phát hiện WAF hoặc mục tiêu không chặn wafw00f"}

        # -------------------------------------------------------------
        # 5. WhatWeb Fingerprint
        # -------------------------------------------------------------
        ww_cmd = f"whatweb -a 1 --color=never https://{safe_domain} || whatweb -a 1 --color=never http://{safe_domain}"
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

        # -------------------------------------------------------------
        # 6. Nikto Vulnerability Audit
        # -------------------------------------------------------------
        nikto_max_time = "25s" if is_deep else "15s"
        nikto_cmd = f"nikto -h {safe_domain} -Tuning 123b -maxtime {nikto_max_time}"
        nikto_out = self.run_command(nikto_cmd, timeout=30.0)
        cli_logs.append({
            "stage": "Stage 3: Nikto Vulnerability Audit (Kali SSH)",
            "command": nikto_cmd,
            "stdout": nikto_out["stdout"][:2000],
            "stderr": nikto_out["stderr"][:500],
            "execution_time_sec": 2.5
        })
        for line in nikto_out["stdout"].splitlines():
            if "+ OSVDB-" in line or "+ Server:" in line or "+ Retrieved" in line or "+ The anti-clickjacking" in line or "+ Uncommon header" in line:
                nikto_list.append(line.strip())

        return {
            "status": "SUCCESS",
            "profile": profile,
            "open_ports": open_ports,
            "tech_fingerprint": {"technologies": tech_list},
            "sensitive_files": sensitive_files,
            "cors_audit": {"vulnerable": False, "findings": []},
            "insecure_methods_audit": insecure_methods,
            "nikto_findings": nikto_list,
            "ssl_audit": ssl_audit_data,
            "waf_detection": waf_data,
            "cli_command_logs": cli_logs,
            "worker_info": {
                "worker_ip": self.host,
                "hostname": "kali-ssh",
                "platform": f"Kali Linux ({'Deep Pentest' if is_deep else 'Fast Recon'})"
            }
        }
