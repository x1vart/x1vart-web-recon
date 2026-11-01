"""
x1vart - Scope Control & In-Scope Validator Module
Enforces strict scope boundaries before network operations (DNS, HTTP, Port Scan).
Analyzes FQDN, Wildcards, CNAME records, and IP addresses to prevent out-of-scope/third-party scanning.
"""

import ipaddress
import logging
import re
import socket
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urlparse

try:
    import dns.asyncresolver
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

logger = logging.getLogger("x1vart.scope_validator")


@dataclass
class ScopeEvaluationResult:
    is_in_scope: bool
    target: str
    hostname: str
    matched_rule: Optional[str] = None
    resolved_ips: List[str] = field(default_factory=list)
    cnames: List[str] = field(default_factory=list)
    warning: Optional[str] = None
    is_third_party: bool = False


class ScopeValidator:
    """
    Scope validation middleware to guard against unauthorized network scans.
    Validates apex domains, wildcard patterns (*.corp.com), CNAME records, and IP ranges.
    """

    DEFAULT_THIRD_PARTY_DOMAINS: Set[str] = {
        "s3.amazonaws.com",
        "amazonaws.com",
        "cloudflare.net",
        "cloudflare.com",
        "zendesk.com",
        "github.io",
        "herokuapp.com",
        "cloudfront.net",
        "fastly.net",
        "akamaized.net",
        "azureedge.net",
        "blob.core.windows.net",
        "googleusercontent.com",
        "shopify.com",
        "wpengine.com",
        "mailchimp.com",
        "salesforce.com",
        "hubspot.com"
    }

    def __init__(
        self,
        whitelist_domains: Optional[List[str]] = None,
        out_of_scope_domains: Optional[List[str]] = None,
        third_party_services: Optional[List[str]] = None,
        allow_private_ips: bool = False
    ):
        self.whitelist: List[str] = [d.strip().lower() for d in (whitelist_domains or []) if d.strip()]
        self.out_of_scope: List[str] = [d.strip().lower() for d in (out_of_scope_domains or []) if d.strip()]
        self.third_party: Set[str] = set(self.DEFAULT_THIRD_PARTY_DOMAINS)
        if third_party_services:
            self.third_party.update(d.strip().lower() for d in third_party_services if d.strip())
        self.allow_private_ips = allow_private_ips

    @staticmethod
    def extract_hostname(target: str) -> str:
        """Extracts clean hostname or IP from URL, domain, or host:port string."""
        target = (target or "").strip()
        if not target:
            return ""
        if "://" in target:
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc or target
        else:
            host = target.split("/")[0]

        if ":" in host and not host.startswith("["):
            host = host.split(":")[0]
        return host.strip("[]").strip().lower()

    def _matches_pattern(self, hostname: str, pattern: str) -> bool:
        """
        Matches hostname against exact domain or wildcard pattern.
        E.g.: *.example.com matches sub.example.com, but not example.com.
        *.example.com pattern also matches deep.sub.example.com.
        """
        hostname = hostname.lower()
        pattern = pattern.lower()

        if pattern.startswith("*."):
            base_domain = pattern[2:]
            return hostname == base_domain or hostname.endswith("." + base_domain)
        elif pattern.startswith("."):
            base_domain = pattern[1:]
            return hostname == base_domain or hostname.endswith("." + base_domain)
        return hostname == pattern

    def _is_third_party(self, domain_name: str) -> Optional[str]:
        """Checks if a domain or its parent belongs to known third-party SaaS/Cloud providers."""
        domain_name = domain_name.lower()
        for tp in self.third_party:
            if domain_name == tp or domain_name.endswith("." + tp):
                return tp
        return None

    async def resolve_dns_details(self, hostname: str) -> tuple[List[str], List[str]]:
        """Resolves CNAME chain and A/AAAA IP records asynchronously."""
        cnames: List[str] = []
        ips: List[str] = []

        # If hostname is already raw IP address, return directly
        try:
            ipaddress.ip_address(hostname)
            return cnames, [hostname]
        except ValueError:
            pass

        if HAS_DNSPYTHON:
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = 2.0
            resolver.lifetime = 2.5

            # 1. Resolve CNAME chain
            curr = hostname
            try:
                for _ in range(5):
                    cname_ans = await resolver.resolve(curr, "CNAME")
                    target_cname = str(cname_ans[0].target).rstrip(".").lower()
                    if target_cname and target_cname != curr:
                        cnames.append(target_cname)
                        curr = target_cname
                    else:
                        break
            except Exception:
                pass

            # 2. Resolve A records
            try:
                a_ans = await resolver.resolve(hostname, "A")
                for rdata in a_ans:
                    ips.append(rdata.address)
            except Exception:
                pass
        else:
            # Fallback to standard library getaddrinfo
            try:
                addr_info = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
                for item in addr_info:
                    ip = item[4][0]
                    if ip not in ips:
                        ips.append(ip)
            except Exception:
                pass

        return cnames, ips

    async def evaluate_scope(self, target: str) -> ScopeEvaluationResult:
        """
        Comprehensive scope evaluation:
        1. Hostname extraction & Out-Of-Scope list check.
        2. Direct Third-Party service check.
        3. Whitelist matching (exact or wildcard).
        4. DNS CNAME resolution (detects alias pointing to third-party).
        5. IP Resolution & RFC 1918 Private IP filtering.
        """
        hostname = self.extract_hostname(target)
        if not hostname:
            return ScopeEvaluationResult(
                is_in_scope=False,
                target=target,
                hostname="",
                warning="Empty or invalid target hostname."
            )

        # Step 1: Explicit Out-Of-Scope check
        for oos in self.out_of_scope:
            if self._matches_pattern(hostname, oos):
                msg = f"Host '{hostname}' matched explicit Out-Of-Scope rule '{oos}'."
                logger.warning(f"[SCOPE REJECTED] {msg}")
                return ScopeEvaluationResult(
                    is_in_scope=False,
                    target=target,
                    hostname=hostname,
                    matched_rule=oos,
                    warning=msg
                )

        # Step 1.5: Direct Private / Loopback IP check
        if not self.allow_private_ips:
            try:
                ip_obj = ipaddress.ip_address(hostname)
                if ip_obj.is_private or ip_obj.is_loopback:
                    msg = f"Host '{hostname}' is a private/loopback IP address. Scanning private network ranges is disabled."
                    logger.warning(f"[SCOPE REJECTED] {msg}")
                    return ScopeEvaluationResult(
                        is_in_scope=False,
                        target=target,
                        hostname=hostname,
                        resolved_ips=[hostname],
                        warning=msg
                    )
            except ValueError:
                pass

        # Step 2: Direct Third-Party Check
        tp_match = self._is_third_party(hostname)
        if tp_match:
            msg = f"Host '{hostname}' points directly to Third-Party service provider '{tp_match}'."
            logger.warning(f"[SCOPE REJECTED] {msg}")
            return ScopeEvaluationResult(
                is_in_scope=False,
                target=target,
                hostname=hostname,
                is_third_party=True,
                matched_rule=tp_match,
                warning=msg
            )

        # Step 3: Whitelist check
        in_whitelist = False
        matched_rule = None
        if not self.whitelist:
            # If whitelist is empty, default permissive mode (excluding OOS/Third-party)
            in_whitelist = True
            matched_rule = "*"
        else:
            for wl in self.whitelist:
                if self._matches_pattern(hostname, wl):
                    in_whitelist = True
                    matched_rule = wl
                    break

        if not in_whitelist:
            msg = f"Host '{hostname}' does not match any configured whitelist domains: {self.whitelist}."
            logger.warning(f"[SCOPE REJECTED] {msg}")
            return ScopeEvaluationResult(
                is_in_scope=False,
                target=target,
                hostname=hostname,
                warning=msg
            )

        # Step 4: CNAME Resolution check (detects subdomains pointing to foreign services)
        cnames, ips = await self.resolve_dns_details(hostname)
        for cname in cnames:
            cname_tp = self._is_third_party(cname)
            if cname_tp:
                msg = f"Host '{hostname}' CNAME alias '{cname}' points to external Third-Party cloud service '{cname_tp}'."
                logger.warning(f"[SCOPE REJECTED] {msg}")
                return ScopeEvaluationResult(
                    is_in_scope=False,
                    target=target,
                    hostname=hostname,
                    is_third_party=True,
                    cnames=cnames,
                    resolved_ips=ips,
                    matched_rule=cname_tp,
                    warning=msg
                )

            for oos in self.out_of_scope:
                if self._matches_pattern(cname, oos):
                    msg = f"Host '{hostname}' CNAME alias '{cname}' is in Out-Of-Scope list."
                    logger.warning(f"[SCOPE REJECTED] {msg}")
                    return ScopeEvaluationResult(
                        is_in_scope=False,
                        target=target,
                        hostname=hostname,
                        cnames=cnames,
                        resolved_ips=ips,
                        matched_rule=oos,
                        warning=msg
                    )

        # Step 5: IP Range validation
        if ips and not self.allow_private_ips:
            for ip_str in ips:
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    if ip_obj.is_private or ip_obj.is_loopback:
                        msg = f"Host '{hostname}' resolved to private/loopback IP address {ip_str}. Private network scanning disabled."
                        logger.warning(f"[SCOPE REJECTED] {msg}")
                        return ScopeEvaluationResult(
                            is_in_scope=False,
                            target=target,
                            hostname=hostname,
                            cnames=cnames,
                            resolved_ips=ips,
                            warning=msg
                        )
                except ValueError:
                    pass

        return ScopeEvaluationResult(
            is_in_scope=True,
            target=target,
            hostname=hostname,
            matched_rule=matched_rule,
            cnames=cnames,
            resolved_ips=ips
        )

    async def is_in_scope(self, target: str) -> bool:
        """Convenience boolean helper method."""
        eval_res = await self.evaluate_scope(target)
        return eval_res.is_in_scope
