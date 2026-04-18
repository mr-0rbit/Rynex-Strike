import os
import sys
import socket
import json
import requests
import dns.resolver
import whois
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from modules.logger import log, save_finding

class OSINTModule:

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.results    = {}

    # ── DNS Recon ─────────────────────────────────────────────────
    def dns_recon(self, domain: str) -> dict:
        log(self.session_id, "OSINT", f"DNS recon → {domain}")
        records = {}
        for rtype in ['A', 'MX', 'NS', 'TXT', 'CNAME', 'AAAA']:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []

        save_finding(
            self.session_id, "OSINT", "dns_records", "INFO",
            f"DNS Records for {domain}",
            f"Found {sum(len(v) for v in records.values())} DNS records",
            records
        )
        log(self.session_id, "OSINT", f"DNS recon complete → {len(records)} record types")
        return records

    # ── WHOIS ─────────────────────────────────────────────────────
    def whois_lookup(self, target: str) -> dict:
        log(self.session_id, "OSINT", f"WHOIS lookup → {target}")
        try:
            w = whois.whois(target)
            data = {
                "domain_name"  : str(w.domain_name),
                "registrar"    : str(w.registrar),
                "creation_date": str(w.creation_date),
                "expiry_date"  : str(w.expiration_date),
                "name_servers" : str(w.name_servers),
                "org"          : str(w.org),
                "country"      : str(w.country),
                "emails"       : str(w.emails)
            }
            save_finding(
                self.session_id, "OSINT", "whois", "INFO",
                f"WHOIS data for {target}",
                f"Registrar: {data['registrar']}",
                data
            )
            return data
        except Exception as e:
            log(self.session_id, "OSINT", f"WHOIS failed: {e}", "ERROR")
            return {}

    # ── Subdomain Enumeration ─────────────────────────────────────
    def subdomain_enum(self, domain: str) -> list:
        log(self.session_id, "OSINT", f"Subdomain enum → {domain}")
        found = []

        # Common subdomains wordlist
        common = [
            'www', 'mail', 'ftp', 'admin', 'vpn', 'api',
            'dev', 'staging', 'test', 'portal', 'remote',
            'blog', 'shop', 'secure', 'webmail', 'mx',
            'ns1', 'ns2', 'smtp', 'pop', 'imap', 'cdn',
            'static', 'media', 'app', 'mobile', 'beta'
        ]

        for sub in common:
            hostname = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(hostname)
                found.append({"subdomain": hostname, "ip": ip})
                log(self.session_id, "OSINT",
                    f"Subdomain found → {hostname} ({ip})")
            except Exception:
                pass

        if found:
            save_finding(
                self.session_id, "OSINT", "subdomains",
                "MEDIUM" if len(found) > 3 else "LOW",
                f"Subdomains found for {domain}",
                f"{len(found)} subdomains discovered",
                {"subdomains": found}
            )
        return found

    # ── IP Recon ─────────────────────────────────────────────────
    def ip_recon(self, ip: str) -> dict:
        log(self.session_id, "OSINT", f"IP recon → {ip}")
        try:
            r = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5
            ).json()
            data = {
                "ip"      : ip,
                "country" : r.get("country", ""),
                "region"  : r.get("regionName", ""),
                "city"    : r.get("city", ""),
                "isp"     : r.get("isp", ""),
                "org"     : r.get("org", ""),
                "lat"     : r.get("lat", ""),
                "lon"     : r.get("lon", ""),
                "timezone": r.get("timezone", "")
            }
            save_finding(
                self.session_id, "OSINT", "ip_info", "INFO",
                f"IP Intelligence for {ip}",
                f"ISP: {data['isp']} | Location: {data['city']}, {data['country']}",
                data
            )
            return data
        except Exception as e:
            log(self.session_id, "OSINT", f"IP recon failed: {e}", "ERROR")
            return {}

    # ── Email Harvesting ──────────────────────────────────────────
    def email_harvest(self, domain: str) -> list:
        log(self.session_id, "OSINT", f"Email harvest → {domain}")
        emails = set()

        # Check common email patterns via DNS MX
        try:
            mx = dns.resolver.resolve(domain, 'MX')
            for r in mx:
                log(self.session_id, "OSINT",
                    f"MX record → {r.exchange}")
        except Exception:
            pass

        # Common admin emails
        prefixes = ['admin', 'info', 'contact', 'support',
                    'security', 'abuse', 'webmaster', 'noc']
        for prefix in prefixes:
            emails.add(f"{prefix}@{domain}")

        result = list(emails)
        if result:
            save_finding(
                self.session_id, "OSINT", "emails", "LOW",
                f"Potential emails for {domain}",
                f"{len(result)} email addresses identified",
                {"emails": result}
            )
        return result

    # ── Port to IP resolution ─────────────────────────────────────
    def resolve_target(self, target: str) -> str:
        try:
            return socket.gethostbyname(target)
        except Exception:
            return target

    # ── Full OSINT Run ────────────────────────────────────────────
    def run_full(self, target: str, target_type: str) -> dict:
        log(self.session_id, "OSINT",
            f"Full OSINT started → {target} [{target_type}]")

        self.results = {"target": target, "target_type": target_type}

        if target_type == "website":
            domain = target.replace("http://","").replace("https://","").split("/")[0]
            ip     = self.resolve_target(domain)
            self.results["domain"]     = domain
            self.results["ip"]         = ip
            self.results["dns"]        = self.dns_recon(domain)
            self.results["whois"]      = self.whois_lookup(domain)
            self.results["subdomains"] = self.subdomain_enum(domain)
            self.results["ip_info"]    = self.ip_recon(ip)
            self.results["emails"]     = self.email_harvest(domain)

        elif target_type in ["network", "machine"]:
            ip = self.resolve_target(target)
            self.results["ip"]      = ip
            self.results["ip_info"] = self.ip_recon(ip)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                self.results["hostname"] = hostname
                self.results["dns"]      = self.dns_recon(hostname)
                self.results["whois"]    = self.whois_lookup(hostname)
            except Exception:
                self.results["hostname"] = "unknown"

        log(self.session_id, "OSINT",
            f"Full OSINT complete → {len(self.results)} data points")
        return self.results
