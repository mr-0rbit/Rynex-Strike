import os
import sys
import nmap
import json
import socket
import requests
import concurrent.futures
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from modules.logger import log, save_finding

class ScannerModule:

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.nm         = nmap.PortScanner()
        self.results    = {}

    # ── Host Discovery ────────────────────────────────────────────
    def discover_hosts(self, target: str) -> list:
        log(self.session_id, "SCANNER", f"Host discovery → {target}")
        try:
            self.nm.scan(hosts=target, arguments='-sn')
            hosts = []
            for host in self.nm.all_hosts():
                state = self.nm[host].state()
                hosts.append({"ip": host, "state": state})
                log(self.session_id, "SCANNER",
                    f"Host found → {host} [{state}]")
            save_finding(
                self.session_id, "SCANNER", "hosts",
                "INFO", f"Live hosts in {target}",
                f"{len(hosts)} hosts discovered",
                {"hosts": hosts}
            )
            return hosts
        except Exception as e:
            log(self.session_id, "SCANNER",
                f"Host discovery failed: {e}", "ERROR")
            return []

    # ── Port Scan ─────────────────────────────────────────────────
    def port_scan(self, ip: str, ports: str = "1-1000") -> dict:
        log(self.session_id, "SCANNER",
            f"Port scan → {ip} ports:{ports}")
        try:
            self.nm.scan(
                hosts=ip,
                ports=ports,
                arguments='-sV -sC --open'
            )
            open_ports = []
            if ip in self.nm.all_hosts():
                for proto in self.nm[ip].all_protocols():
                    for port in self.nm[ip][proto]:
                        info = self.nm[ip][proto][port]
                        if info['state'] == 'open':
                            port_data = {
                                "port"   : port,
                                "proto"  : proto,
                                "service": info.get('name', ''),
                                "version": info.get('version', ''),
                                "product": info.get('product', ''),
                                "state"  : info['state']
                            }
                            open_ports.append(port_data)
                            log(self.session_id, "SCANNER",
                                f"Open → {port}/{proto} "
                                f"{info.get('name','')} "
                                f"{info.get('product','')}")

            severity = "CRITICAL" if len(open_ports) > 10 else \
                       "HIGH"     if len(open_ports) > 5  else \
                       "MEDIUM"   if len(open_ports) > 2  else "LOW"

            save_finding(
                self.session_id, "SCANNER", "open_ports",
                severity, f"Open ports on {ip}",
                f"{len(open_ports)} open ports found",
                {"ip": ip, "ports": open_ports}
            )
            return {"ip": ip, "ports": open_ports}
        except Exception as e:
            log(self.session_id, "SCANNER",
                f"Port scan failed: {e}", "ERROR")
            return {"ip": ip, "ports": []}

    # ── Service Fingerprint ───────────────────────────────────────
    def service_fingerprint(self, ip: str) -> dict:
        log(self.session_id, "SCANNER",
            f"Service fingerprint → {ip}")
        try:
            self.nm.scan(
                hosts=ip,
                arguments='-sV -O --version-intensity 5'
            )
            info = {}
            if ip in self.nm.all_hosts():
                host_info = self.nm[ip]
                info = {
                    "os_match"  : [],
                    "hostnames" : [h['name'] for h in
                                   host_info.get('hostnames', [])],
                    "status"    : host_info.state()
                }
                if 'osmatch' in host_info:
                    for os in host_info['osmatch'][:3]:
                        info["os_match"].append({
                            "name"    : os['name'],
                            "accuracy": os['accuracy']
                        })
                        log(self.session_id, "SCANNER",
                            f"OS detected → {os['name']} "
                            f"({os['accuracy']}%)")

            save_finding(
                self.session_id, "SCANNER", "fingerprint",
                "INFO", f"Service fingerprint for {ip}",
                f"OS: {info.get('os_match', [{}])[0].get('name', 'Unknown') if info.get('os_match') else 'Unknown'}",
                info
            )
            return info
        except Exception as e:
            log(self.session_id, "SCANNER",
                f"Fingerprint failed: {e}", "ERROR")
            return {}

    # ── CVE Lookup ────────────────────────────────────────────────
    def cve_lookup(self, service: str, version: str) -> list:
        if not service or not version:
            return []
        try:
            query   = f"{service} {version}"
            url     = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params  = {
                "keywordSearch": query,
                "resultsPerPage": 5
            }
            r = requests.get(url, params=params, timeout=10)
            if r.status_code != 200:
                return []
            data = r.json()
            cves = []
            for vuln in data.get('vulnerabilities', []):
                cve  = vuln.get('cve', {})
                cvss = 0
                try:
                    metrics = cve.get('metrics', {})
                    if 'cvssMetricV31' in metrics:
                        cvss = metrics['cvssMetricV31'][0]\
                               ['cvssData']['baseScore']
                    elif 'cvssMetricV2' in metrics:
                        cvss = metrics['cvssMetricV2'][0]\
                               ['cvssData']['baseScore']
                except Exception:
                    pass

                desc = ""
                for d in cve.get('descriptions', []):
                    if d.get('lang') == 'en':
                        desc = d.get('value', '')
                        break

                cves.append({
                    "cve_id"  : cve.get('id', ''),
                    "score"   : cvss,
                    "severity": "CRITICAL" if cvss >= 9 else
                                "HIGH"     if cvss >= 7 else
                                "MEDIUM"   if cvss >= 4 else "LOW",
                    "description": desc[:200]
                })
            return sorted(cves, key=lambda x: x['score'], reverse=True)
        except Exception as e:
            log(self.session_id, "SCANNER",
                f"CVE lookup failed: {e}", "ERROR")
            return []

    # ── Map CVEs to open ports ────────────────────────────────────
    def map_cves(self, scan_result: dict) -> dict:
        log(self.session_id, "SCANNER", "Mapping CVEs to services")
        enriched = []
        for port_info in scan_result.get('ports', []):
            service = port_info.get('service', '')
            version = port_info.get('version', '')
            cves    = self.cve_lookup(service, version)
            port_info['cves'] = cves
            if cves:
                log(self.session_id, "SCANNER",
                    f"Port {port_info['port']}: "
                    f"{len(cves)} CVEs found — "
                    f"highest: {cves[0]['cve_id']} "
                    f"({cves[0]['score']})")
                save_finding(
                    self.session_id, "SCANNER", "cve_match",
                    cves[0]['severity'],
                    f"CVE match on port {port_info['port']}",
                    f"{cves[0]['cve_id']} — Score: {cves[0]['score']}",
                    {"port": port_info['port'],
                     "service": service, "cves": cves}
                )
            enriched.append(port_info)
        scan_result['ports'] = enriched
        return scan_result

    # ── Web Vulnerability Scan ────────────────────────────────────
    def web_scan(self, url: str) -> dict:
        log(self.session_id, "SCANNER", f"Web scan → {url}")
        findings = []

        # Ensure URL has scheme
        if not url.startswith('http'):
            url = 'http://' + url

        headers_to_check = [
            ('X-Frame-Options',          'MEDIUM',
             'Missing X-Frame-Options — clickjacking risk'),
            ('X-XSS-Protection',         'MEDIUM',
             'Missing XSS protection header'),
            ('X-Content-Type-Options',   'LOW',
             'Missing X-Content-Type-Options'),
            ('Strict-Transport-Security','HIGH',
             'Missing HSTS — SSL stripping risk'),
            ('Content-Security-Policy',  'HIGH',
             'Missing CSP — XSS risk'),
            ('Referrer-Policy',          'LOW',
             'Missing Referrer-Policy'),
        ]

        try:
            r = requests.get(url, timeout=10, verify=False)

            # Check security headers
            for header, severity, message in headers_to_check:
                if header not in r.headers:
                    findings.append({
                        "type"    : "missing_header",
                        "severity": severity,
                        "title"   : f"Missing {header}",
                        "detail"  : message
                    })
                    log(self.session_id, "SCANNER",
                        f"[{severity}] {message}")

            # Check for server disclosure
            server = r.headers.get('Server', '')
            if server:
                findings.append({
                    "type"    : "server_disclosure",
                    "severity": "LOW",
                    "title"   : "Server Version Disclosure",
                    "detail"  : f"Server header: {server}"
                })

            # Check for HTTP (not HTTPS)
            if url.startswith('http://'):
                findings.append({
                    "type"    : "no_https",
                    "severity": "HIGH",
                    "title"   : "No HTTPS",
                    "detail"  : "Site not using HTTPS"
                })

            # Common sensitive paths
            sensitive_paths = [
                '/admin', '/login', '/wp-admin',
                '/.git', '/.env', '/config',
                '/backup', '/phpmyadmin', '/api',
                '/robots.txt', '/sitemap.xml'
            ]
            accessible = []
            for path in sensitive_paths:
                try:
                    pr = requests.get(
                        url + path, timeout=3, verify=False
                    )
                    if pr.status_code in [200, 301, 302, 403]:
                        accessible.append({
                            "path"  : path,
                            "status": pr.status_code
                        })
                        log(self.session_id, "SCANNER",
                            f"Sensitive path found → "
                            f"{path} [{pr.status_code}]")
                except Exception:
                    pass

            if accessible:
                findings.append({
                    "type"    : "sensitive_paths",
                    "severity": "MEDIUM",
                    "title"   : "Accessible sensitive paths",
                    "detail"  : f"{len(accessible)} paths found",
                    "paths"   : accessible
                })

            for f in findings:
                save_finding(
                    self.session_id, "SCANNER",
                    f['type'], f['severity'],
                    f['title'], f['detail'],
                    f
                )

            return {
                "url"          : url,
                "status_code"  : r.status_code,
                "server"       : server,
                "findings"     : findings,
                "total_issues" : len(findings)
            }

        except Exception as e:
            log(self.session_id, "SCANNER",
                f"Web scan failed: {e}", "ERROR")
            return {"url": url, "error": str(e), "findings": []}

    # ── Full Scan Run ─────────────────────────────────────────────
    def run_full(self, target: str, target_type: str) -> dict:
        log(self.session_id, "SCANNER",
            f"Full scan → {target} [{target_type}]")
        self.results = {
            "target"     : target,
            "target_type": target_type
        }

        if target_type == "website":
            domain = target.replace("http://","").replace("https://","").split("/")[0]
            try:
                ip = socket.gethostbyname(domain)
            except Exception:
                ip = domain
            self.results["ip"]       = ip
            self.results["ports"]    = self.port_scan(ip)
            self.results["ports"]    = self.map_cves(self.results["ports"])
            self.results["web"]      = self.web_scan(target)
            self.results["os_info"]  = self.service_fingerprint(ip)

        elif target_type == "machine":
            self.results["ports"]   = self.port_scan(target)
            self.results["ports"]   = self.map_cves(self.results["ports"])
            self.results["os_info"] = self.service_fingerprint(target)

        elif target_type == "network":
            hosts = self.discover_hosts(target)
            self.results["hosts"] = []
            for host in hosts:
                ip        = host["ip"]
                scan      = self.port_scan(ip, "1-500")
                scan      = self.map_cves(scan)
                os_info   = self.service_fingerprint(ip)
                self.results["hosts"].append({
                    "ip"    : ip,
                    "ports" : scan,
                    "os"    : os_info
                })

        log(self.session_id, "SCANNER", "Full scan complete")
        return self.results
