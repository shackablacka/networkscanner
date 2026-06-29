#!/usr/bin/env python3
"""
Network scanner + safe packet capture helper.

What it does:
  1) Actively discovers devices on a local IPv4 subnet using ARP requests.
  2) Reads the system ARP cache/table and merges any extra entries.
  3) Lets you choose a discovered device.
  4) Captures packets matching that chosen device's IP that are visible to THIS machine,
     then saves them to a .pcap file and prints a small summary.

Important:
  - Use only on networks/devices you own or are explicitly authorized to monitor.
  - This script does NOT perform ARP spoofing/poisoning, MITM, credential capture,
    decryption, or bypasses. On normal switched networks you usually only see your own
    traffic plus broadcast/multicast traffic unless your network is configured for monitoring.

Requirements:
  pip install scapy

Run as administrator/root for ARP scanning and packet capture:
  sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24
  sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --count 100
  sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --timeout 60 --output capture.pcap
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Dict, Iterable, Optional

try:
    from scapy.all import (
        ARP,
        BOOTP,
        DHCP,
        DNS,
        DNSQR,
        Ether,
        ICMP,
        IP,
        Raw,
        TCP,
        UDP,
        conf,
        get_if_addr,
        get_if_hwaddr,
        sniff,
        srp,
        wrpcap,
    )
    SCAPY_IMPORT_ERROR = None
except ImportError as exc:
    # Import lazily/fail later so `--help` and ARP-table-only utilities can still work.
    ARP = BOOTP = DHCP = DNS = DNSQR = Ether = ICMP = IP = Raw = TCP = UDP = None
    conf = get_if_addr = get_if_hwaddr = sniff = srp = wrpcap = None
    SCAPY_IMPORT_ERROR = exc


def require_scapy() -> None:
    """Exit with a clear message if Scapy is unavailable."""
    if SCAPY_IMPORT_ERROR is not None:
        print("Missing dependency: scapy", file=sys.stderr)
        print("Install it with: python3 -m pip install scapy", file=sys.stderr)
        raise SystemExit(1)


@dataclass
class Device:
    ip: str
    mac: str = "unknown"
    hostname: str = ""
    vendor: str = ""
    source: str = ""


def is_adminish() -> bool:
    """Best-effort privilege check. Packet capture/ARP scanning usually needs elevated rights."""
    if os.name == "nt":
        # Avoid ctypes dependency details; Windows will fail later if not elevated/Npcap missing.
        return True
    return hasattr(os, "geteuid") and os.geteuid() == 0


def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    return mac if re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac) else "unknown"


def hostname_for_ip(ip: str, timeout_seconds: float = 0.4) -> str:
    """Reverse DNS lookup with a short socket timeout."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout_seconds)
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old_timeout)


def guess_vendor(mac: str) -> str:
    """
    Best-effort offline vendor guess from a few common OUIs.
    This avoids sending MAC addresses to an external lookup service.
    Extend COMMON_OUIS if you want more vendor names.
    """
    if mac == "unknown":
        return ""
    oui = mac.upper().replace(":", "")[:6]
    common_ouis = {
        "001A11": "Google/Nest",
        "3C5A37": "Google/Nest",
        "F4F5D8": "Google/Nest",
        "DCA632": "Raspberry Pi",
        "B827EB": "Raspberry Pi",
        "E45F01": "Raspberry Pi",
        "F0D7AA": "Amazon",
        "FC65DE": "Amazon",
        "684898": "Amazon",
        "A47733": "Amazon",
        "001788": "Philips",
        "B0C5CA": "Samsung",
        "F8D0BD": "Samsung",
        "7CD1C3": "Apple",
        "A4C361": "Apple",
        "F0DBE2": "Apple",
        "28CFDA": "Apple",
        "D850E6": "ASUSTek",
        "C8D7B0": "TP-Link",
        "50C7BF": "TP-Link",
        "B0487A": "TP-Link",
        "001CDF": "Belkin",
        "94103E": "Belkin",
        "001E58": "D-Link",
        "C0A0BB": "D-Link",
        "2C3033": "Netgear",
        "A040A0": "Netgear",
        "00146C": "Netgear",
    }
    return common_ouis.get(oui, "")


def infer_default_subnet() -> str:
    """
    Infer a likely /24 from Scapy's default interface address.
    For accuracy, pass --subnet explicitly.
    """
    require_scapy()
    try:
        iface = conf.iface
        ip = get_if_addr(iface)
        if not ip or ip.startswith("127.") or ip == "0.0.0.0":
            raise ValueError("no usable interface IP")
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(network)
    except Exception as exc:
        raise SystemExit(
            "Could not infer a subnet automatically. Please pass one, e.g. --subnet 192.168.1.0/24"
        ) from exc


def active_arp_scan(subnet: str, timeout: int = 3, iface: Optional[str] = None) -> Dict[str, Device]:
    """Send ARP who-has requests to discover local IPv4 devices."""
    require_scapy()
    devices: Dict[str, Device] = {}
    print(f"[*] ARP scanning {subnet} ...")

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    answered, _unanswered = srp(pkt, timeout=timeout, iface=iface, verbose=False)

    for _sent, received in answered:
        ip = str(received.psrc)
        mac = normalize_mac(str(received.hwsrc))
        devices[ip] = Device(ip=ip, mac=mac, hostname=hostname_for_ip(ip), vendor=guess_vendor(mac), source="arp-scan")

    return devices


def read_arp_cache() -> Dict[str, Device]:
    """Parse the OS ARP cache/table. Patterns cover common Linux/macOS/Windows output."""
    devices: Dict[str, Device] = {}
    system = platform.system().lower()

    commands = []
    if "windows" in system:
        commands = [["arp", "-a"]]
    else:
        commands = [["ip", "neigh"], ["arp", "-a"]]

    for cmd in commands:
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=4, check=False)
        except (FileNotFoundError, subprocess.SubprocessError):
            continue

        output = proc.stdout + "\n" + proc.stderr
        for line in output.splitlines():
            ip = None
            mac = None

            # Linux ip neigh: 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
            m = re.search(
                r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*?lladdr\s+(?P<mac>[0-9a-fA-F:-]{17})",
                line,
            )
            if m:
                ip, mac = m.group("ip"), m.group("mac")

            # macOS/Linux arp -a: router (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
            if ip is None:
                m = re.search(
                    r"\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(?P<mac>[0-9a-fA-F:-]{17})",
                    line,
                )
                if m:
                    ip, mac = m.group("ip"), m.group("mac")

            # Windows arp -a: 192.168.1.1           aa-bb-cc-dd-ee-ff     dynamic
            if ip is None:
                m = re.search(
                    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>[0-9a-fA-F:-]{17})\s+\w+",
                    line,
                )
                if m:
                    ip, mac = m.group("ip"), m.group("mac")

            if ip and mac:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    continue
                norm_mac = normalize_mac(mac)
                devices[ip] = Device(
                    ip=ip,
                    mac=norm_mac,
                    hostname=hostname_for_ip(ip),
                    vendor=guess_vendor(norm_mac),
                    source="arp-cache",
                )

    return devices


def merge_devices(*device_maps: Dict[str, Device]) -> Dict[str, Device]:
    merged: Dict[str, Device] = {}
    for dmap in device_maps:
        for ip, dev in dmap.items():
            if ip not in merged:
                merged[ip] = dev
            else:
                existing = merged[ip]
                if existing.mac == "unknown" and dev.mac != "unknown":
                    existing.mac = dev.mac
                if not existing.hostname and dev.hostname:
                    existing.hostname = dev.hostname
                if not existing.vendor and dev.vendor:
                    existing.vendor = dev.vendor
                if dev.source not in existing.source:
                    existing.source = f"{existing.source}+{dev.source}" if existing.source else dev.source
    return dict(sorted(merged.items(), key=lambda kv: ipaddress.ip_address(kv[0])))


def print_devices(devices: Dict[str, Device]) -> None:
    print("\nDiscovered devices connected/visible on this Wi-Fi/LAN")
    print("=" * 108)
    print(f"{'#':>3}  {'IP':<16} {'MAC':<18} {'Hostname':<28} {'Vendor':<18} Source")
    print("-" * 108)
    for idx, dev in enumerate(devices.values(), start=1):
        hostname = (dev.hostname[:27] + "…") if len(dev.hostname) > 28 else dev.hostname
        vendor = (dev.vendor[:17] + "…") if len(dev.vendor) > 18 else dev.vendor
        print(f"{idx:>3}  {dev.ip:<16} {dev.mac:<18} {hostname:<28} {vendor:<18} {dev.source}")
    print("=" * 108)


def save_devices(devices: Dict[str, Device], base_path: str = "discovered_devices") -> None:
    """Save discovered device information to JSON and CSV files."""
    rows = [asdict(dev) for dev in devices.values()]

    json_path = f"{base_path}.json"
    csv_path = f"{base_path}.csv"

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2)

    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "mac", "hostname", "vendor", "source"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Saved device list to {json_path} and {csv_path}")


def choose_device(devices: Dict[str, Device], target: Optional[str]) -> Device:
    if not devices:
        raise SystemExit("No devices discovered. Try a different --subnet, increase --scan-timeout, or check privileges.")

    values = list(devices.values())

    if target:
        # Accept an index or IP address.
        if target.isdigit():
            idx = int(target)
            if 1 <= idx <= len(values):
                return values[idx - 1]
            raise SystemExit(f"Invalid target index: {target}")
        try:
            ipaddress.ip_address(target)
        except ValueError:
            raise SystemExit("--target must be a discovered IP address or list index")
        if target in devices:
            return devices[target]
        raise SystemExit(f"Target {target} was not in the discovered device list")

    while True:
        print("\nOptions:")
        print("  - Enter a device number, e.g. 3")
        print("  - Enter an IP address, e.g. 192.168.1.25")
        print("  - Enter r to rescan")
        print("  - Enter q to quit")
        choice = input("Choose a device to capture visible packets for: ").strip().lower()

        if choice in {"q", "quit", "exit"}:
            raise SystemExit("User quit before capture.")
        if choice in {"r", "rescan"}:
            raise SystemExit("RESCAN_REQUESTED")

        try:
            return choose_device(devices, choice)
        except SystemExit as exc:
            print(exc)


PROTOCOL_FILTERS = {
    # Safe capture/display presets. These only filter traffic already visible to this machine.
    "all": "",
    "arp": "arp",
    "dns": "udp port 53 or tcp port 53",
    "http": "tcp port 80",
    "https": "tcp port 443",
    "web": "tcp port 80 or tcp port 443",
    "dhcp": "udp port 67 or udp port 68",
    "icmp": "icmp",
    "ping": "icmp",
    "ssh": "tcp port 22",
    "ftp": "tcp port 21 or tcp port 20",
    "smtp": "tcp port 25 or tcp port 465 or tcp port 587",
    "imap": "tcp port 143 or tcp port 993",
    "pop3": "tcp port 110 or tcp port 995",
    "ntp": "udp port 123",
    "mdns": "udp port 5353",
    "llmnr": "udp port 5355",
    "netbios": "udp port 137 or udp port 138 or tcp port 139",
    "smb": "tcp port 445",
    "rdp": "tcp port 3389",
}


HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"}


def available_protocols() -> str:
    return ", ".join(sorted(PROTOCOL_FILTERS.keys()))


def build_bpf_filter(target_ip: str, protocols: list[str], custom_bpf: Optional[str] = None) -> str:
    """Build a BPF capture filter for the selected host and protocol presets."""
    base = f"host {target_ip}"

    if custom_bpf:
        return f"({base}) and ({custom_bpf})"

    normalized = [p.strip().lower() for p in protocols if p.strip()]
    if not normalized or "all" in normalized:
        return base

    unknown = [p for p in normalized if p not in PROTOCOL_FILTERS]
    if unknown:
        raise SystemExit(f"Unknown protocol preset(s): {', '.join(unknown)}. Available: {available_protocols()}")

    protocol_parts = [PROTOCOL_FILTERS[p] for p in normalized if PROTOCOL_FILTERS[p]]
    if not protocol_parts:
        return base

    return f"({base}) and ({' or '.join(f'({part})' for part in protocol_parts)})"


def packet_protocol(pkt) -> str:
    """Classify packet protocol for display purposes."""
    try:
        if pkt.haslayer(ARP):
            return "ARP"
        if pkt.haslayer(DNS):
            return "DNS"
        if pkt.haslayer(DHCP) or pkt.haslayer(BOOTP):
            return "DHCP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer(TCP):
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            ports = {sport, dport}
            if 80 in ports:
                return "HTTP"
            if 443 in ports:
                return "HTTPS"
            if 22 in ports:
                return "SSH"
            if 445 in ports:
                return "SMB"
            if 3389 in ports:
                return "RDP"
            if 21 in ports or 20 in ports:
                return "FTP"
            if 25 in ports or 465 in ports or 587 in ports:
                return "SMTP"
            if 143 in ports or 993 in ports:
                return "IMAP"
            if 110 in ports or 995 in ports:
                return "POP3"
            return "TCP"
        if pkt.haslayer(UDP):
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            ports = {sport, dport}
            if 53 in ports:
                return "DNS"
            if 67 in ports or 68 in ports:
                return "DHCP"
            if 123 in ports:
                return "NTP"
            if 5353 in ports:
                return "mDNS"
            if 5355 in ports:
                return "LLMNR"
            if 137 in ports or 138 in ports:
                return "NetBIOS"
            return "UDP"
        if pkt.haslayer(IP):
            return "IP"
    except Exception:
        pass
    return "OTHER"


def safe_raw_preview(pkt, limit: int = 80) -> str:
    """Return a short printable preview of packet payload metadata, not full sensitive content."""
    try:
        if not pkt.haslayer(Raw):
            return ""
        raw = bytes(pkt[Raw].load)
        text = raw[:limit].decode("utf-8", errors="replace")
        text = "".join(ch if 32 <= ord(ch) <= 126 else "." for ch in text)
        return text
    except Exception:
        return ""


def packet_line(pkt, show_details: bool = False) -> str:
    """Build a compact packet summary without dumping full payload contents."""
    ts = datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S") if hasattr(pkt, "time") else "--:--:--"
    proto = packet_protocol(pkt)

    try:
        src = dst = "?"
        extra = ""

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
        elif pkt.haslayer(ARP):
            src = pkt[ARP].psrc
            dst = pkt[ARP].pdst

        if pkt.haslayer(TCP):
            src = f"{src}:{pkt[TCP].sport}"
            dst = f"{dst}:{pkt[TCP].dport}"
        elif pkt.haslayer(UDP):
            src = f"{src}:{pkt[UDP].sport}"
            dst = f"{dst}:{pkt[UDP].dport}"

        if pkt.haslayer(DNS):
            try:
                qr = pkt[DNS].qr
                if qr == 0 and pkt[DNS].qd and pkt[DNS].qd.qname:
                    qname = pkt[DNS].qd.qname.decode(errors="replace").rstrip(".")
                    extra = f" query={qname}"
                elif qr == 1:
                    extra = " response"
            except Exception:
                pass

        if proto == "HTTP" and pkt.haslayer(Raw):
            preview = safe_raw_preview(pkt, 120)
            first = preview.split("\\r\\n", 1)[0].split("\\n", 1)[0]
            method = first.split(" ", 1)[0].upper() if first else ""
            if method in HTTP_METHODS or first.startswith("HTTP/"):
                extra = f" {first[:100]}"

        if show_details:
            return f"[{ts}] {proto:<7} {src} -> {dst}{extra} | {pkt.summary()}"
        return f"[{ts}] {proto:<7} {src} -> {dst}{extra}"
    except Exception:
        try:
            return f"[{ts}] {proto:<7} {pkt.summary()}"
        except Exception:
            return f"[{ts}] <packet>"


def capture_for_device(
    target_ip: str,
    output: str,
    iface: Optional[str],
    count: int,
    timeout: Optional[int],
    protocols: list[str],
    custom_bpf: Optional[str] = None,
    show_details: bool = False,
) -> None:
    require_scapy()
    bpf_filter = build_bpf_filter(target_ip, protocols, custom_bpf)
    print("\n[*] Starting packet capture")
    print(f"    Target filter : host {target_ip}")
    print(f"    Protocols     : {', '.join(protocols) if protocols else 'all'}")
    if custom_bpf:
        print(f"    Custom BPF    : {custom_bpf}")
    print(f"    Final BPF     : {bpf_filter}")
    print(f"    Interface     : {iface or conf.iface}")
    print(f"    Output        : {output}")
    print(f"    Stop condition: {'count=' + str(count) if count else ''} {'timeout=' + str(timeout) + 's' if timeout else ''}".strip())
    print("[*] Press Ctrl+C to stop early. Full payloads are not printed; packets are saved to PCAP.\n")

    packets = []

    def on_packet(pkt):
        print(packet_line(pkt, show_details=show_details))
        packets.append(pkt)

    # BPF filter keeps collection limited to the selected IP/protocols. If libpcap/BPF is unavailable,
    # fall back to a Python-level host filter.
    try:
        sniff(
            iface=iface,
            filter=bpf_filter,
            prn=on_packet,
            store=False,
            count=count if count > 0 else 0,
            timeout=timeout,
        )
    except Exception as exc:
        print(f"[!] BPF capture failed ({exc}). Falling back to Python-level host filtering.")
        print("[!] Note: protocol filtering may be less precise in fallback mode.")

        protocol_set = {p.strip().lower() for p in protocols if p.strip()}

        def protocol_matches(pkt) -> bool:
            if not protocol_set or "all" in protocol_set or custom_bpf:
                return True
            proto = packet_protocol(pkt).lower()
            if "web" in protocol_set and proto in {"http", "https"}:
                return True
            aliases = {"ping": "icmp"}
            return proto in protocol_set or aliases.get(proto, proto) in protocol_set

        def lfilter(pkt) -> bool:
            try:
                host_match = False
                if pkt.haslayer(IP):
                    host_match = pkt[IP].src == target_ip or pkt[IP].dst == target_ip
                elif pkt.haslayer(ARP):
                    host_match = pkt[ARP].psrc == target_ip or pkt[ARP].pdst == target_ip
                return host_match and protocol_matches(pkt)
            except Exception:
                return False

        sniff(
            iface=iface,
            lfilter=lfilter,
            prn=on_packet,
            store=False,
            count=count if count > 0 else 0,
            timeout=timeout,
        )

    if packets:
        wrpcap(output, packets)
        print(f"\n[+] Saved {len(packets)} packets to {output}")
    else:
        print("\n[!] No matching packets captured. This is normal on switched networks if no visible traffic matches.")


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="ARP network scanner plus safe visible packet capture.")
    parser.add_argument("--subnet", help="IPv4 subnet to ARP scan, e.g. 192.168.1.0/24. Defaults to inferred /24.")
    parser.add_argument("--iface", help="Network interface to use. Defaults to Scapy's default interface.")
    parser.add_argument("--scan-timeout", type=int, default=3, help="ARP scan timeout in seconds. Default: 3")
    parser.add_argument("--target", help="Optional target IP or list index to skip interactive selection.")
    parser.add_argument("--count", type=int, default=50, help="Stop after this many packets. Use 0 for no count limit. Default: 50")
    parser.add_argument("--timeout", type=int, default=60, help="Stop capture after this many seconds. Use 0 for no timeout. Default: 60")
    parser.add_argument("--output", default="capture_selected_device.pcap", help="PCAP output path. Default: capture_selected_device.pcap")
    parser.add_argument(
        "--protocols",
        default="all",
        help=f"Comma-separated protocol presets to capture. Available: {available_protocols()}. Default: all",
    )
    parser.add_argument(
        "--bpf",
        help="Advanced custom BPF filter combined with selected host, e.g. 'tcp port 80 or udp port 53'. Overrides --protocols.",
    )
    parser.add_argument("--show-details", action="store_true", help="Print Scapy's packet summary in addition to the compact protocol summary.")
    parser.add_argument("--save-devices", action="store_true", help="Save discovered device information to discovered_devices.json/csv.")
    parser.add_argument("--list-only", action="store_true", help="Scan and list devices, then exit without capturing packets.")
    parser.add_argument("--arp-cache-only", action="store_true", help="Only show the system ARP table; skip active ARP scan and packet capture.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.arp_cache_only:
        devices = read_arp_cache()
        print_devices(devices)
        if args.save_devices:
            save_devices(devices)
        return 0

    require_scapy()

    if not is_adminish():
        print("[!] Warning: ARP scanning and packet capture often require root/administrator privileges.")

    subnet = args.subnet or infer_default_subnet()
    try:
        ipaddress.ip_network(subnet, strict=False)
    except ValueError as exc:
        raise SystemExit(f"Invalid --subnet value: {subnet}") from exc

    try:
        if args.iface:
            conf.iface = args.iface
        actual_iface = args.iface or conf.iface
        print(f"[*] Interface: {actual_iface}")
        try:
            print(f"[*] Local IP : {get_if_addr(actual_iface)}")
            print(f"[*] Local MAC: {get_if_hwaddr(actual_iface)}")
        except Exception:
            pass

        while True:
            scanned = active_arp_scan(subnet, timeout=args.scan_timeout, iface=args.iface)
            cached = read_arp_cache()
            devices = merge_devices(scanned, cached)
            print_devices(devices)

            if args.save_devices:
                save_devices(devices)

            if args.list_only:
                return 0

            try:
                chosen = choose_device(devices, args.target)
                break
            except SystemExit as exc:
                if str(exc) == "RESCAN_REQUESTED" and not args.target:
                    print("\n[*] Rescanning...\n")
                    continue
                raise

        print(f"\n[+] Selected: {chosen.ip}  {chosen.mac}  {chosen.hostname}  {chosen.vendor}")

        timeout = None if args.timeout == 0 else args.timeout
        protocols = [p.strip().lower() for p in args.protocols.split(",") if p.strip()]
        capture_for_device(
            chosen.ip,
            args.output,
            args.iface,
            args.count,
            timeout,
            protocols,
            custom_bpf=args.bpf,
            show_details=args.show_details,
        )
        return 0
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
