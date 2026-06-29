# Network Scanner & Safe Packet Capture Tool

A Python network discovery and packet capture helper built with Scapy. It finds visible devices on a local IPv4 network with ARP, lets you select a device, then captures packets for that selected host that are visible to your own machine.

This project is for educational, administrative, and authorized network monitoring use only.

## Features

- ARP-based local network scanning
- System ARP cache parsing on Windows, Linux, and macOS
- Device list merging from active scans and cached entries
- Hostname lookup and basic offline MAC vendor guessing
- Interactive device selection or automatic target selection
- Packet capture scoped to a selected host
- Protocol capture presets such as DNS, HTTP, HTTPS, DHCP, ICMP, SSH, SMB, and RDP
- Optional custom BPF filters for advanced capture control
- Compact live packet summaries without dumping full payload contents
- Optional detailed Scapy packet summaries
- PCAP export for Wireshark or other analysis tools
- Device export to JSON and CSV

## Requirements

- Python 3.9 or newer
- Scapy
- Administrator/root privileges for ARP scanning and packet capture
- Npcap on Windows if packet capture is needed

Install the Python dependency:

```bash
python -m pip install scapy
```

## Quick Start

Scan a subnet, choose a discovered device, and capture visible packets:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24
```

On Windows, run PowerShell or Command Prompt as Administrator:

```powershell
python network_scanner_capture.py --subnet 192.168.1.0/24
```

If you omit `--subnet`, the script tries to infer a likely `/24` from Scapy's default interface.

## Examples

Capture 100 packets for the selected device:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --count 100
```

Capture for 60 seconds and write to a custom PCAP file:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --timeout 60 --output capture.pcap
```

Capture only DNS and web traffic for a selected device:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --protocols dns,web
```

Skip interactive selection by targeting an IP address:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --target 192.168.1.25
```

Use an advanced BPF filter with the selected host:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --bpf "tcp port 80 or udp port 53"
```

List discovered devices without capturing packets:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --list-only
```

Read only the system ARP cache:

```bash
python3 network_scanner_capture.py --arp-cache-only
```

Save discovered devices to JSON and CSV:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --save-devices --list-only
```

## Command-Line Options

| Option | Description |
| --- | --- |
| `--subnet` | IPv4 subnet to ARP scan, such as `192.168.1.0/24`. Defaults to an inferred `/24`. |
| `--iface` | Network interface to use. Defaults to Scapy's default interface. |
| `--scan-timeout` | ARP scan timeout in seconds. Default: `3`. |
| `--target` | Target IP address or displayed list index to skip interactive selection. |
| `--count` | Stop after this many packets. Use `0` for no count limit. Default: `50`. |
| `--timeout` | Stop capture after this many seconds. Use `0` for no timeout. Default: `60`. |
| `--output` | PCAP output path. Default: `capture_selected_device.pcap`. |
| `--protocols` | Comma-separated protocol presets to capture. Default: `all`. |
| `--bpf` | Custom BPF filter combined with the selected host. Overrides `--protocols`. |
| `--show-details` | Print Scapy's packet summary in addition to the compact summary. |
| `--save-devices` | Save discovered devices to `discovered_devices.json` and `discovered_devices.csv`. |
| `--list-only` | Scan and list devices, then exit without packet capture. |
| `--arp-cache-only` | Show the system ARP table only; skip active ARP scanning and packet capture. |

## Protocol Presets

Available `--protocols` values:

```text
all, arp, dhcp, dns, ftp, http, https, icmp, imap, llmnr, mdns, netbios, ntp, ping, pop3, rdp, smb, smtp, ssh, web
```

You can combine presets with commas, for example:

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24 --protocols dns,ssh,icmp
```

## Output Files

Depending on the options used, the tool can create:

- `capture_selected_device.pcap`
- A custom `.pcap` file from `--output`
- `discovered_devices.json`
- `discovered_devices.csv`

Open PCAP files in Wireshark or another packet analysis tool.

## Important Limitations

- You only capture traffic visible to the machine running the script.
- On normal switched networks, you usually see your own traffic plus broadcast or multicast traffic.
- The tool does not perform ARP spoofing, ARP poisoning, man-in-the-middle interception, credential collection, decryption, or bypasses.
- Some systems require administrator/root privileges, Npcap, or libpcap for capture filters to work.
- Vendor detection uses a small offline OUI list and may be incomplete.

## Legal Notice

Use this software only on networks and devices you own or have explicit permission to monitor. Unauthorized scanning or packet capture may violate laws, policies, or terms of service.

## Author

Blacker S

GitHub: https://github.com/shackablacka

## License

This project is released under the MIT License.
