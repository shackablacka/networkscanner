# Network Scanner & Safe Packet Capture Tool

A Python-based network discovery and packet capture utility built with Scapy. This tool performs local network device discovery using ARP requests and allows users to capture visible traffic associated with selected devices.

> ⚠️ This tool is intended for educational, administrative, and authorized network monitoring purposes only.

---

## Features

- Active ARP network scanning
- Local ARP cache analysis
- Device discovery and enumeration
- Hostname resolution
- Basic vendor identification from MAC addresses
- Interactive device selection
- Packet capture for selected hosts
- PCAP export for analysis in Wireshark
- Device information export to CSV and JSON
- Cross-platform ARP cache support (Windows, Linux, macOS)

---

## Requirements

- Python 3.9+
- Scapy

Install dependencies:

```bash
pip install scapy
```

---

## Running the Tool

### Scan a subnet

```bash
sudo python3 network_scanner_capture.py --subnet 192.168.1.0/24
```

### Capture 100 packets

```bash
sudo python3 network_scanner_capture.py \
    --subnet 192.168.1.0/24 \
    --count 100
```

### Save discovered devices

```bash
sudo python3 network_scanner_capture.py \
    --subnet 192.168.1.0/24 \
    --save-devices
```

### List devices only

```bash
sudo python3 network_scanner_capture.py \
    --subnet 192.168.1.0/24 \
    --list-only
```

### Read only the ARP cache

```bash
python3 network_scanner_capture.py --arp-cache-only
```

---

## Example Output

```text
Discovered devices connected/visible on this Wi-Fi/LAN

#   IP               MAC                Hostname
----------------------------------------------------
1   192.168.1.1      aa:bb:cc:dd:ee:ff  router
2   192.168.1.20     11:22:33:44:55:66  laptop
3   192.168.1.35     77:88:99:aa:bb:cc  printer
```

---

## Command-Line Options

| Option | Description |
|--------|-------------|
| `--subnet` | Target subnet to scan |
| `--iface` | Network interface |
| `--scan-timeout` | ARP scan timeout |
| `--target` | Select device automatically |
| `--count` | Number of packets to capture |
| `--timeout` | Capture timeout |
| `--output` | PCAP output filename |
| `--save-devices` | Export device list |
| `--list-only` | Only display devices |
| `--arp-cache-only` | Read system ARP cache only |

---

## Generated Files

The tool can generate:

- `capture_selected_device.pcap`
- `discovered_devices.json`
- `discovered_devices.csv`

These files can be analyzed using tools such as Wireshark.

---

## Project Structure

```text
network-scanner-capture/
│
├── network_scanner_capture.py
├── requirements.txt
├── README.md
└── .gitignore
```

---

## Technologies Used

- Python 3
- Scapy
- ARP Protocol
- Packet Capture (PCAP)
- JSON
- CSV

---

## Educational Purpose

This project demonstrates:

- Network discovery techniques
- ARP-based host identification
- Packet capture fundamentals
- Python networking programming
- Traffic analysis workflows

---

## Limitations

- Requires administrator/root privileges for scanning and capture.
- On switched networks, only traffic visible to the host can be captured.
- Does not perform traffic interception, spoofing, or credential collection.
- Vendor detection uses a small offline OUI database.

---

## Legal Notice

Use this software only on networks and devices you own or have explicit authorization to monitor. Unauthorized monitoring or packet capture may violate laws, regulations, or organizational policies.

---

## Author

**Blacker S**

GitHub: https://github.com/shackablacka

---

## License

This project is released under the MIT License.
