# Windows Network Sniffer (Python)

A Windows network packet sniffer using `scapy` with enhanced IP/protocol analysis.

## Features

- list Windows network interfaces
- capture live packets from a selected interface
- print packet summaries and detailed IP/port info
- filter by BPF expression, source/destination IP, or protocol
- capture by packet count or timeout
- show protocol distribution and top talkers
- save captured packets to `.pcap`

## Prerequisites

1. `Python 3.10+`
2. `Npcap` installed on Windows
   - Download from https://nmap.org/npcap/
   - Install with `WinPcap compatible mode` enabled
3. Run PowerShell as Administrator

## Setup

Open PowerShell and run:

```powershell
python -m pip install --upgrade pip
python -m pip install scapy
```

## Commands

List available interfaces:

```powershell
python sniffer.py --list
```

Capture packets on an interface:

```powershell
python sniffer.py --iface "Ethernet" --count 20
```

Capture traffic for 30 seconds:

```powershell
python sniffer.py --iface "Ethernet" --timeout 30
```

Filter by IP address:

```powershell
python sniffer.py --iface "Ethernet" --only-ip 192.168.1.10
```

Filter by protocol:

```powershell
python sniffer.py --iface "Ethernet" --protocols tcp,udp
```

Use a BPF filter and save to pcap:

```powershell
python sniffer.py --iface "Ethernet" --filter "tcp port 80" --output capture.pcap
```

Show detailed packet info including DNS, HTTP, ARP, and ICMP:

```powershell
python sniffer.py --iface "Ethernet" --detail --count 50
```

Show live traffic stats while capturing:

```powershell
python sniffer.py --iface "Ethernet" --live --timeout 30
```

Start the interactive CLI menu:

```powershell
python sniffer.py --menu
```

Show top talkers in the summary:

```powershell
python sniffer.py --iface "Ethernet" --count 100 --top-talkers 10
```

Disable summary output:

```powershell
python sniffer.py --iface "Ethernet" --quiet --no-summary
```

## Notes

- Use interface names exactly as shown by `--list`.
- If capture fails, verify `Npcap` is installed and that PowerShell is running as Administrator.
- When using `--only-ip` or `--protocols`, the script builds a combined filter automatically.
