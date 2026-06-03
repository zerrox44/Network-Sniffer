import argparse
import sys
import time
from collections import Counter
from typing import Optional

try:
    from scapy.all import (
        ARP,
        DNS,
        DNSRR,
        ICMP,
        IP,
        IPv6,
        Raw,
        TCP,
        UDP,
        conf,
        get_if_list,
        sniff,
        wrpcap,
    )
except ImportError:
    print("Error: scapy is not installed. Run 'python -m pip install scapy'.")
    sys.exit(1)

conf.use_pcap = True


def list_interfaces() -> None:
    print("Available network interfaces:")
    for idx, iface in enumerate(get_if_list(), 1):
        print(f"{idx}. {iface}")


def build_filter(user_filter: str, only_ip: Optional[str], protocols: Optional[str]) -> Optional[str]:
    parts = []
    if only_ip:
        parts.append(f"host {only_ip}")

    if protocols:
        names = [name.strip().lower() for name in protocols.split(",") if name.strip()]
        allowed = {"tcp", "udp", "icmp", "arp", "ip", "ipv6"}
        invalid = [name for name in names if name not in allowed]
        if invalid:
            raise ValueError(f"Unsupported protocols: {', '.join(invalid)}")
        parts.append(" or ".join(names))

    if user_filter:
        parts.append(user_filter)

    return " and ".join(f"({part})" for part in parts) if parts else None


def http_summary(packet) -> Optional[str]:
    if not packet.haslayer(Raw) or not packet.haslayer(TCP):
        return None

    payload = bytes(packet[Raw].load)
    if not payload:
        return None

    text = payload.decode("utf-8", errors="ignore")
    first_line = text.splitlines()[0] if text else ""
    methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "HTTP/")
    for method in methods:
        if first_line.startswith(method):
            return first_line
    return None


def dns_summary(packet) -> Optional[str]:
    if not packet.haslayer(DNS):
        return None

    dns = packet[DNS]
    if dns.qr == 0 and dns.qd:
        name = dns.qd.qname.decode("utf-8", errors="ignore")
        return f"DNS query {name} type={dns.qd.qtype}"

    answers = []
    answer = dns.an
    while isinstance(answer, DNSRR) and len(answers) < 4:
        name = getattr(answer, "rrname", b"").decode("utf-8", errors="ignore")
        rdata = answer.rdata
        if isinstance(rdata, bytes):
            rdata = rdata.decode("utf-8", errors="ignore")
        answers.append(f"{name} -> {rdata}")
        answer = answer.payload

    return f"DNS response answers={len(answers)}"


def arp_summary(packet) -> Optional[str]:
    if not packet.haslayer(ARP):
        return None

    arp = packet[ARP]
    op = {1: "who-has", 2: "is-at"}.get(arp.op, str(arp.op))
    return f"ARP {op} {arp.psrc} -> {arp.pdst}"


def icmp_summary(packet) -> Optional[str]:
    if not packet.haslayer(ICMP):
        return None

    icmp = packet[ICMP]
    return f"ICMP type={icmp.type} code={icmp.code}"


def packet_info(packet):
    src = "unknown"
    dst = "unknown"
    proto = "OTHER"
    ports = ""
    details = []

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(ip_layer.proto, "IP")
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        src = ip_layer.src
        dst = ip_layer.dst
        proto = "IPv6"
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        src = arp_layer.psrc
        dst = arp_layer.pdst
        proto = "ARP"

    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        ports = f"{tcp_layer.sport}->{tcp_layer.dport}"
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        ports = f"{udp_layer.sport}->{udp_layer.dport}"

    http_text = http_summary(packet)
    dns_text = dns_summary(packet)
    arp_text = arp_summary(packet)
    icmp_text = icmp_summary(packet)

    if http_text:
        details.append(http_text)
        proto = "HTTP"
    if dns_text:
        details.append(dns_text)
        proto = "DNS"
    if arp_text:
        details.append(arp_text)
    if icmp_text:
        details.append(icmp_text)

    if packet.haslayer(Raw) and not (http_text or dns_text):
        raw_payload = bytes(packet[Raw].load)
        if raw_payload:
            preview = raw_payload[:80].decode("utf-8", errors="ignore").replace("\n", " ").replace("\r", " ")
            details.append(preview)

    summary = f"{src} -> {dst} | {proto}"
    if ports:
        summary += f" | ports={ports}"
    if details:
        summary += " | " + " | ".join(details)

    arp_op = packet[ARP].op if packet.haslayer(ARP) else None
    icmp_key = (packet[ICMP].type, packet[ICMP].code) if packet.haslayer(ICMP) else None

    return summary, proto, src, dst, ports, arp_op, icmp_key


def print_live_stats(
    protocol_counts: Counter,
    ip_counts: Counter,
    port_counts: Counter,
    arp_counts: Counter,
    icmp_counts: Counter,
    dns_count: int,
    http_count: int,
    top_talkers: int,
) -> None:
    print("\n=== LIVE TRAFFIC STATS ===")
    if protocol_counts:
        print("Protocols:")
        for proto, count in protocol_counts.most_common(6):
            print(f"  {proto}: {count}")
    if arp_counts:
        print("ARP ops:")
        for op, count in arp_counts.most_common():
            name = {1: "who-has", 2: "is-at"}.get(op, str(op))
            print(f"  {name}: {count}")
    if icmp_counts:
        print("ICMP types:")
        for (icmp_type, code), count in icmp_counts.most_common(6):
            print(f"  type={icmp_type} code={code}: {count}")
    if dns_count:
        print(f"DNS packets: {dns_count}")
    if http_count:
        print(f"HTTP packets: {http_count}")
    if ip_counts and top_talkers > 0:
        print("Top IP talkers:")
        for ip, count in ip_counts.most_common(top_talkers):
            print(f"  {ip}: {count}")
    if port_counts and top_talkers > 0:
        print("Top port pairs:")
        for port, count in port_counts.most_common(top_talkers):
            print(f"  {port}: {count}")
    print("==========================\n")


def capture_packets(
    interface: str,
    packet_filter: str,
    count: int,
    timeout: int,
    output: Optional[str],
    only_ip: Optional[str],
    protocols: Optional[str],
    show_summary: bool,
    show_details: bool,
    quiet: bool,
    top_talkers: int,
    live_stats: bool,
    stats_interval: int,
) -> None:
    full_filter = build_filter(packet_filter, only_ip, protocols)
    print(f"Starting capture on interface: {interface}")
    if full_filter:
        print(f"Using filter: {full_filter}")
    if count > 0:
        print(f"Capturing up to {count} packets")
    elif timeout > 0:
        print(f"Capturing for up to {timeout} seconds")
    else:
        print("Capturing until interrupted (Ctrl+C)")
    if output:
        print(f"Output file: {output}")
    if live_stats:
        print(f"Live stats every {stats_interval} seconds")

    protocol_counts: Counter[str] = Counter()
    ip_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    arp_counts: Counter[int] = Counter()
    icmp_counts: Counter[tuple[int, int]] = Counter()
    dns_count = 0
    http_count = 0
    packets = []
    next_stats = time.time() + stats_interval if live_stats else 0

    def on_packet(packet) -> None:
        nonlocal next_stats, dns_count, http_count
        summary, proto, src, dst, ports, arp_op, icmp_key = packet_info(packet)
        protocol_counts[proto] += 1
        if src:
            ip_counts[src] += 1
        if dst:
            ip_counts[dst] += 1
        if ports:
            port_counts[ports] += 1
        if arp_op is not None:
            arp_counts[arp_op] += 1
        if icmp_key is not None:
            icmp_counts[icmp_key] += 1
        if packet.haslayer(DNS):
            dns_count += 1
        if "HTTP" in proto:
            http_count += 1

        if not quiet:
            print(summary if show_details else packet.summary())

        if live_stats and time.time() >= next_stats:
            print_live_stats(
                protocol_counts,
                ip_counts,
                port_counts,
                arp_counts,
                icmp_counts,
                dns_count,
                http_count,
                top_talkers,
            )
            next_stats = time.time() + stats_interval

        packets.append(packet)

    try:
        sniff(
            iface=interface,
            filter=full_filter,
            prn=on_packet,
            count=count if count else 0,
            timeout=timeout if timeout else None,
            store=False,
            promisc=True,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as exc:
        print(f"Capture failed: {exc}")
        sys.exit(1)

    if output:
        wrpcap(output, packets)
        print(f"Saved {len(packets)} packets to {output}")

    if show_summary:
        print("\nCapture summary:")
        print(f"Total packets: {len(packets)}")
        if protocol_counts:
            print("Protocol counts:")
            for proto, count in protocol_counts.most_common():
                print(f"  {proto}: {count}")
        if arp_counts:
            print("ARP breakdown:")
            for op, count in arp_counts.most_common():
                name = {1: "who-has", 2: "is-at"}.get(op, str(op))
                print(f"  {name}: {count}")
        if icmp_counts:
            print("ICMP breakdown:")
            for (icmp_type, code), count in icmp_counts.most_common():
                print(f"  type={icmp_type} code={code}: {count}")
        if dns_count:
            print(f"DNS packets: {dns_count}")
        if http_count:
            print(f"HTTP packets: {http_count}")
        if top_talkers > 0 and ip_counts:
            print(f"Top {top_talkers} IPs:")
            for ip, count in ip_counts.most_common(top_talkers):
                print(f"  {ip}: {count}")
        if top_talkers > 0 and port_counts:
            print(f"Top {top_talkers} ports:")
            for port, count in port_counts.most_common(top_talkers):
                print(f"  {port}: {count}")


def cli_menu() -> None:
    print("\nICL Sniffer")
    print("1) List interfaces")
    print("2) Capture packets")
    print("3) Capture with filters")
    print("4) Exit")

    while True:
        choice = input("Select [1-4]: ").strip()
        if choice == "1":
            list_interfaces()
        elif choice == "2":
            iface = input("Interface name: ").strip()
            count = int(input("Packet count (0 = unlimited): ").strip() or "0")
            capture_packets(
                interface=iface,
                packet_filter="",
                count=count,
                timeout=0,
                output=None,
                only_ip=None,
                protocols=None,
                show_summary=True,
                show_details=False,
                quiet=False,
                top_talkers=5,
                live_stats=False,
                stats_interval=5,
            )
        elif choice == "3":
            iface = input("Interface: ").strip()
            bpf = input("BPF filter: ").strip()
            only_ip = input("Only IP (blank for none): ").strip() or None
            protocols = input("Protocols (tcp,udp,icmp,arp,ip,ipv6): ").strip() or None
            count = int(input("Count (0 = unlimited): ").strip() or "0")
            timeout = int(input("Timeout seconds: ").strip() or "0")
            detail = input("Show details? [y/N]: ").strip().lower() == "y"
            live = input("Live stats? [y/N]: ").strip().lower() == "y"
            capture_packets(
                interface=iface,
                packet_filter=bpf,
                count=count,
                timeout=timeout,
                output=None,
                only_ip=only_ip,
                protocols=protocols,
                show_summary=True,
                show_details=detail,
                quiet=False,
                top_talkers=5,
                live_stats=live,
                stats_interval=5,
            )
        elif choice == "4":
            print("Bye.")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Windows network sniffer")
    parser.add_argument("--iface", help="Interface name to capture on")
    parser.add_argument("--filter", default="", help="BPF expression, e.g. 'tcp port 80'")
    parser.add_argument("--count", type=int, default=0, help="Packets to capture")
    parser.add_argument("--timeout", type=int, default=0, help="Capture time in seconds")
    parser.add_argument("--output", help="Save capture to pcap file")
    parser.add_argument("--only-ip", help="Filter packets to/from IP")
    parser.add_argument("--protocols", help="Comma-separated protocols: tcp,udp,icmp,arp,ip,ipv6")
    parser.add_argument("--detail", action="store_true", help="Show packet details")
    parser.add_argument("--quiet", action="store_true", help="Do not print packet lines")
    parser.add_argument("--top-talkers", type=int, default=5, help="Show top IPs/ports")
    parser.add_argument("--no-summary", action="store_true", help="Skip summary at the end")
    parser.add_argument("--live", action="store_true", help="Show live stats")
    parser.add_argument("--stats-interval", type=int, default=5, help="Live stats interval")
    parser.add_argument("--menu", action="store_true", help="Interactive mode")
    parser.add_argument("--list", action="store_true", help="List interfaces")

    args = parser.parse_args()

    if args.menu:
        cli_menu()
        sys.exit(0)

    if args.list:
        list_interfaces()
        sys.exit(0)

    if not args.iface:
        print("Specify --iface or use --menu or --list.")
        parser.print_help()
        sys.exit(1)

    try:
        capture_packets(
            interface=args.iface,
            packet_filter=args.filter,
            count=args.count,
            timeout=args.timeout,
            output=args.output,
            only_ip=args.only_ip,
            protocols=args.protocols,
            show_summary=not args.no_summary,
            show_details=args.detail,
            quiet=args.quiet,
            top_talkers=args.top_talkers,
            live_stats=args.live,
            stats_interval=args.stats_interval,
        )
    except ValueError as exc:
        print(f"Invalid argument: {exc}")
        sys.exit(1)
