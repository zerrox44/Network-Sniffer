import argparse
import sys
import time
from collections import Counter

try:
    from scapy.all import (
        ARP, DNS, DNSRR, ICMP, IP, IPv6,
        Raw, TCP, UDP, conf,
        get_if_list, sniff, wrpcap,
    )
except ImportError:
    print("do pip install scapy")
    sys.exit(1)

conf.use_pcap = True


_ARP_OPS = {1: "who-has", 2: "is-at"}


def list_interfaces():
    print("Interfaces:")
    for i, iface in enumerate(get_if_list(), 1):
        print(f"  {i}. {iface}")


def build_filter(user_filter, only_ip, protocols):
    parts = []

    if only_ip:
        parts.append(f"host {only_ip}")

    if protocols:
        names = [p.strip().lower() for p in protocols.split(",") if p.strip()]
        ok = {"tcp", "udp", "icmp", "arp", "ip", "ipv6"}
        bad = [n for n in names if n not in ok]
        if bad:
            raise ValueError(f"Unknown protocols: {', '.join(bad)}")
        parts.append(" or ".join(names))

    if user_filter:
        parts.append(user_filter)

    if not parts:
        return None
    return " and ".join(f"({p})" for p in parts)


def http_summary(packet):
    if not (packet.haslayer(Raw) and packet.haslayer(TCP)):
        return None

    try:
        text = bytes(packet[Raw].load).decode("utf-8", errors="ignore")
    except Exception:
        return None

    first = text.splitlines()[0] if text else ""
    for m in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "HTTP/"):
        if first.startswith(m):
            return first
    return None


def dns_summary(packet):
    if not packet.haslayer(DNS):
        return None

    d = packet[DNS]
    if d.qr == 0 and d.qd:
        name = d.qd.qname.decode("utf-8", errors="ignore")
        return f"DNS query {name} type={d.qd.qtype}"

    answers = []
    a = d.an
    while isinstance(a, DNSRR) and len(answers) < 4:
        n = getattr(a, "rrname", b"").decode("utf-8", errors="ignore")
        rd = a.rdata
        if isinstance(rd, bytes):
            rd = rd.decode("utf-8", errors="ignore")
        answers.append(f"{n} -> {rd}")
        a = a.payload

    return f"DNS response answers={len(answers)}"


def arp_summary(packet):
    if not packet.haslayer(ARP):
        return None
    a = packet[ARP]
    op = _ARP_OPS.get(a.op, str(a.op))
    return f"ARP {op} {a.psrc} -> {a.pdst}"


def icmp_summary(packet):
    if not packet.haslayer(ICMP):
        return None
    ic = packet[ICMP]
    return f"ICMP type={ic.type} code={ic.code}"


def packet_info(packet):
    src = dst = "unknown"
    proto = "OTHER"
    ports = ""
    details = []

    if packet.haslayer(IP):
        l = packet[IP]
        src, dst = l.src, l.dst
        proto = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(l.proto, "IP")
    elif packet.haslayer(IPv6):
        l = packet[IPv6]
        src, dst = l.src, l.dst
        proto = "IPv6"
    elif packet.haslayer(ARP):
        l = packet[ARP]
        src, dst = l.psrc, l.pdst
        proto = "ARP"

    if packet.haslayer(TCP):
        t = packet[TCP]
        ports = f"{t.sport}->{t.dport}"
    elif packet.haslayer(UDP):
        u = packet[UDP]
        ports = f"{u.sport}->{u.dport}"

    http_t  = http_summary(packet)
    dns_t   = dns_summary(packet)
    arp_t   = arp_summary(packet)
    icmp_t  = icmp_summary(packet)

    if http_t:
        details.append(http_t)
        proto = "HTTP"
    if dns_t:
        details.append(dns_t)
        proto = "DNS"
    if arp_t:
        details.append(arp_t)
    if icmp_t:
        details.append(icmp_t)

    if packet.haslayer(Raw) and not (http_t or dns_t):
        raw = bytes(packet[Raw].load)
        if raw:
            preview = raw[:80].decode("utf-8", errors="ignore").replace("\n", " ").replace("\r", " ")
            details.append(preview)

    line = f"{src} -> {dst} | {proto}"
    if ports:
        line += f" | ports={ports}"
    if details:
        line += " | " + " | ".join(details)

    arp_op   = packet[ARP].op if packet.haslayer(ARP) else None
    icmp_key = (packet[ICMP].type, packet[ICMP].code) if packet.haslayer(ICMP) else None

    return line, proto, src, dst, ports, arp_op, icmp_key


def print_live_stats(pcounts, ipcounts, portcounts, arpcounts, icmpcounts,
                     dns_n, http_n, top_n):
    print("\n=== LIVE STATS ===")
    if pcounts:
        print("Protocols:")
        for p, c in pcounts.most_common(6):
            print(f"  {p}: {c}")
    if arpcounts:
        print("ARP:")
        for op, c in arpcounts.most_common():
            print(f"  {_ARP_OPS.get(op, op)}: {c}")
    if icmpcounts:
        print("ICMP:")
        for (t, code), c in icmpcounts.most_common(6):
            print(f"  type={t} code={code}: {c}")
    if dns_n:
        print(f"DNS: {dns_n}")
    if http_n:
        print(f"HTTP: {http_n}")
    if ipcounts and top_n > 0:
        print("Top IPs:")
        for ip, c in ipcounts.most_common(top_n):
            print(f"  {ip}: {c}")
    if portcounts and top_n > 0:
        print("Top ports:")
        for port, c in portcounts.most_common(top_n):
            print(f"  {port}: {c}")
    print("==================\n")


def capture_packets(interface, packet_filter, count, timeout, output,
                    only_ip, protocols, show_summary, show_details,
                    quiet, top_talkers, live_stats, stats_interval):

    full_filter = build_filter(packet_filter, only_ip, protocols)

    print(f"Capturing on: {interface}")
    if full_filter:
        print(f"Filter: {full_filter}")

    if count > 0:
        print(f"Stopping at {count} packets")
    elif timeout > 0:
        print(f"Stopping after {timeout}s")
    else:
        print("Ctrl+C to stop")

    if output:
        print(f"Saving to: {output}")

    pcounts   = Counter()
    ipcounts  = Counter()
    portcounts = Counter()
    arpcounts = Counter()
    icmpcounts = Counter()
    dns_n = 0
    http_n = 0
    captured = []
    next_stats = time.time() + stats_interval if live_stats else 0

    def handle(packet):
        nonlocal next_stats, dns_n, http_n

        line, proto, src, dst, ports, arp_op, icmp_key = packet_info(packet)

        pcounts[proto] += 1
        if src: ipcounts[src] += 1
        if dst: ipcounts[dst] += 1
        if ports: portcounts[ports] += 1
        if arp_op is not None: arpcounts[arp_op] += 1
        if icmp_key is not None: icmpcounts[icmp_key] += 1
        if packet.haslayer(DNS): dns_n += 1
        if "HTTP" in proto: http_n += 1

        if not quiet:
            print(line if show_details else packet.summary())

        if live_stats and time.time() >= next_stats:
            print_live_stats(pcounts, ipcounts, portcounts, arpcounts,
                             icmpcounts, dns_n, http_n, top_talkers)
            next_stats = time.time() + stats_interval

        captured.append(packet)

    try:
        sniff(
            iface=interface,
            filter=full_filter,
            prn=handle,
            count=count or 0,
            timeout=timeout or None,
            store=False,
            promisc=True,
        )
    except KeyboardInterrupt:
        print("\nStopped.")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

    if output:
        wrpcap(output, captured)
        print(f"Saved {len(captured)} packets -> {output}")

    if show_summary:
        print(f"\nTotal: {len(captured)}")
        for p, c in pcounts.most_common():
            print(f"  {p}: {c}")
        for op, c in arpcounts.most_common():
            print(f"  ARP {_ARP_OPS.get(op, op)}: {c}")
        for (t, code), c in icmpcounts.most_common():
            print(f"  ICMP type={t} code={code}: {c}")
        if dns_n: print(f"  DNS: {dns_n}")
        if http_n: print(f"  HTTP: {http_n}")
        if top_talkers > 0:
            for ip, c in ipcounts.most_common(top_talkers):
                print(f"  {ip}: {c}")
            for port, c in portcounts.most_common(top_talkers):
                print(f"  {port}: {c}")


def cli_menu():
    print("\nICL Sniffer")
    print("1) List interfaces")
    print("2) Capture")
    print("3) Capture w/ filters")
    print("4) Exit")

    while True:
        c = input("Choice [1-4]: ").strip()

        if c == "1":
            list_interfaces()

        elif c == "2":
            iface = input("Interface: ").strip()
            n = int(input("Count (0=unlimited): ").strip() or 0)
            capture_packets(iface, "", n, 0, None, None, None,
                            True, False, False, 5, False, 5)

        elif c == "3":
            iface    = input("Interface: ").strip()
            bpf      = input("BPF filter: ").strip()
            only_ip  = input("Only IP (blank=skip): ").strip() or None
            protos   = input("Protocols (tcp,udp,...): ").strip() or None
            n        = int(input("Count (0=unlimited): ").strip() or 0)
            t        = int(input("Timeout (s): ").strip() or 0)
            detail   = input("Details? [y/N]: ").strip().lower() == "y"
            live     = input("Live stats? [y/N]: ").strip().lower() == "y"
            capture_packets(iface, bpf, n, t, None, only_ip, protos,
                            True, detail, False, 5, live, 5)

        elif c == "4":
            print("bye")
            break
        else:
            print("?")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="net sniffer")
    ap.add_argument("--iface")
    ap.add_argument("--filter", default="")
    ap.add_argument("--count", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=0)
    ap.add_argument("--output")
    ap.add_argument("--only-ip")
    ap.add_argument("--protocols")
    ap.add_argument("--detail", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--top-talkers", type=int, default=5)
    ap.add_argument("--no-summary", action="store_true")
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--stats-interval", type=int, default=5)
    ap.add_argument("--menu", action="store_true")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    if args.menu:
        cli_menu()
        sys.exit(0)

    if args.list:
        list_interfaces()
        sys.exit(0)

    if not args.iface:
        print("need --iface or use --menu / --list")
        ap.print_help()
        sys.exit(1)

    try:
        capture_packets(
            args.iface, args.filter, args.count, args.timeout,
            args.output, args.only_ip, args.protocols,
            not args.no_summary, args.detail, args.quiet,
            args.top_talkers, args.live, args.stats_interval,
        )
    except ValueError as e:
        print(f"bad arg: {e}")
        sys.exit(1)
