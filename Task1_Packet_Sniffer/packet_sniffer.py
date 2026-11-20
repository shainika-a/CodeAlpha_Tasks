"""Internship Task 1: passive packet capture and analysis using Scapy."""
import argparse
from collections import Counter
from datetime import datetime

try:
    from scapy.all import ARP, IP, IPv6, TCP, UDP, ICMP, Raw, conf, sniff
except ImportError:
    raise SystemExit("Install Scapy first: py -m pip install scapy")


def describe(packet, number, preview_bytes=64):
    """Return readable fields without printing untrusted terminal controls."""
    protocol = "OTHER"
    source = destination = "N/A"
    details = ""
    if IP in packet:
        layer = packet[IP]
        source, destination = layer.src, layer.dst
        protocol = f"IP protocol {layer.proto}"
        details = f"IPv4 | TTL: {layer.ttl} | Header: {layer.ihl * 4} bytes"
    elif IPv6 in packet:
        layer = packet[IPv6]
        source, destination = layer.src, layer.dst
        protocol = "IPv6"
        details = f"IPv6 | Hop limit: {layer.hlim}"
    elif ARP in packet:
        layer = packet[ARP]
        source, destination = layer.psrc, layer.pdst
        protocol = "ARP"
        details = f"ARP operation: {layer.op} | Sender MAC: {layer.hwsrc}"
    if TCP in packet:
        layer = packet[TCP]
        protocol = "TCP"
        details += f" | Ports: {layer.sport} to {layer.dport} | Flags: {layer.flags}"
    elif UDP in packet:
        layer = packet[UDP]
        protocol = "UDP"
        details += f" | Ports: {layer.sport} to {layer.dport}"
    elif ICMP in packet:
        layer = packet[ICMP]
        protocol = "ICMP"
        details += f" | Type: {layer.type} | Code: {layer.code}"
    elif IPv6 in packet and packet.haslayer("ICMPv6Unknown"):
        protocol = "ICMPv6"
    # Prefer transport payload, including structured DNS, over only Raw data.
    payload = b""
    if TCP in packet:
        payload = bytes(packet[TCP].payload)
    elif UDP in packet:
        payload = bytes(packet[UDP].payload)
    elif Raw in packet:
        payload = bytes(packet[Raw].load)
    preview = payload[:preview_bytes]
    timestamp = datetime.fromtimestamp(float(packet.time)).astimezone().isoformat(timespec="milliseconds")
    text = [f"\nPacket {number} | {timestamp}",
            f"Source: {source} | Destination: {destination}",
            f"Protocol: {protocol} | Captured length: {len(packet)} bytes",
            f"Structure: {packet.summary()!r}", details,
            f"Payload: {len(payload)} bytes; showing up to {preview_bytes}",
            f"Text: {preview!r}", f"Hex: {preview.hex(' ') or '(empty)'}"]
    return protocol, "\n".join(text)


def nonnegative(value):
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("Must be zero or greater")
    return number


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="List capture interfaces")
    parser.add_argument("--iface", help="Interface name or numeric index from --list")
    parser.add_argument("--count", type=nonnegative, default=20, help="Packet limit; 0 is unlimited")
    parser.add_argument("--timeout", type=nonnegative, default=60, help="Seconds; 0 is unlimited")
    parser.add_argument("--filter", help="Optional BPF capture filter, e.g. tcp or icmp")
    parser.add_argument("--read", metavar="PCAP", help="Analyze a saved capture instead of live traffic")
    parser.add_argument("--details", action="store_true", help="Display all decoded header fields")
    args = parser.parse_args()
    if args.list:
        conf.ifaces.show()
        return
    interface = args.iface
    if interface and interface.isdecimal():
        try:
            interface = conf.ifaces.dev_from_index(int(interface))
        except ValueError as exc:
            parser.error(str(exc))
    counts = Counter()

    def display(packet):
        protocol, output = describe(packet, sum(counts.values()) + 1)
        counts[protocol] += 1
        print(output, flush=True)
        if args.details:
            # repr prevents packet content from emitting terminal control codes.
            print(repr(packet.show(dump=True)))

    print("Analyzing saved packets..." if args.read else
          "Capturing packets for up to 60 seconds by default. Press Ctrl+C to stop.")
    options = dict(prn=display, store=False, count=args.count)
    if args.read:
        options["offline"] = args.read
    else:
        options.update(iface=interface, promisc=False, timeout=args.timeout or None)
    if args.filter:
        options["filter"] = args.filter
    try:
        sniff(**options)
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, RuntimeError) as exc:
        raise SystemExit(f"Capture failed: {exc}\nCheck interface, permissions, filter, and Npcap on Windows.")
    finally:
        print(f"\nTotal packets: {sum(counts.values())}")
        for protocol, count in counts.most_common():
            print(f"  {protocol}: {count}")


if __name__ == "__main__":
    main()
