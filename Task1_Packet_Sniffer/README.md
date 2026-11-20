# Task 1: Network Packet Sniffer

## Aim
Capture network packets using Python and Scapy and understand packet layers, source/destination addresses, protocols, ports and payload bytes. Capture only on your own device or a network where you have permission.

## Windows setup
1. Install Python 3 from https://www.python.org/downloads/ if needed.
2. Install Npcap from https://npcap.com/#download. Scapy's current documentation recommends leaving WinPcap compatibility mode off.
3. Open PowerShell in the extracted project folder and run:

```powershell
py -m pip install scapy
py packet_sniffer.py --list
```

Use the Wi-Fi or Ethernet interface index shown in the list (replace 12 below):

```powershell
py packet_sniffer.py --iface 12
```

If capture permissions are denied, reopen PowerShell as Administrator and navigate back to this folder. Capture ends after 20 packets or 60 seconds by default. Ctrl+C also stops it. No packets are saved to disk by default.

## Demonstration
In one terminal:

```powershell
py packet_sniffer.py --iface 19 --filter icmp --count 4 --details
```

In another terminal:

```powershell
ping -4 1.1.1.1
```

If your network blocks ping, use an unfiltered capture and browse a website instead. For TCP-only traffic use `--filter tcp`. For unlimited capture use `--count 0 --timeout 0`. Interface visibility depends on the adapter and network; this does not capture every device's traffic.

Analyze an existing PCAP without live capture:

```powershell
py packet_sniffer.py --read capture.pcap --details
```

## How it works
1. `sniff()` receives packets from the selected interface.
2. The `display()` callback passes each packet to `describe()`.
3. Layer checks identify IPv4, IPv6, ARP, TCP, UDP and IPv4 ICMP.
4. The program prints addresses, length, packet structure, ports where present, and a preview of up to 64 payload bytes in text and hexadecimal.
5. Counters summarize packets by protocol. `store=False` avoids accumulating captured packets in memory.

## Understanding the fields
| Field / protocol | Meaning |
| --- | --- |
| Source IP | Address the IP packet says it came from |
| Destination IP | Address the IP packet is sent to |
| TCP | Connection-oriented transport with ordering and retransmission |
| UDP | Datagram transport without TCP's delivery guarantees |
| ICMP | Network control and diagnostic messages, such as ping |
| ARP | Resolves IPv4 addresses to local link MAC addresses |
| Port | Identifies a transport endpoint used by an application |
| Payload | Bytes carried by the transport or raw data layer |
| TTL / hop limit | Limits how many routed hops a packet can take |

Typical flow: application data is carried by TCP or UDP, then IP, then a link-layer frame. The receiver interprets those layers in reverse. ARP operates directly on the local link. The Structure line shows Scapy's actual decoded layers. TCP headers can reveal connection flags such as S (SYN) and A (ACK).

HTTPS payload is encrypted: IP addresses and ports remain visible, but you normally cannot read website text or passwords. Some packets contain no application payload. A packet is not necessarily a complete message: this program does not reassemble TCP streams or decrypt TLS. IPv6 addresses are displayed; detailed ICMP decoding in this beginner implementation focuses on IPv4 ICMP.

## Explanation
I implemented a passive Python packet sniffer using Scapy. It captures packets from a selected network interface and inspects their layers. It displays source and destination addresses, protocol, ports, packet length and bounded payload previews. I used ping to observe request and reply packets and learned how headers carry routing and transport information. Encrypted application content remains unreadable.

## References
- https://scapy.readthedocs.io/en/stable/installation.html
- https://scapy.readthedocs.io/en/stable/usage.html
- https://npcap.com/
