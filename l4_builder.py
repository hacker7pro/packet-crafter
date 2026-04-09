"""
l4_builder.py  —  Layer 4 Intelligence Engine
===============================================
Centralises ALL Layer-4 knowledge:
  • TCP / UDP / ICMP / IGMP / GRE / ESP / AH / SCTP / DCCP / OSPF
  • Port registry   (IANA + well-known + registered + dynamic ranges)
  • TCP flag semantics + handshake state machine
  • UDP service detection (by port pair)
  • ICMP extended type/code lookup (delegates to l3_builder table)
  • GRE inner-payload resolution
  • IPsec ESP/AH field-level detail
  • Auto-mapping: l3.next_layer → L4 handler class
  • process_l4() integration function called by main.py
"""

from __future__ import annotations
import struct
from typing import Any


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — PORT REGISTRY
#  Covers: IANA well-known (0-1023), registered (1024-49151),
#          plus common dynamic/ephemeral patterns
# ══════════════════════════════════════════════════════════════════════════════

PORT_REGISTRY: dict[int, dict] = {

    # ── Well-known (0–1023) ───────────────────────────────────────────────────
    7:    dict(name="Echo",          proto=["tcp","udp"], category="Diagnostic",
               status="Active",   usage="Echo back any received data"),
    19:   dict(name="CHARGEN",       proto=["tcp","udp"], category="Diagnostic",
               status="Deprecated",usage="Character generator (RFC 864)"),
    20:   dict(name="FTP-Data",      proto=["tcp"],       category="File Transfer",
               status="Active",   usage="FTP data channel"),
    21:   dict(name="FTP-Control",   proto=["tcp"],       category="File Transfer",
               status="Active",   usage="FTP command channel"),
    22:   dict(name="SSH",           proto=["tcp"],       category="Remote Access",
               status="Active",   usage="Secure Shell remote login + SFTP"),
    23:   dict(name="Telnet",        proto=["tcp"],       category="Remote Access",
               status="Deprecated",usage="Cleartext remote terminal (insecure)"),
    25:   dict(name="SMTP",          proto=["tcp"],       category="Email",
               status="Active",   usage="Mail transfer between servers"),
    37:   dict(name="Time",          proto=["tcp","udp"], category="Time",
               status="Deprecated",usage="Legacy time protocol (RFC 868)"),
    43:   dict(name="WHOIS",         proto=["tcp"],       category="Directory",
               status="Active",   usage="Domain/IP registration lookup"),
    53:   dict(name="DNS",           proto=["tcp","udp"], category="Name Resolution",
               status="Active",   usage="Domain name to IP resolution"),
    67:   dict(name="DHCP-Server",   proto=["udp"],       category="Address Assignment",
               status="Active",   usage="DHCP server listens on this port"),
    68:   dict(name="DHCP-Client",   proto=["udp"],       category="Address Assignment",
               status="Active",   usage="DHCP client listens on this port"),
    69:   dict(name="TFTP",          proto=["udp"],       category="File Transfer",
               status="Active",   usage="Trivial FTP — no auth, used by PXE boot"),
    70:   dict(name="Gopher",        proto=["tcp"],       category="Web",
               status="Deprecated",usage="Pre-web document retrieval"),
    79:   dict(name="Finger",        proto=["tcp"],       category="Directory",
               status="Deprecated",usage="User info lookup (privacy risk)"),
    80:   dict(name="HTTP",          proto=["tcp","udp"], category="Web",
               status="Active",   usage="Hypertext Transfer Protocol"),
    88:   dict(name="Kerberos",      proto=["tcp","udp"], category="Authentication",
               status="Active",   usage="MIT Kerberos authentication"),
    102:  dict(name="ISO-TSAP",      proto=["tcp"],       category="OSI",
               status="Active",   usage="ISO Transport Service Access Point"),
    110:  dict(name="POP3",          proto=["tcp"],       category="Email",
               status="Active",   usage="Post Office Protocol 3 — mail retrieval"),
    111:  dict(name="RPC",           proto=["tcp","udp"], category="RPC",
               status="Active",   usage="ONC RPC portmapper"),
    119:  dict(name="NNTP",          proto=["tcp"],       category="News",
               status="Active",   usage="Network News Transfer Protocol"),
    123:  dict(name="NTP",           proto=["udp"],       category="Time",
               status="Active",   usage="Network Time Protocol"),
    135:  dict(name="MS-RPC",        proto=["tcp","udp"], category="Windows",
               status="Active",   usage="Microsoft RPC endpoint mapper"),
    137:  dict(name="NetBIOS-NS",    proto=["udp"],       category="Windows",
               status="Active",   usage="NetBIOS Name Service"),
    138:  dict(name="NetBIOS-DGM",   proto=["udp"],       category="Windows",
               status="Active",   usage="NetBIOS Datagram Service"),
    139:  dict(name="NetBIOS-SSN",   proto=["tcp"],       category="Windows",
               status="Active",   usage="NetBIOS Session Service"),
    143:  dict(name="IMAP",          proto=["tcp"],       category="Email",
               status="Active",   usage="Internet Message Access Protocol"),
    161:  dict(name="SNMP",          proto=["udp"],       category="Management",
               status="Active",   usage="Get/Set device MIB variables"),
    162:  dict(name="SNMP-Trap",     proto=["udp"],       category="Management",
               status="Active",   usage="SNMP asynchronous trap notifications"),
    179:  dict(name="BGP",           proto=["tcp"],       category="Routing",
               status="Active",   usage="Border Gateway Protocol"),
    194:  dict(name="IRC",           proto=["tcp"],       category="Messaging",
               status="Active",   usage="Internet Relay Chat"),
    389:  dict(name="LDAP",          proto=["tcp","udp"], category="Directory",
               status="Active",   usage="Lightweight Directory Access Protocol"),
    443:  dict(name="HTTPS",         proto=["tcp","udp"], category="Web",
               status="Active",   usage="HTTP over TLS/SSL — HTTP/3 uses UDP/QUIC"),
    445:  dict(name="SMB",           proto=["tcp"],       category="File Sharing",
               status="Active",   usage="SMB/CIFS file sharing (Windows)"),
    465:  dict(name="SMTPS",         proto=["tcp"],       category="Email",
               status="Active",   usage="SMTP over TLS (implicit TLS)"),
    500:  dict(name="IKE/ISAKMP",    proto=["udp"],       category="Security",
               status="Active",   usage="IPsec key exchange (IKEv1/v2)"),
    514:  dict(name="Syslog",        proto=["udp"],       category="Logging",
               status="Active",   usage="System log messages"),
    515:  dict(name="LPD",           proto=["tcp"],       category="Printing",
               status="Active",   usage="Line Printer Daemon"),
    520:  dict(name="RIP",           proto=["udp"],       category="Routing",
               status="Active",   usage="Routing Information Protocol v1/v2"),
    521:  dict(name="RIPng",         proto=["udp"],       category="Routing",
               status="Active",   usage="RIP next generation (IPv6)"),
    554:  dict(name="RTSP",          proto=["tcp","udp"], category="Streaming",
               status="Active",   usage="Real-Time Streaming Protocol"),
    587:  dict(name="SMTP-Submission",proto=["tcp"],      category="Email",
               status="Active",   usage="Mail submission with auth (RFC 6409)"),
    593:  dict(name="MS-RPC-HTTP",   proto=["tcp"],       category="Windows",
               status="Active",   usage="Microsoft RPC over HTTP"),
    623:  dict(name="IPMI",          proto=["udp"],       category="Management",
               status="Active",   usage="IPMI/BMC remote management"),
    636:  dict(name="LDAPS",         proto=["tcp"],       category="Directory",
               status="Active",   usage="LDAP over TLS/SSL"),
    646:  dict(name="LDP",           proto=["tcp","udp"], category="MPLS",
               status="Active",   usage="MPLS Label Distribution Protocol"),
    694:  dict(name="Heartbeat",     proto=["udp"],       category="Clustering",
               status="Active",   usage="Linux-HA heartbeat"),
    860:  dict(name="iSCSI",         proto=["tcp"],       category="Storage",
               status="Active",   usage="iSCSI block storage over TCP"),
    873:  dict(name="rsync",         proto=["tcp"],       category="File Transfer",
               status="Active",   usage="rsync daemon file synchronisation"),
    902:  dict(name="VMware-ESX",    proto=["tcp","udp"], category="Virtualisation",
               status="Vendor-specific",usage="VMware ESXi management"),
    # ── Registered (1024–49151) ───────────────────────────────────────────────
    993:  dict(name="IMAPS",         proto=["tcp"],       category="Email",
               status="Active",   usage="IMAP over TLS/SSL"),
    995:  dict(name="POP3S",         proto=["tcp"],       category="Email",
               status="Active",   usage="POP3 over TLS/SSL"),
    1080: dict(name="SOCKS",         proto=["tcp"],       category="Proxy",
               status="Active",   usage="SOCKS proxy protocol"),
    1194: dict(name="OpenVPN",       proto=["tcp","udp"], category="VPN",
               status="Active",   usage="OpenVPN tunnel"),
    1433: dict(name="MSSQL",         proto=["tcp","udp"], category="Database",
               status="Active",   usage="Microsoft SQL Server"),
    1521: dict(name="Oracle-DB",     proto=["tcp"],       category="Database",
               status="Active",   usage="Oracle Database Listener"),
    1701: dict(name="L2TP",          proto=["udp"],       category="VPN",
               status="Active",   usage="Layer 2 Tunneling Protocol"),
    1723: dict(name="PPTP",          proto=["tcp"],       category="VPN",
               status="Deprecated",usage="Point-to-Point Tunneling Protocol"),
    1812: dict(name="RADIUS-Auth",   proto=["udp"],       category="Authentication",
               status="Active",   usage="RADIUS authentication"),
    1813: dict(name="RADIUS-Acct",   proto=["udp"],       category="Authentication",
               status="Active",   usage="RADIUS accounting"),
    1883: dict(name="MQTT",          proto=["tcp"],       category="IoT",
               status="Active",   usage="Message Queuing Telemetry Transport"),
    2049: dict(name="NFS",           proto=["tcp","udp"], category="File Sharing",
               status="Active",   usage="Network File System"),
    2181: dict(name="ZooKeeper",     proto=["tcp"],       category="Distributed",
               status="Active",   usage="Apache ZooKeeper coordination"),
    2375: dict(name="Docker",        proto=["tcp"],       category="Container",
               status="Active",   usage="Docker daemon API (insecure)"),
    2376: dict(name="Docker-TLS",    proto=["tcp"],       category="Container",
               status="Active",   usage="Docker daemon API (TLS)"),
    3306: dict(name="MySQL",         proto=["tcp","udp"], category="Database",
               status="Active",   usage="MySQL/MariaDB"),
    3389: dict(name="RDP",           proto=["tcp","udp"], category="Remote Access",
               status="Active",   usage="Remote Desktop Protocol"),
    4500: dict(name="IKE-NAT-T",     proto=["udp"],       category="Security",
               status="Active",   usage="IPsec IKE NAT traversal"),
    4789: dict(name="VXLAN",         proto=["udp"],       category="Overlay",
               status="Active",   usage="Virtual Extensible LAN"),
    5000: dict(name="Docker-Registry",proto=["tcp"],      category="Container",
               status="Active",   usage="Docker image registry"),
    5060: dict(name="SIP",           proto=["tcp","udp"], category="VoIP",
               status="Active",   usage="SIP call signalling"),
    5061: dict(name="SIP-TLS",       proto=["tcp"],       category="VoIP",
               status="Active",   usage="SIP over TLS"),
    5355: dict(name="LLMNR",         proto=["tcp","udp"], category="Name Resolution",
               status="Active",   usage="Link-Local Multicast Name Resolution"),
    5432: dict(name="PostgreSQL",    proto=["tcp"],       category="Database",
               status="Active",   usage="PostgreSQL database server"),
    5672: dict(name="AMQP",          proto=["tcp"],       category="Messaging",
               status="Active",   usage="Advanced Message Queuing Protocol"),
    5900: dict(name="VNC",           proto=["tcp"],       category="Remote Access",
               status="Active",   usage="Virtual Network Computing"),
    6379: dict(name="Redis",         proto=["tcp"],       category="Database",
               status="Active",   usage="Redis in-memory data store"),
    6514: dict(name="Syslog-TLS",    proto=["tcp"],       category="Logging",
               status="Active",   usage="Syslog over TLS (RFC 5425)"),
    6653: dict(name="OpenFlow",      proto=["tcp"],       category="SDN",
               status="Active",   usage="OpenFlow SDN controller"),
    7946: dict(name="Docker-Swarm",  proto=["tcp","udp"], category="Container",
               status="Active",   usage="Docker Swarm node communication"),
    8080: dict(name="HTTP-Alt",      proto=["tcp"],       category="Web",
               status="Active",   usage="Alternate HTTP / proxy"),
    8443: dict(name="HTTPS-Alt",     proto=["tcp"],       category="Web",
               status="Active",   usage="Alternate HTTPS"),
    8883: dict(name="MQTT-TLS",      proto=["tcp"],       category="IoT",
               status="Active",   usage="MQTT over TLS"),
    9090: dict(name="Prometheus",    proto=["tcp"],       category="Monitoring",
               status="Active",   usage="Prometheus metrics endpoint"),
    9092: dict(name="Kafka",         proto=["tcp"],       category="Messaging",
               status="Active",   usage="Apache Kafka broker"),
    9200: dict(name="Elasticsearch", proto=["tcp"],       category="Search",
               status="Active",   usage="Elasticsearch REST API"),
    10250:dict(name="Kubernetes-Kubelet",proto=["tcp"],   category="Container",
               status="Active",   usage="Kubernetes node agent API"),
    27017:dict(name="MongoDB",       proto=["tcp"],       category="Database",
               status="Active",   usage="MongoDB document database"),
    50000:dict(name="SAP",           proto=["tcp"],       category="ERP",
               status="Active",   usage="SAP application server"),
    51820:dict(name="WireGuard",     proto=["udp"],       category="VPN",
               status="Active",   usage="WireGuard VPN tunnel"),
}

# ── Ephemeral / dynamic port ranges ──────────────────────────────────────────
EPHEMERAL_RANGES = [
    (32768, 60999, "Linux default ephemeral"),
    (49152, 65535, "IANA recommended ephemeral (RFC 6335)"),
    (1024,  5000,  "BSD/Windows legacy ephemeral"),
]


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — TCP FLAG SEMANTICS
# ══════════════════════════════════════════════════════════════════════════════

TCP_FLAG_BITS: dict[str, int] = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04,
    "PSH": 0x08, "ACK": 0x10, "URG": 0x20,
    "ECE": 0x40, "CWR": 0x80,
}

TCP_FLAG_DETAIL: dict[str, dict] = {
    "SYN": dict(usage="Open connection — initiate 3-way handshake",
                direction="client→server (step1) or server→client (step2)"),
    "ACK": dict(usage="Acknowledge received data — always set after handshake",
                direction="both"),
    "FIN": dict(usage="Graceful close — no more data to send",
                direction="initiating side → peer"),
    "RST": dict(usage="Abrupt connection reset — discard all state",
                direction="either — usually error response"),
    "PSH": dict(usage="Push data to application immediately (do not buffer)",
                direction="either — set on last segment of application write"),
    "URG": dict(usage="Urgent pointer field is significant — out-of-band data",
                direction="either — rarely used in modern TCP"),
    "ECE": dict(usage="ECN-Echo — peer received CE-marked packet (congestion signalled)",
                direction="receiver→sender during congestion"),
    "CWR": dict(usage="Congestion Window Reduced — sender already reduced cwnd",
                direction="sender→receiver acknowledging ECE"),
}

TCP_HANDSHAKE_STATES: dict[str, dict] = {
    "CLOSED":      dict(flags=None,   description="No connection"),
    "LISTEN":      dict(flags=None,   description="Server waiting for SYN"),
    "SYN_SENT":    dict(flags="SYN",  description="Client sent SYN, waiting SYN-ACK"),
    "SYN_RCVD":    dict(flags="SYN+ACK", description="Server sent SYN-ACK, waiting ACK"),
    "ESTABLISHED": dict(flags="ACK",  description="Connection open — data flows"),
    "FIN_WAIT_1":  dict(flags="FIN+ACK", description="Active closer sent FIN"),
    "FIN_WAIT_2":  dict(flags="ACK",  description="Active closer got ACK for FIN"),
    "CLOSE_WAIT":  dict(flags="ACK",  description="Passive closer got FIN, app must close"),
    "LAST_ACK":    dict(flags="FIN+ACK", description="Passive closer sent FIN"),
    "TIME_WAIT":   dict(flags="ACK",  description="2×MSL wait before CLOSED"),
    "CLOSING":     dict(flags="FIN+ACK", description="Simultaneous close"),
}


def decode_tcp_flags(flag_byte: int) -> list[str]:
    """Return list of active flag names for a TCP flags byte."""
    return [name for name, bit in TCP_FLAG_BITS.items() if flag_byte & bit]


def tcp_flag_summary(flag_byte: int) -> str:
    """Human-readable TCP flag string e.g. 'SYN+ACK'."""
    names = decode_tcp_flags(flag_byte)
    return "+".join(names) if names else "NONE"


def classify_tcp_segment(flag_byte: int, payload_len: int) -> dict:
    """
    Classify a TCP segment by its flags and payload.
    Returns dict(classification, description, handshake_step).
    """
    flags = decode_tcp_flags(flag_byte)
    fset  = set(flags)

    if fset == {"SYN"}:
        return dict(classification="SYN",
                    description="Connection request — 3-way handshake step 1",
                    handshake_step=1)
    if fset == {"SYN", "ACK"}:
        return dict(classification="SYN-ACK",
                    description="Connection grant — 3-way handshake step 2",
                    handshake_step=2)
    if fset == {"ACK"} and payload_len == 0:
        return dict(classification="ACK",
                    description="Pure acknowledgment — no data",
                    handshake_step=3)
    if "PSH" in fset and "ACK" in fset and payload_len > 0:
        return dict(classification="PSH+ACK",
                    description=f"Data segment ({payload_len}B) — push to application",
                    handshake_step=4)
    if "FIN" in fset and "ACK" in fset:
        return dict(classification="FIN+ACK",
                    description="Graceful close initiation",
                    handshake_step=5)
    if fset == {"RST"} or fset == {"RST", "ACK"}:
        return dict(classification="RST",
                    description="Abrupt connection reset",
                    handshake_step=6)
    return dict(classification="+".join(sorted(flags)),
                description="TCP segment",
                handshake_step=None)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — UDP SERVICE DETECTION
# ══════════════════════════════════════════════════════════════════════════════

UDP_SERVICE_MAP: dict[tuple, dict] = {
    (53,  53):   dict(name="DNS Query/Response",  direction="client→server or server→client"),
    (67,  68):   dict(name="DHCP Server→Client",  direction="server→client"),
    (68,  67):   dict(name="DHCP Client→Server",  direction="client→server"),
    (123, 123):  dict(name="NTP",                 direction="client↔server"),
    (161, 162):  dict(name="SNMP Get/Set",        direction="manager→agent"),
    (162, 162):  dict(name="SNMP Trap",           direction="agent→manager"),
    (514, 514):  dict(name="Syslog",              direction="device→collector"),
    (520, 520):  dict(name="RIP v1/v2",           direction="router↔router"),
    (521, 521):  dict(name="RIPng",               direction="router↔router"),
    (69,  69):   dict(name="TFTP",                direction="client↔server"),
    (5060,5060): dict(name="SIP",                 direction="UA↔UA or UA↔Proxy"),
    (1194,1194): dict(name="OpenVPN",             direction="peer↔peer"),
    (4789,4789): dict(name="VXLAN Tunnel",        direction="VTEP↔VTEP"),
    (51820,51820):dict(name="WireGuard",          direction="peer↔peer"),
    (4500,4500): dict(name="IKE NAT-T",           direction="IPsec peer↔peer"),
    (500, 500):  dict(name="IKE/ISAKMP",          direction="IPsec peer↔peer"),
}


def detect_udp_service(src_port: int, dst_port: int) -> dict:
    """Detect UDP service from port pair (tries both orderings)."""
    svc = UDP_SERVICE_MAP.get((src_port, dst_port))
    if svc:
        return svc
    svc = UDP_SERVICE_MAP.get((dst_port, src_port))
    if svc:
        return svc
    # fallback: check individual port names
    src_info = PORT_REGISTRY.get(src_port)
    dst_info = PORT_REGISTRY.get(dst_port)
    if dst_info and "udp" in dst_info.get("proto", []):
        return dict(name=dst_info["name"], direction=f"→ port {dst_port}")
    if src_info and "udp" in src_info.get("proto", []):
        return dict(name=src_info["name"], direction=f"← port {src_port}")
    return dict(name="Unknown UDP service", direction="unknown")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — GRE FIELD DETAIL
# ══════════════════════════════════════════════════════════════════════════════

GRE_VERSIONS: dict[int, str] = {
    0: "GRE (RFC 2784 / RFC 2890) — standard",
    1: "Enhanced GRE (PPTP) — RFC 2637",
}

def decode_gre_header(data: bytes) -> dict:
    """
    Decode a GRE header (minimum 4 bytes).
    Returns dict with flags, version, protocol, optional fields.
    """
    if len(data) < 4:
        return dict(valid=False, reason="Too short for GRE")

    word0    = struct.unpack("!H", data[0:2])[0]
    proto    = struct.unpack("!H", data[2:4])[0]

    cksum_present = bool(word0 & 0x8000)
    key_present   = bool(word0 & 0x2000)
    seq_present   = bool(word0 & 0x1000)
    version       = word0 & 0x7

    offset = 4
    checksum = None
    key      = None
    seq      = None

    if cksum_present:
        checksum = struct.unpack("!H", data[offset:offset+2])[0]
        offset  += 4  # checksum(2) + reserved(2)
    if key_present and offset + 4 <= len(data):
        key    = struct.unpack("!I", data[offset:offset+4])[0]
        offset += 4
    if seq_present and offset + 4 <= len(data):
        seq    = struct.unpack("!I", data[offset:offset+4])[0]
        offset += 4

    return dict(
        valid         = True,
        version       = version,
        version_name  = GRE_VERSIONS.get(version, f"Unknown v{version}"),
        proto         = proto,
        proto_name    = f"0x{proto:04X}",
        cksum_present = cksum_present,
        checksum      = checksum,
        key_present   = key_present,
        key           = key,
        seq_present   = seq_present,
        seq           = seq,
        header_len    = offset,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — IPSEC ESP / AH DETAIL
# ══════════════════════════════════════════════════════════════════════════════

ESP_FIELD_DETAIL: dict = {
    "SPI":      "4B Security Parameters Index — identifies SA on receiver",
    "Seq":      "4B anti-replay counter — increments per packet",
    "IV":       "variable initialisation vector (AES-CBC=16B, AES-GCM=8B)",
    "Payload":  "encrypted data (variable)",
    "Pad":      "0-255B padding to block boundary",
    "Pad-len":  "1B number of pad bytes",
    "Next-Hdr": "1B inner protocol (4=IPv4 41=IPv6 17=UDP 6=TCP)",
    "ICV":      "8-16B integrity check value (authentication tag)",
}

AH_FIELD_DETAIL: dict = {
    "Next-Hdr":    "1B inner protocol number",
    "Payload-Len": "1B  (ICV length in 4B words − 2)",
    "Reserved":    "2B  must be zero",
    "SPI":         "4B Security Parameters Index",
    "Seq":         "4B anti-replay counter",
    "ICV":         "variable integrity check (HMAC-SHA1=12B HMAC-SHA256=16B)",
}

# Common ESP transform sets
ESP_TRANSFORMS: dict[str, dict] = {
    "AES-128-CBC + HMAC-SHA1-96": dict(enc_key=128, auth_key=160,
                                        iv_len=16, icv_len=12, status="Active"),
    "AES-256-CBC + HMAC-SHA256-128":dict(enc_key=256, auth_key=256,
                                          iv_len=16, icv_len=16, status="Active"),
    "AES-128-GCM-16":              dict(enc_key=128, auth_key=None,
                                        iv_len=8, icv_len=16, status="Active",
                                        note="AEAD — no separate auth algo"),
    "AES-256-GCM-16":              dict(enc_key=256, auth_key=None,
                                        iv_len=8, icv_len=16, status="Active",
                                        note="AEAD — preferred in IKEv2"),
    "3DES-CBC + HMAC-SHA1-96":     dict(enc_key=168, auth_key=160,
                                        iv_len=8, icv_len=12, status="Deprecated"),
    "NULL + HMAC-SHA1-96":         dict(enc_key=None, auth_key=160,
                                        iv_len=0, icv_len=12, status="Active",
                                        note="Integrity only — no encryption"),
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — PROTOCOL-LEVEL FIELD DETAIL (concise)
# ══════════════════════════════════════════════════════════════════════════════

L4_FIELD_DETAIL: dict[str, dict] = {
    "tcp": {
        "Src Port":    "2B source port (ephemeral for clients)",
        "Dst Port":    "2B destination port (service identifier)",
        "Seq":         "4B position of first data byte in this segment",
        "Ack":         "4B next byte expected from peer (ACK flag must be set)",
        "Data Offset": "4b header length ÷4 (min=5 for 20B no-option header)",
        "Flags":       "9b: NS CWR ECE URG ACK PSH RST SYN FIN",
        "Window":      "2B receive buffer space (flow control)",
        "Checksum":    "2B RFC793 pseudo-header + segment",
        "Urgent":      "2B valid only when URG flag set",
    },
    "udp": {
        "Src Port":  "2B source port",
        "Dst Port":  "2B destination port",
        "Length":    "2B header(8B) + data length",
        "Checksum":  "2B RFC768 pseudo-header + datagram (0xFFFF if zero)",
    },
    "icmp": {
        "Type":     "1B message type (8=request 0=reply 3=unreachable 11=TTL-exceeded)",
        "Code":     "1B sub-code qualifying the type",
        "Checksum": "2B over entire ICMP message",
        "Rest":     "4B type-specific (ID+Seq for echo, unused for errors)",
        "Data":     "variable: for errors = IP header + 8B of triggering packet",
    },
    "igmp": {
        "Type":         "1B 0x11=Query 0x16=Report(v2) 0x22=Report(v3) 0x17=Leave",
        "Max Resp":     "1B max response time in tenths of second",
        "Checksum":     "2B over IGMP message",
        "Group Addr":   "4B multicast group address",
    },
    "gre": {
        "Flags+Ver":  "2B: C=cksum K=key S=seq bits + version(3b)",
        "Protocol":   "2B inner EtherType (0x0800=IPv4 0x86DD=IPv6 0x6558=TEB)",
        "Checksum":   "opt 4B (2B cksum + 2B reserved) when C=1",
        "Key":        "opt 4B tunnel key when K=1",
        "Seq":        "opt 4B sequence number when S=1",
    },
    "esp": ESP_FIELD_DETAIL,
    "ah":  AH_FIELD_DETAIL,
    "ospf": {
        "Version":   "1B  2=OSPFv2 (IPv4) 3=OSPFv3 (IPv6)",
        "Type":      "1B  1=Hello 2=DBD 3=LSReq 4=LSU 5=LSAck",
        "Length":    "2B  total packet length",
        "Router-ID": "4B  sender's router identifier",
        "Area-ID":   "4B  ospf area (0.0.0.0=backbone)",
        "Checksum":  "2B  over entire OSPF packet",
        "Auth-Type": "2B  0=none 1=simple-password 2=MD5",
    },
    "sctp": {
        "Src Port":   "2B",
        "Dst Port":   "2B",
        "Verif-Tag":  "4B  peer's assigned tag",
        "Checksum":   "4B  CRC-32c over full packet",
        "Chunks":     "variable  Type(1B)+Flags(1B)+Length(2B)+Value",
    },
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 7 — PORT RANGE CLASSIFIER
# ══════════════════════════════════════════════════════════════════════════════

def classify_port(port: int) -> dict:
    """
    Classify a port number.
    Returns dict(range_name, registered_name, is_ephemeral, category).
    """
    known = PORT_REGISTRY.get(port)
    name  = known["name"] if known else None
    cat   = known["category"] if known else None

    if 0 <= port <= 1023:
        return dict(range_name="Well-known (0-1023)", registered_name=name,
                    category=cat, is_ephemeral=False)
    if 1024 <= port <= 49151:
        return dict(range_name="Registered (1024-49151)", registered_name=name,
                    category=cat, is_ephemeral=False)
    return dict(range_name="Dynamic/Ephemeral (49152-65535)", registered_name=name,
                category=cat, is_ephemeral=True)


def port_info(port: int) -> str:
    """One-line port description."""
    known = PORT_REGISTRY.get(port)
    if known:
        return f"{port}/{'/'.join(known['proto'])} — {known['name']} [{known['usage']}]"
    cls = classify_port(port)
    return f"{port} — {cls['range_name']}"


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 8 — AUTO-MAPPING ENGINE  (l3_data.next_layer → L4 handler)
# ══════════════════════════════════════════════════════════════════════════════

# Protocols that ARE L4 (can be directly dispatched)
L4_HANDLERS: set = {
    "tcp", "udp", "icmp", "icmpv6", "igmp",
    "gre", "esp", "ah", "sctp", "dccp",
    "ospf", "eigrp", "vrrp", "pim",
    "rsvp", "l2tp", "isis",
}

# Protocols that have no further L4 (terminate here)
L4_TERMINATES: set = {
    "arp", "rarp", "stp", "lldp", "pagp", "lacp",
    "dtp", "pfc", "pause", "vlan_only",
}

# Recursive / tunnelled protocols that need inner L4 analysis
L4_RECURSIVE: set = {
    "gre",    # inner proto field
    "esp",    # decrypted inner packet
    "ah",     # inner proto = next header
    "l2tp",   # inner PPP → inner IP → inner L4
}


def resolve_l4_handler(next_layer: str | None) -> dict:
    """
    Given l3_data.next_layer, return L4 dispatch info.
    """
    if next_layer is None:
        return dict(handler=None, has_payload=False, recursive=False,
                    reason="No L4 implied by this L3 protocol")
    nl = next_layer.lower()
    if nl in L4_TERMINATES:
        return dict(handler=None, has_payload=False, recursive=False,
                    reason=f"{nl} terminates — no Layer 4")
    if nl in L4_HANDLERS:
        return dict(handler=nl, has_payload=True,
                    recursive=nl in L4_RECURSIVE,
                    reason=f"Standard L4 protocol: {nl}")
    return dict(handler="raw", has_payload=True, recursive=False,
                reason=f"Unknown L4: {nl} — treated as RAW payload")


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 9 — process_l4()  (called by main.py)
# ══════════════════════════════════════════════════════════════════════════════

def process_l4(
    l3_data:    dict,
    src_port:   int   | None = None,
    dst_port:   int   | None = None,
    flags:      int   | None = None,
    seq_num:    int   | None = None,
    ack_num:    int   | None = None,
    icmp_type:  int   | None = None,
    icmp_code:  int   | None = None,
    raw_segment:bytes | None = None,
    extra:      dict  | None = None,
) -> dict:
    """
    Central L4 intelligence dispatcher.

    Parameters
    ----------
    l3_data     : dict returned by process_l3() — provides next_layer hint
    src_port    : source port (TCP/UDP)
    dst_port    : destination port (TCP/UDP)
    flags       : TCP flags byte
    seq_num     : TCP sequence number
    ack_num     : TCP acknowledgement number
    icmp_type   : ICMP type
    icmp_code   : ICMP code
    raw_segment : raw L4 bytes (optional — for decode)
    extra       : any extra context

    Returns
    -------
    dict with keys:
        handler, l4_class, service_info, field_detail,
        tcp_classification, port_info, gre_detail,
        has_payload, recursive, summary
    """
    extra   = extra or {}
    nl      = l3_data.get("next_layer")
    handler = resolve_l4_handler(nl)
    l4_cls  = handler.get("handler", "raw")

    # ── Port classification ───────────────────────────────────────────────────
    src_port_info = classify_port(src_port) if src_port is not None else {}
    dst_port_info = classify_port(dst_port) if dst_port is not None else {}

    # ── Service detection ─────────────────────────────────────────────────────
    service_info  = {}
    if l4_cls == "tcp" and dst_port is not None:
        known = PORT_REGISTRY.get(dst_port)
        if known:
            service_info = known
    elif l4_cls == "udp" and src_port is not None and dst_port is not None:
        service_info = detect_udp_service(src_port, dst_port)

    # ── TCP segment classification ────────────────────────────────────────────
    tcp_class = {}
    if l4_cls == "tcp" and flags is not None:
        payload_len = len(raw_segment) - 20 if raw_segment else 0
        tcp_class   = classify_tcp_segment(flags, payload_len)

    # ── Field detail ──────────────────────────────────────────────────────────
    field_detail = L4_FIELD_DETAIL.get(l4_cls, {})

    # ── GRE decode ────────────────────────────────────────────────────────────
    gre_detail = {}
    if l4_cls == "gre" and raw_segment:
        gre_detail = decode_gre_header(raw_segment)

    # ── ICMP lookup ───────────────────────────────────────────────────────────
    icmp_detail = {}
    if l4_cls == "icmp" and icmp_type is not None:
        # Import from l3_builder at runtime to avoid circular dependency
        try:
            from l3_builder import get_icmp_type_info
            icmp_detail = get_icmp_type_info(icmp_type)
            if icmp_code is not None:
                code_name = icmp_detail.get("codes", {}).get(icmp_code, f"Code {icmp_code}")
                icmp_detail["resolved_code"] = code_name
        except ImportError:
            icmp_detail = dict(type=icmp_type, code=icmp_code)

    # ── Summary string ────────────────────────────────────────────────────────
    if l4_cls == "tcp":
        flag_str = tcp_flag_summary(flags) if flags is not None else "?"
        sp = port_info(src_port) if src_port is not None else "?"
        dp = port_info(dst_port) if dst_port is not None else "?"
        summary = f"TCP  {sp} → {dp}  flags={flag_str}"

    elif l4_cls == "udp":
        sp = port_info(src_port) if src_port is not None else "?"
        dp = port_info(dst_port) if dst_port is not None else "?"
        svc = service_info.get("name", "")
        summary = f"UDP  {sp} → {dp}  {svc}"

    elif l4_cls == "icmp":
        t_name = icmp_detail.get("name", f"Type {icmp_type}")
        c_name = icmp_detail.get("resolved_code", f"Code {icmp_code}")
        summary = f"ICMP  {t_name} / {c_name}"

    elif l4_cls == "gre":
        inner = gre_detail.get("proto_name", "?")
        summary = f"GRE  inner={inner}"

    elif l4_cls == "esp":
        summary = "ESP  (encrypted payload — no L4 visible)"

    elif l4_cls == "ah":
        summary = "AH  (authenticated — inner proto in Next-Hdr field)"

    else:
        summary = f"L4={l4_cls or 'none'}"

    return dict(
        handler          = handler,
        l4_class         = l4_cls,
        src_port         = src_port,
        dst_port         = dst_port,
        src_port_info    = src_port_info,
        dst_port_info    = dst_port_info,
        service_info     = service_info,
        tcp_classification = tcp_class,
        field_detail     = field_detail,
        gre_detail       = gre_detail,
        icmp_detail      = icmp_detail,
        flags            = flags,
        flag_str         = tcp_flag_summary(flags) if flags is not None else None,
        seq_num          = seq_num,
        ack_num          = ack_num,
        has_payload      = handler.get("has_payload", False),
        recursive        = handler.get("recursive", False),
        summary          = summary,
        l3_context       = l3_data,
        extra            = extra,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 10 — CONVENIENCE WRAPPERS
# ══════════════════════════════════════════════════════════════════════════════

def process_l4_tcp(l3_data: dict, src_port: int, dst_port: int,
                   flags: int, seq: int, ack: int,
                   raw: bytes | None = None) -> dict:
    return process_l4(l3_data, src_port=src_port, dst_port=dst_port,
                      flags=flags, seq_num=seq, ack_num=ack, raw_segment=raw)


def process_l4_udp(l3_data: dict, src_port: int, dst_port: int,
                   raw: bytes | None = None) -> dict:
    return process_l4(l3_data, src_port=src_port, dst_port=dst_port, raw_segment=raw)


def process_l4_icmp(l3_data: dict, icmp_type: int, icmp_code: int,
                    raw: bytes | None = None) -> dict:
    return process_l4(l3_data, icmp_type=icmp_type, icmp_code=icmp_code, raw_segment=raw)


def process_l4_gre(l3_data: dict, raw: bytes) -> dict:
    return process_l4(l3_data, raw_segment=raw)


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 11 — LISTING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def list_ports(
    proto:    str | None = None,
    category: str | None = None,
    status:   str | None = None,
) -> list[tuple[int, str, str]]:
    """
    Return list of (port, name, usage) optionally filtered.
    proto    : 'tcp' | 'udp'
    category : e.g. 'Database' | 'Web' | 'VPN'
    status   : 'Active' | 'Deprecated'
    """
    result = []
    for port, info in PORT_REGISTRY.items():
        if proto and proto not in info.get("proto", []):
            continue
        if category and info.get("category") != category:
            continue
        if status and info.get("status") != status:
            continue
        result.append((port, info["name"], info["usage"]))
    return sorted(result, key=lambda x: x[0])


def get_esp_transforms() -> dict:
    return ESP_TRANSFORMS


def get_tcp_states() -> dict:
    return TCP_HANDSHAKE_STATES


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 12 — NON-IP L4 PROTOCOL HANDLERS
#  Covers: XNS SPP/PEP/Echo/Error/RIP, Novell SPX/NCP/SAP/RIP,
#          AppleTalk ATP/NBP/RTMP/AEP/ZIP/ADSP,
#          Banyan VINES IPC/SPP, DECnet NSP, DEC LAT sessions, IBM SNA RU
# ══════════════════════════════════════════════════════════════════════════════

NON_IP_L4_REGISTRY: dict[str, dict] = {

    # ── XNS L4 protocols ──────────────────────────────────────────────────────
    "spp": dict(
        name="XNS SPP (Sequenced Packet Protocol)",
        transport="reliable ordered byte stream  (≈ TCP)",
        header_bytes=12,
        fields={
            "Connection ID (src)":  "2B source connection ID",
            "Connection ID (dst)":  "2B destination connection ID",
            "Sequence Number":      "2B",
            "Acknowledge Number":   "2B",
            "Allocation Number":    "2B (window: next seq peer may send)",
            "Datastream Type":      "1B sub-stream: 0=normal 1=end-of-msg 254=attention 255=probe",
            "Flags":                "1B: Send-ACK(1) Attention(2) EOM(4) Sys-Pkt(128)",
        },
        connections="3-way: Connect(SPP)/SPPACK/data → Disconnect/SPPACK",
        sockets="established via IDP; SPP socket numbers > 3000",
        applications="Courier RPC  ·  Filing  ·  Clearinghouse directory  ·  Printing",
    ),
    "pep": dict(
        name="XNS PEP (Packet Exchange Protocol)",
        transport="unreliable request/response  (≈ UDP)",
        header_bytes=4,
        fields={
            "ID":      "4B transaction ID — response copies request ID",
            "Client":  "4B client-type",
            "Data":    "variable request/response payload",
        },
        applications="Clearinghouse lookup  ·  Echo  ·  Routing queries",
    ),
    "xns_echo": dict(
        name="XNS Echo Protocol",
        transport="single request/response pair",
        header_bytes=2,
        fields={"Type":"2B  1=Request  2=Reply","Data":"variable — copied from request to reply"},
        applications="Network reachability testing (like ICMP echo)",
    ),
    "xns_error": dict(
        name="XNS Error Protocol",
        transport="one-way error notification",
        header_bytes=4,
        fields={"Error Type":"2B  0=Unspecified 1=Bad-Checksum 2=No-Socket 3=Pkt-Too-Large",
                "Error Param":"2B  max-packet-size for type 3",
                "Original":"first 42B of offending IDP packet"},
        applications="Network error reporting (like ICMP unreachable)",
    ),
    "xns_rip": dict(
        name="XNS RIP (Routing Information Protocol)",
        transport="periodic broadcast + request/response",
        header_bytes=2,
        fields={"Packet Type":"2B  1=Request 2=Response",
                "Entries":"variable: Network(4B)+Hop-Count(2B)",
                "Infinity":"hop count 16 = unreachable"},
        applications="XNS network routing table maintenance",
    ),

    # ── Novell IPX L4 protocols ────────────────────────────────────────────────
    "spx": dict(
        name="Novell SPX (Sequenced Packet Exchange)",
        transport="reliable ordered connection-oriented (≈ TCP)",
        header_bytes=12,
        fields={
            "Connection Control":   "1B flags EOM(4) Attention(5) ACK-req(6) Sys-pkt(7)",
            "Datastream Type":      "1B 0=normal 1=end-of-msg 254=attention 255=probe",
            "Src Connection ID":    "2B",
            "Dst Connection ID":    "2B",
            "Sequence Number":      "2B",
            "Acknowledge Number":   "2B",
            "Allocation Number":    "2B (window)",
        },
        connections="Connect-Req/Connect-Ack/data → Disconnect",
        applications="NetWare print  ·  remote access  ·  legacy NetWare apps",
    ),
    "ncp": dict(
        name="Novell NCP (NetWare Core Protocol)",
        transport="request/response over IPX (IPX type 17)",
        header_bytes=7,
        fields={
            "Request Type":    "2B  0x1111=Create-Service-Conn 0x2222=Service-Req 0x3333=Service-Reply 0x5555=Destroy 0x9999=Broadcast",
            "Sequence Number": "1B  0-255 wrapping",
            "Connection Low":  "1B low byte of connection number (1-250)",
            "Task Number":     "1B",
            "Connection High": "1B high byte",
            "Function Code":   "1B  21=Read 22=Write 66=CloseFile 72=OpenFile 0x17=NDS calls",
            "Sub-Function":    "variable depends on Function Code",
            "Data":            "variable  function-specific payload",
        },
        applications="NetWare file system  ·  NDS/eDirectory  ·  print queues  ·  bindery",
    ),
    "sap_ipx": dict(
        name="Novell SAP (Service Advertisement Protocol)",
        transport="periodic broadcast + nearest-server query (IPX type 4, socket 0x0452)",
        header_bytes=2,
        fields={
            "Query Type":    "2B  1=General-Svc-Query 2=General-Svc-Resp 3=Nearest-Query 4=Nearest-Resp",
            "Server Type":   "2B  0x0004=FileServer 0x0007=PrintServer 0x0278=NDS 0x0640+=app-specific",
            "Server Name":   "48B null-padded server name string",
            "Network":       "4B server network",
            "Node":          "6B server node MAC",
            "Socket":        "2B service socket number",
            "Hops":          "2B hop count (16=down/unreachable)",
        },
        applications="Advertising and discovering NetWare servers and services",
        note="SAP broadcasts every 60s — replaced by SLP in NetWare 5+ environments",
    ),
    "netbios_ipx": dict(
        name="NetBIOS over IPX (type-20 propagation)",
        transport="broadcast propagation through routers (IPX type 20)",
        header_bytes=0,
        fields={"Data":"NetBIOS datagram — Name_Claimed/Name_Query/Datagram/Broadcast",
                "Note":"IPX type-20 broadcasts are forwarded up to 8 hops — router must enable"},
        applications="Windows networking on NetWare  ·  legacy file/printer sharing",
    ),

    # ── AppleTalk L4 protocols ─────────────────────────────────────────────────
    "atp": dict(
        name="AppleTalk ATP (Transaction Protocol)",
        transport="reliable request/response with exactly-once semantics",
        header_bytes=8,
        fields={
            "Control":        "1B: TReq=0x40 TResp=0x80 TRel=0xC0 | XO(5) EOM(4) STS(3)",
            "Bitmap/SeqNo":   "1B: in TReq=response bitmap; in TResp=response seq 0-7",
            "Transaction ID": "2B unique transaction identifier",
            "User Bytes":     "4B caller-defined (ASP uses for func/bitmap)",
            "Data":           "variable — max 578B per response packet",
        },
        connections="TReq → [up to 8 TResp] → TRel  (XO = exactly-once semantics)",
        applications="AFP (AppleTalk Filing Protocol)  ·  PAP (Printer Access Protocol)  ·  ASP",
    ),
    "nbp": dict(
        name="AppleTalk NBP (Name Binding Protocol)",
        transport="DDP broadcast/multicast request → unicast reply",
        header_bytes=2,
        fields={
            "Function":    "4b BrRq(1) LkUp(2) LkUp-Reply(3) FwdReq(4) NuLkUp(5) NuLkUp-Reply(6) Confirm(7)",
            "Tuple Count": "4b number of NBP tuples in packet",
            "CBId":        "1B callback ID (correlates request to reply)",
            "Tuples":      "variable: Network(2B)+Node(1B)+Socket(1B)+Enum(1B)+Name(var)",
            "Name format": "Object:Type@Zone — e.g. LaserWriter:LaserWriter@Engineering",
        },
        applications="Service discovery on AppleTalk (≈ mDNS/DNS-SD on modern Apple)",
    ),
    "rtmp": dict(
        name="AppleTalk RTMP (Routing Table Maintenance Protocol)",
        transport="periodic broadcast (every 10s) + request/response",
        header_bytes=4,
        fields={"Sender Net":"2B","ID Len":"1B=8","Sender ID":"1B",
                "Routing Tuples":"variable StartNet(2B)+Distance(1B)+EndNet(2B) per route"},
        note="Distance measured in router hops — max 15 (16=unreachable)",
        applications="AppleTalk inter-zone routing table distribution",
    ),
    "aep": dict(
        name="AppleTalk AEP (Echo Protocol)",
        transport="single DDP echo request/reply",
        header_bytes=1,
        fields={"Function":"1B  1=Echo-Request  2=Echo-Reply","Data":"variable — copied to reply"},
        applications="AppleTalk reachability testing (≈ ICMP ping)",
    ),
    "zip": dict(
        name="AppleTalk ZIP (Zone Information Protocol)",
        transport="request/response + ATP-based zone list retrieval",
        header_bytes=2,
        fields={"Function":"1B 1=GetZoneList 2=GetLocalZones 3=GetMyZone 5=Query 6=Reply 7=TakeMyZone 8=Notify",
                "Zone Count":"1B (in multi-zone responses)",
                "Zone Names":"variable Pascal strings"},
        applications="AppleTalk zone name management — Chooser zone list",
    ),
    "adsp": dict(
        name="AppleTalk ADSP (Data Stream Protocol)",
        transport="reliable full-duplex byte stream  (≈ TCP)",
        header_bytes=13,
        fields={"Connection ID":"2B","First Byte Seq":"4B","Next Recv Seq":"4B",
                "Recv Window":"2B","Descriptor":"1B flags: EOM ACKREQ CLOSE RESET",
                "Data":"variable"},
        applications="Apple Remote Access  ·  AOCE  ·  legacy Mac peer networking",
    ),

    # ── Banyan VINES L4 protocols ──────────────────────────────────────────────
    "vines_ipc": dict(
        name="Banyan VINES IPC (Interprocess Communication)",
        transport="reliable message delivery (connection-oriented)",
        header_bytes=16,
        fields={"Src Port":"2B","Dst Port":"2B","Packet Type":"1B 0=Data 1=Error 2=Discard 3=Probe 4=Ack",
                "Control":"1B flags","Local Conn":"2B","Remote Conn":"2B",
                "Seq Number":"4B","Ack Number":"4B"},
        applications="VINES file service  ·  print  ·  StreetTalk queries  ·  messaging",
    ),
    "vines_spp": dict(
        name="Banyan VINES SPP (Sequenced Packet Protocol)",
        transport="reliable stream connection (≈ TCP, simpler than IPC)",
        header_bytes=8,
        fields={"Src Port":"2B","Dst Port":"2B","Seq":"2B","Ack":"2B"},
        applications="VINES terminal services  ·  simple file transfer",
    ),
    "vines_arp": dict(
        name="Banyan VINES ARP",
        transport="VIP broadcast/unicast — no connection setup",
        header_bytes=8,
        fields={"Type":"2B  1=Request 2=Response 3=Assignment","Network":"4B","Subnetwork":"2B"},
        applications="VINES internet address resolution",
    ),
    "vines_rtp": dict(
        name="Banyan VINES RTP (Routing Table Protocol)",
        transport="periodic broadcast + request/response",
        header_bytes=4,
        fields={"Packet Type":"2B  1=Request 2=Update 3=Response 4=Redirect",
                "Control":"2B","Entries":"variable network/metric tuples"},
        applications="VINES routing table maintenance",
    ),
    "vines_icp": dict(
        name="Banyan VINES ICP (Internet Control Protocol)",
        transport="one-way error/cost notification",
        header_bytes=4,
        fields={"Packet Type":"2B  0=Exception 1=Metric-Notification",
                "Exception Code":"2B","Original":"first bytes of offending VIP packet"},
        applications="VINES error reporting + path cost notifications",
    ),

    # ── DECnet NSP ────────────────────────────────────────────────────────────
    "nsp": dict(
        name="DECnet NSP (Network Services Protocol)",
        transport="reliable full-duplex logical link  (≈ TCP)",
        header_bytes="variable 3-9B",
        fields={
            "Msg Flags":  "1B: Data/Other-Data/Interrupt/Connect-Init/Connect-Confirm/Disconnect-Init/Disconnect-Confirm/Ack",
            "Dst Addr":   "2B destination logical link address",
            "Src Addr":   "2B source logical link address",
            "Ack Num":    "2B (LS bit=1 + 15b seq) in data/other segments",
            "Seq Num":    "2B sequence number",
            "Reason":     "2B reason code in connect/disconnect messages",
            "Data":       "variable user payload in data segments",
        },
        msg_types={
            0x00: "Data Segment",        0x10: "Other Data (expedited)",
            0x20: "Connect Initiate",    0x28: "Connect Confirm",
            0x30: "Disconnect Initiate", 0x38: "Disconnect Confirm",
            0x04: "Data ACK",            0x14: "Other Data ACK",
            0x08: "No-Resource ACK",     0x01: "Interrupt",
        },
        applications="CTERM (virtual terminal)  ·  DAP/FAL (file access)  ·  NML (management)  ·  Mail-11",
    ),

    # ── DEC LAT Session Slots ─────────────────────────────────────────────────
    "lat_session": dict(
        name="DEC LAT Session Slots",
        transport="multiplexed virtual circuits within LAT messages",
        header_bytes=3,
        fields={"Slot Type":  "1B: 0=Data 1=Attention 3=Start 9=Disconnect A=Reject",
                "Byte Count": "1B number of data bytes in this slot",
                "Min Attention":"1B minimum credits",
                "Data":       "variable terminal data (keystrokes, screen output)"},
        connections="Start→Start-Response → Data slots ↔ Disconnect",
        note="Up to 255 terminal sessions multiplexed in one LAT virtual circuit",
        applications="DECserver 100/200/300/500/700  ·  VAX console  ·  serial line mux",
    ),

    # ── IBM SNA RU Layer ──────────────────────────────────────────────────────
    "sna_ru": dict(
        name="IBM SNA RU (Request/Response Unit)",
        transport="hierarchical session over SNA path control",
        header_bytes=3,
        fields={"RH Byte 0":"Request/Response(1b)+Category(2b)+FI(1b)+SDI(1b)+BCI(1b)+ECI(1b)+DR1I(1b)",
                "RH Byte 1":"DR2I+ERI+QRI+PI+BBU+BIS+EIS bits",
                "RH Byte 2":"RLWI+QUI+PDI+CEBI bits + sense byte indicator",
                "RU":       "variable — contains VTAM/CICS/3270 data stream"},
        request_types={"FMD":"Function Management Data — normal application data",
                       "NC": "Network Control — path control operations",
                       "DFC":"Data Flow Control — pacing, chaining, brackets",
                       "SC": "Session Control — BIND/UNBIND/SDT/CLEAR"},
        applications="3270 terminal emulation  ·  CICS transactions  ·  JES print  ·  DB2",
    ),
}


def get_non_ip_l4_info(l4_class: str) -> dict:
    """Return non-IP L4 protocol registry entry."""
    return NON_IP_L4_REGISTRY.get(l4_class, {})


def process_l4_non_ip(l3_data: dict, extra: dict | None = None) -> dict:
    """
    L4 dispatcher for non-IP protocol stacks (XNS, IPX, DDP, VINES, DECnet, LAT, SNA).
    Uses l3_data.next_layer to select the L4 handler.
    """
    extra   = extra or {}
    nl      = l3_data.get("next_layer", "")
    entry   = NON_IP_L4_REGISTRY.get(nl, {})

    if not entry:
        return dict(l4_class="raw", summary=f"Non-IP L4: {nl} — raw payload",
                    field_detail={}, has_payload=True, l3_context=l3_data)

    return dict(
        l4_class     = nl,
        l4_name      = entry.get("name", nl),
        transport    = entry.get("transport", ""),
        header_bytes = entry.get("header_bytes", 0),
        field_detail = entry.get("fields", {}),
        applications = entry.get("applications", ""),
        connections  = entry.get("connections", ""),
        note         = entry.get("note", ""),
        has_payload  = True,
        summary      = f"{entry.get('name', nl)}  [{entry.get('transport','')}]",
        l3_context   = l3_data,
        extra        = extra,
    )


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 13 — STORAGE NETWORK L4 INTERACTIVE BUILDERS
#  All ask_* functions prompt user for every field with caution notes.
# ══════════════════════════════════════════════════════════════════════════════

STORAGE_L4_REGISTRY: dict[str, dict] = {

    # ── FCoE ──────────────────────────────────────────────────────────────────
    "fcoe_fcp": dict(
        name="FCoE FCP (Fibre Channel Protocol — SCSI over FC)",
        transport="FC frames over lossless Ethernet (PFC CoS 3 required)",
        header_bytes=24,
        fields={
            "R_CTL":     "1B  0x00=FCP_DATA 0x06=FCP_XFER_RDY 0x07=FCP_RSP",
            "D_ID":      "3B  Destination N_Port ID (e.g. 0x01 0x00 0x00)",
            "S_ID":      "3B  Source N_Port ID",
            "TYPE":      "1B  0x08=FCP",
            "F_CTL":     "3B  ExchangeSeq(bit23)+SeqInitiator+LastSeq",
            "SEQ_ID":    "1B  0=first sequence",
            "SEQ_CNT":   "2B  frame count within sequence",
            "OX_ID":     "2B  Originator Exchange ID",
            "RX_ID":     "2B  Responder Exchange ID (0xFFFF if initiator)",
            "FCP_LUN":   "8B  SCSI LUN (usually 0x0000000000000000 for LUN 0)",
            "FCP_Cntl":  "1B  FCP_CMD=0x02 FCP_DATA_DIR: bit1=write bit2=read",
            "FCP_DL":    "4B  data length (byte count of SCSI data phase)",
            "SCSI CDB":  "16B  Command Descriptor Block: Op+LUN+LBA+Length",
            "CDB Opcode":"1B  0x00=Test-Unit-Ready 0x03=RequestSense 0x12=Inquiry 0x1A=ModeSense6 0x25=ReadCapacity 0x28=Read10 0x2A=Write10 0x55=ModeSense10 0x88=Read16 0x8A=Write16 0xA0=ReportLUNs",
            "CAUTION":   "OX_ID must be unique per exchange — reuse causes exchange collision and I/O abort",
        },
        applications="SAN block I/O — disk read/write over FCoE fabric",
        caution="Requires PFC on CoS 3 and DCBX negotiation — without lossless = FC frames dropped = I/O errors",
    ),
    "fcoe_els": dict(
        name="FCoE ELS (Extended Link Service — FLOGI/PLOGI/LOGO)",
        transport="FC link service over lossless Ethernet",
        header_bytes=4,
        fields={
            "ELS Command": "1B  0x04=FLOGI 0x03=PLOGI 0x05=LOGO 0x52=FDISC 0x09=ADISC 0x23=RNID",
            "Reserved":    "3B",
            "FLOGI Payload":"36B N_Port Name(8B)+Fabric Name(8B)+Class3 Service Params(16B)",
            "PLOGI N_Port Name":"8B WWN of requesting N_Port",
            "PLOGI Node Name":  "8B WWN of node containing the N_Port",
            "Class3 Params":    "16B receive data size + concurrent sequences",
            "CAUTION":     "FLOGI must succeed before PLOGI — ELS ordering is strict",
        },
        applications="FCoE fabric login sequence — required before any FCP I/O",
    ),
    "fcoe_bls": dict(
        name="FCoE BLS (Basic Link Service — ABTS/BA_ACC/BA_RJT)",
        transport="FC abort/reset over lossless Ethernet",
        header_bytes=4,
        fields={
            "R_CTL":    "1B  0x81=BA_NOP 0x82=ABTS 0x84=BA_ACC 0x85=BA_RJT",
            "SEQ_ID":   "1B  sequence ID being aborted",
            "SEQ_CNT":  "2B  last frame count of aborted sequence",
            "OX_ID":    "2B  exchange to abort",
            "RX_ID":    "2B  responder exchange ID",
            "CAUTION":  "ABTS waits for BA_ACC before retry — timeout without response = port reset",
        },
        applications="FCoE error recovery — abort failing I/O exchanges",
    ),

    # ── FIP ───────────────────────────────────────────────────────────────────
    "fip_discovery": dict(
        name="FIP Discovery (FCF Solicitation/Advertisement)",
        transport="FCoE fabric discovery over Ethernet multicast",
        header_bytes=4,
        fields={
            "Op":         "2B  0x0001=Solicitation 0x0002=Advertisement",
            "Subcode":    "1B",
            "Desc ListLen":"2B  in 32-bit words",
            "Priority":   "1B  FCF priority (lower=better) 0=highest",
            "FC-Map":     "3B  0x0E:FC:00 default Ethernet-to-FC mapping prefix",
            "Switch Name":"8B  FCF WWN",
            "Fabric Name":"8B  fabric WWN",
            "FCF MAC":    "6B  FCF MAC address",
            "Max FCoE Size":"2B  maximum FCoE frame size (default 2158)",
            "FKA_ADV_Period":"4B  ms keepalive interval (default 8000ms)",
            "CAUTION":    "FC-Map must match on all FCoE nodes — mismatch = ENode cannot join fabric",
        },
        applications="FCoE initialisation — ENode discovers FCF before FLOGI",
    ),
    "fip_vlan": dict(
        name="FIP VLAN Discovery",
        transport="FIP VLAN request/notification",
        header_bytes=4,
        fields={
            "Op":      "2B  0x0004=VLAN",
            "Subcode": "1B  0x01=VLAN-Request 0x02=VLAN-Notification",
            "VLAN ID": "2B  VLAN carrying FCoE traffic (1-4094)",
            "CAUTION": "ENode must switch to discovered VLAN before sending FIP solicitation",
        },
    ),

    # ── AoE ───────────────────────────────────────────────────────────────────
    "aoe_ata": dict(
        name="AoE ATA Command",
        transport="ATA disk command over Ethernet — no IP/TCP",
        header_bytes=12,
        fields={
            "ATA Error/Feature":"1B  ATA feature register (command) or error register (response)",
            "ATA SectorCount":  "1B  number of 512B sectors",
            "ATA CmdStatus":    "1B  ATA command: 0x20=Read 0x30=Write 0xEC=Identify 0xB0=SMART 0xEF=SetFeatures",
            "ATA LBA0":         "1B  LBA bits 7:0",
            "ATA LBA1":         "1B  LBA bits 15:8",
            "ATA LBA2":         "1B  LBA bits 23:16",
            "ATA Device":       "1B  bits 3:0=LBA bits 27:24, bit4=DRV, bit6=LBA-mode=1, bit7=1",
            "ATA LBA3":         "1B  LBA bits 31:24 (48-bit LBA)",
            "ATA LBA4":         "1B  LBA bits 39:32",
            "ATA LBA5":         "1B  LBA bits 47:40",
            "ATA Data":         "variable  512B per sector",
            "CAUTION":          "ATA device register bit6 must=1 for LBA mode — CHS mode deprecated",
        },
        applications="AoE disk read/write/identify on Ethernet-attached storage",
    ),
    "aoe_config": dict(
        name="AoE Config Query",
        transport="AoE target capability query",
        header_bytes=8,
        fields={
            "Buffer Count": "2B  number of outstanding ATA requests target can accept",
            "Firmware Vers":"2B",
            "Sector Count": "1B  max sectors per ATA command",
            "AoE CCCmd":    "1B  0=Read 1=Test 2=Prefix-Test 3=Set 4=ForcedSet",
            "Config Length":"2B  length of config string",
            "Config String":"variable  target config data (e.g. storage device info)",
            "CAUTION":      "Buffer Count limits pipeline depth — exceed it = lost frames and retransmit",
        },
    ),

    # ── RoCE ──────────────────────────────────────────────────────────────────
    "roce_verb": dict(
        name="RoCE v1 RDMA Verb (Send/Write/Read)",
        transport="RDMA over lossless Ethernet — zero copy",
        header_bytes=12,
        fields={
            "OpCode":   "1B  0=RC-Send-First 4=RC-Send-Only 6=RC-Write-First 10=RC-Write-Only 12=RC-Read-Request",
            "SE":       "1b  Solicited Event — receiver posts completion",
            "M":        "1b  MigReq — migration state",
            "Pad":      "2b  payload padding bytes count",
            "TVer":     "4b  transport version=0",
            "P_Key":    "2B  partition key (default 0xFFFF=default partition)",
            "Dest QP":  "3B  Destination Queue Pair number",
            "A":        "1b  Acknowledge Request bit",
            "PSN":      "3B  Packet Sequence Number (increments per packet)",
            "RETH VirtAddr":"8B  (Write/Read) virtual address on remote node",
            "RETH R_Key":"4B  (Write/Read) remote key authorising access to that VA",
            "RETH DMA_Len":"4B  (Write/Read) total bytes to transfer",
            "Payload":  "variable  RDMA payload (must be 4B aligned)",
            "ICRC":     "4B  Invariant CRC over all invariant fields",
            "CAUTION":  "P_Key mismatch drops frame silently — verify partition config on both QPs",
        },
        applications="HPC MPI · NVMe-oF targets · GPU-direct RDMA · Lustre/GPFS parallel I/O",
        caution="Requires PFC + ECN (DCQCN) on lossless fabric — packet loss = QP error and I/O hang",
    ),
    "roce_ack": dict(
        name="RoCE v1 ACK/NAK",
        transport="RoCE reliable connected acknowledgement",
        header_bytes=12,
        fields={
            "OpCode":   "1B  0x10=RC-ACK 0x11=RC-Atomic-ACK",
            "Dest QP":  "3B",
            "PSN":      "3B",
            "AETH Syndrome": "1B  0x00=ACK others=NAK(code in bits 6:5)",
            "AETH MSN": "3B  Message Sequence Number acknowledged",
            "ICRC":     "4B",
            "CAUTION":  "NAK code 0x60=RNR-NAK (retry-later) — implement RNR retry timer or sender stalls",
        },
    ),

    # ── iSCSI ─────────────────────────────────────────────────────────────────
    "iscsi_scsi": dict(
        name="iSCSI SCSI Command/Response PDU",
        transport="iSCSI over direct Ethernet (no TCP)",
        header_bytes=48,
        fields={
            "Opcode":    "1B  0x01=Command 0x21=Response",
            "Flags":     "1B  F=Final W=Write R=Read Attr(3b)=0x0=Untagged",
            "CDB Len":   "1B  always 16B for standard CDB",
            "DataSegLen":"3B  data segment byte count",
            "LUN":       "8B  iSCSI LUN (8B format): first 2B=bus+target encoding",
            "ITT":       "4B  Initiator Task Tag — unique per outstanding command",
            "Expected DL":"4B  total data bytes expected (read=transfer size, write=same)",
            "CmdSN":     "4B  command sequence number (ordering)",
            "ExpStatSN": "4B  next expected StatusSN from target",
            "CDB":       "16B  SCSI Command Descriptor Block",
            "SCSI_Op":   "1B  0x00=TUR 0x03=RequestSense 0x12=Inquiry 0x25=ReadCap 0x28=Read10 0x2A=Write10 0x88=Read16 0x8A=Write16",
            "LBA":       "4-8B  starting logical block address (in CDB)",
            "Transfer Length":"2-4B  number of blocks (in CDB)",
            "CAUTION":   "ITT must be unique across all outstanding commands — duplicate ITT = target abort",
        },
        applications="iSCSI block storage I/O over direct Ethernet fabric",
    ),
    "iscsi_data": dict(
        name="iSCSI Data PDU (Data-In/Data-Out)",
        transport="iSCSI data transfer phase",
        header_bytes=48,
        fields={
            "Opcode":    "1B  0x04=Data-Out(write) 0x25=Data-In(read)",
            "Flags":     "1B  F=Final A=Acknowledge S=Status(Data-In only)",
            "DataSegLen":"3B  data bytes in this PDU",
            "LUN":       "8B",
            "ITT":       "4B  matches Command ITT",
            "TTT":       "4B  Target Transfer Tag (from R2T — 0xFFFFFFFF for unsolicited)",
            "StatSN":    "4B  status sequence (Data-In only)",
            "ExpCmdSN":  "4B",
            "DataSN":    "4B  data sequence number within task (starts at 0)",
            "BufferOffset":"4B  byte offset into total data buffer",
            "Data":      "variable  actual SCSI data (read or write)",
            "CAUTION":   "BufferOffset + DataSegLen must not exceed ExpectedDataTransferLength",
        },
    ),
    "iscsi_nop": dict(
        name="iSCSI NOP (keepalive)",
        transport="iSCSI session keepalive",
        header_bytes=48,
        fields={
            "Opcode":    "1B  0x00=NOP-Out 0x3F=NOP-In",
            "ITT":       "4B  0xFFFFFFFF for unsolicited NOP-In",
            "TTT":       "4B  0xFFFFFFFF for NOP-Out ping",
            "CmdSN":     "4B",
            "ExpStatSN": "4B",
            "Data":      "optional  ping data (echoed back)",
            "CAUTION":   "NOP-Out with ITT≠0xFFFFFFFF expects NOP-In response — no response = session timeout",
        },
    ),

    # ── NVMe ──────────────────────────────────────────────────────────────────
    "nvme_cmd": dict(
        name="NVMe Command Capsule (SQE — Submission Queue Entry)",
        transport="NVMe-oF L2 command submission",
        header_bytes=64,
        fields={
            "Opcode":    "1B  0x00=Flush 0x01=Write 0x02=Read 0x04=WriteUncorrectable 0x05=Compare 0x08=WriteZeroes 0x09=DSM 0x0C=Verify 0x0D=ResvRegister 0x7C=Format 0x7E=SecuritySend 0x7F=SecurityRecv",
            "FUSE":      "2b  Fused operation: 00=Normal 01=FirstFuse 10=SecondFuse",
            "PSDT":      "2b  PRP or SGL select: 00=PRP 01=SGL-Seg 10=SGL-Last",
            "CID":       "2B  Command Identifier — unique per SQ",
            "NSID":      "4B  Namespace ID (1-based; 0xFFFFFFFF=all namespaces)",
            "MPTR":      "8B  Metadata Pointer",
            "PRP1":      "8B  Physical Region Page entry 1 (data buffer host address)",
            "PRP2":      "8B  Physical Region Page entry 2 (or SGL segment pointer)",
            "CDW10":     "4B  command-specific DWord 10 (e.g. LBA[31:0] for Read/Write)",
            "CDW11":     "4B  command-specific DWord 11 (e.g. LBA[63:32])",
            "CDW12":     "4B  NLB(15:0)+PRINFO(3b)+FUA(1b)+LR(1b) for Read/Write",
            "CDW13":     "4B",
            "CDW14":     "4B",
            "CDW15":     "4B",
            "CAUTION":   "CID must be unique within the SQ — duplicate CID = command abort by controller",
        },
        applications="NVMe SSD I/O over Ethernet fabric — sub-10µs latency",
        caution="NSID 0 is reserved — use 1-based IDs; 0xFFFFFFFF only for admin namespace commands",
    ),
    "nvme_resp": dict(
        name="NVMe Completion Capsule (CQE — Completion Queue Entry)",
        transport="NVMe-oF L2 command completion",
        header_bytes=16,
        fields={
            "DW0":       "4B  command-specific result",
            "DW1":       "4B  reserved",
            "SQ_Head":   "2B  SQ Head Pointer — freed SQ slots",
            "SQ_ID":     "2B  identifies which SQ this completion is for",
            "CID":       "2B  matches Command Identifier from SQE",
            "P":         "1b  Phase Tag — alternates 0/1 per CQ wrap",
            "SC":        "8b  Status Code: 0=Success 1=InvalidCmdOpcode 2=InvalidField",
            "SCT":       "3b  Status Code Type: 0=Generic 1=CmdSpecific 2=MediaError",
            "CAUTION":   "Phase Tag mismatch means stale CQE — always check P bit matches expected phase",
        },
    ),
    "nvme_data": dict(
        name="NVMe H2C/C2H Data PDU",
        transport="NVMe-oF L2 data transfer",
        header_bytes=8,
        fields={
            "PDU Type":  "1B  0x02=H2C-Data(write) 0x03=C2H-Data(read)",
            "Flags":     "1B  HDGSTF+DDGSTF+LAST_PDU",
            "HDR Len":   "1B  header DWords",
            "PLEN":      "4B  total PDU length",
            "CCCID":     "4B  Command Capsule CID this data belongs to",
            "DATAO":     "4B  data offset within total transfer",
            "Data":      "variable  actual NVMe data (4B aligned)",
            "CAUTION":   "DATAO must be 4B aligned — misaligned offsets = PDU error and CQE failure",
        },
    ),

    # ── CFM / Y.1731 ──────────────────────────────────────────────────────────
    "cfm_ccm": dict(
        name="CFM CCM (Continuity Check Message)",
        transport="IEEE 802.1ag L2 OAM — periodic heartbeat",
        header_bytes=75,
        fields={
            "MD Level":  "3b  Maintenance Domain level 0-7 (0=lowest/customer 7=highest/operator)",
            "Version":   "5b  must be 0",
            "Opcode":    "1B  0x01=CCM",
            "Flags":     "1B  RDI(bit7)=Remote-Defect-Indicator  Period(bits 2:0): 1=3.3ms 2=10ms 4=1s 5=10s",
            "TLV Offset":"1B  0x46=70 (offset to first TLV from Flags byte)",
            "Seq Number":"4B  monotonically increasing — gap indicates frame loss",
            "MEPID":     "2B  1-8191  unique MEP ID within the MA",
            "MAID":      "48B  Maintenance Association ID: MDNameFormat(1B)+MDNameLen(1B)+MDName+MANameFormat(1B)+MANameLen(1B)+MAName",
            "Tx Timestamp":"8B  optional — for one-way delay measurement",
            "Port Status":"optional TLV  type=2 len=1 value: 1=Blocked 2=Up",
            "Intf Status":"optional TLV  type=4 len=1 value: 1=Up 2=Down 3=Testing",
            "End TLV":   "1B=0x00  mandatory last TLV",
            "CAUTION":   "All MEPs in MA must use same CCM interval — mismatch causes false RDI alarm",
        },
        applications="Ethernet OAM continuity monitoring — carrier fault detection",
    ),
    "cfm_lb": dict(
        name="CFM LBM/LBR (Loopback Message/Reply)",
        transport="IEEE 802.1ag L2 loopback — ≈ L2 ping",
        header_bytes=4,
        fields={
            "MD Level":      "3b",
            "Version":       "5b=0",
            "Opcode":        "1B  0x03=LBM  0x02=LBR",
            "Flags":         "1B=0",
            "TLV Offset":    "1B=0x04",
            "Transaction ID":"4B  echoed in LBR — identifies request",
            "Data TLV":      "optional  type=3 len=N data pattern (echoed)",
            "End TLV":       "1B=0x00",
            "CAUTION":       "LBM Dst must be unicast MEP MAC — broadcast LBM = all MEPs reply (multicast flood)",
        },
        applications="CFM loopback — verify L2 path between MEPs without IP",
    ),
    "cfm_lt": dict(
        name="CFM LTM/LTR (Linktrace Message/Reply)",
        transport="IEEE 802.1ag L2 traceroute",
        header_bytes=4,
        fields={
            "MD Level":     "3b",
            "Version":      "5b=0",
            "Opcode":       "1B  0x05=LTM  0x04=LTR",
            "Flags":        "1B  LTM: UseFDBonly(bit7)",
            "TLV Offset":   "1B",
            "Transaction ID":"4B",
            "TTL":          "1B  LTM only — hop limit (decremented per MIP/MEP)",
            "Orig MAC":     "6B  LTM sender MAC",
            "Target MAC":   "6B  LTM target MEP MAC",
            "Relay Action": "1B  LTR only: 1=RlyHit 2=RlyFDB 3=RlyMPDB",
            "CAUTION":      "LTM TTL too low = partial trace; LTM must be sent to LTM multicast 01:80:C2:00:00:3X",
        },
        applications="CFM path trace — identify intermediate MIPs between MEPs",
    ),
    "cfm_dm": dict(
        name="CFM/Y.1731 Delay Measurement (DMM/DMR/1DM/LMM/LMR)",
        transport="IEEE 802.1ag / ITU-T Y.1731 performance measurement",
        header_bytes=4,
        fields={
            "MD Level":      "3b",
            "Version":       "5b=0",
            "Opcode":        "1B  47=DMM 46=DMR 49=1DM 43=LMM 42=LMR",
            "Flags":         "1B=0",
            "TLV Offset":    "1B",
            "Seq Number":    "4B  (DMM/SLM) frame counter",
            "TxTimeStampf":  "8B  Tx PTP timestamp of this frame (seconds(6B)+nanoseconds(4B))",
            "RxTimeStampf":  "8B  Rx timestamp when peer received previous DMM",
            "TxTimeStampb":  "8B  (DMR) Tx timestamp of this DMR",
            "RxTimeStampb":  "8B  (DMR) Rx timestamp when this node received DMM",
            "TxFCf":         "4B  (LMM) transmitted frame counter far-end",
            "RxFCf":         "4B  (LMM) received frame counter far-end",
            "TxFCb":         "4B  (LMR) transmitted frame counter near-end",
            "CAUTION":       "Hardware timestamping required for accuracy — software TS error > 100µs typical",
        },
        applications="Y.1731 SLA measurement — frame delay (FD), mean FD, FDV (jitter), frame loss ratio",
    ),
    "cfm_ais": dict(
        name="Y.1731 AIS/LCK (Alarm Indication / Lock Signal)",
        transport="ITU-T Y.1731 defect propagation signal",
        header_bytes=4,
        fields={
            "MD Level":  "3b  client layer MD level (higher than server layer)",
            "Version":   "5b=0",
            "Opcode":    "1B  0x21=AIS  0x23=LCK",
            "Flags":     "1B  Period(3b): 4=1s 5=1min  Level(3b): client MD level",
            "TLV Offset":"1B=0x04",
            "End TLV":   "1B=0x00",
            "CAUTION":   "AIS must be sent at client layer level — wrong level = ignored by client MEPs",
        },
        applications="Server-layer fault propagation — suppress client-layer RDI alarms during known outage",
    ),
    "cfm_sl": dict(
        name="Y.1731 SLM/SLR (Synthetic Loss Measurement)",
        transport="ITU-T Y.1731 statistical frame loss measurement",
        header_bytes=4,
        fields={
            "Opcode":    "1B  0x37=SLM  0x38=SLR",
            "Flags":     "1B",
            "Seq Number":"4B",
            "Source MEP ID":"2B",
            "RxFCl":     "4B  received frame count local",
            "TxFCf":     "4B  transmitted frame count far end",
            "RxFCf":     "4B  received frame count far end",
            "CAUTION":   "SLM/SLR interval must match — mismatched periods = incorrect loss ratio calculation",
        },
        applications="Carrier-grade frame loss ratio measurement for SLA reporting",
    ),

    # ── Switch Protocol L4 builders ───────────────────────────────────────────
    "eapol_eap": dict(
        name="EAPOL EAP-Packet (802.1X authentication exchange)",
        transport="EAP over LAN — IEEE 802.1X port NAC",
        header_bytes=4,
        fields={
            "EAPOL Version": "1B  0x02=802.1X-2004  0x03=802.1X-2010",
            "EAPOL Type":    "1B  0x00=EAP-Packet",
            "EAPOL Length":  "2B  EAP data length",
            "EAP Code":      "1B  0x01=Request 0x02=Response 0x03=Success 0x04=Failure",
            "EAP ID":        "1B  request/response correlation ID",
            "EAP Length":    "2B  total EAP message length including Code+ID+Length",
            "EAP Type":      "1B  1=Identity 4=MD5-Challenge 13=EAP-TLS 25=PEAP 43=EAP-FAST 52=EAP-GPSK",
            "EAP Type Data": "variable  method-specific: TLS hello / PEAP tunnel / challenge bytes",
            "CAUTION":       "EAP-ID must match between Request and Response — ID mismatch = auth failure",
        },
        applications="802.1X wired/wireless port authentication — RADIUS EAP tunnel via Access-Request",
    ),
    "eapol_key": dict(
        name="EAPOL-Key (WPA/WPA2 4-way handshake key material)",
        transport="WPA key derivation exchange",
        header_bytes=4,
        fields={
            "EAPOL Version": "1B",
            "EAPOL Type":    "1B  0x03=EAPOL-Key",
            "EAPOL Length":  "2B",
            "Key Descriptor":"1B  0x02=RSN/WPA2 0x01=WPA1",
            "Key Info":      "2B  KeyType(1b)+Install(1b)+ACK(1b)+MIC(1b)+Secure(1b)+Error(1b)+Request(1b)+Encrypted-KeyData(1b)+SMK(1b)",
            "Key Length":    "2B  PTK/GTK length in bytes",
            "Replay Counter":"8B  monotonic — prevents replay of old 4-way messages",
            "Nonce":         "32B  ANonce (AP random) or SNonce (STA random)",
            "EAPOL-Key IV":  "16B  (WPA1 only) key encryption IV",
            "Key RSC":       "8B  RSN receive sequence counter",
            "Key MIC":       "16B  HMAC-SHA1 or AES-CMAC over entire EAPOL frame",
            "Key Data Len":  "2B",
            "Key Data":      "variable  RSN IE or GTK wrapped with KEK",
            "CAUTION":       "Replay Counter must strictly increase — reuse or decrease = 4-way handshake failure",
        },
        applications="WPA2/WPA3 4-way handshake — derives PTK from ANonce+SNonce+PMK",
    ),
    "eapol_ctrl": dict(
        name="EAPOL-Start / EAPOL-Logoff",
        transport="802.1X supplicant control messages",
        header_bytes=4,
        fields={
            "EAPOL Version": "1B",
            "EAPOL Type":    "1B  0x01=EAPOL-Start  0x02=EAPOL-Logoff",
            "EAPOL Length":  "2B  0x0000 (no data)",
            "CAUTION":       "EAPOL-Logoff sent unprotected — rogue logoff possible without MFP (802.11w)",
        },
    ),
    "lldp_tlv": dict(
        name="LLDP TLV (Type-Length-Value)",
        transport="LLDP TLV chain in LLDPDU",
        header_bytes=2,
        fields={
            "TLV Type":    "7b  0=End 1=ChassisID 2=PortID 3=TTL 4=PortDesc 5=SysName 6=SysDesc 7=SysCap 8=MgmtAddr 127=OrgSpec",
            "TLV Length":  "9b  value field length in bytes",
            "SubType":     "1B  (ChassisID/PortID) 4=MAC 5=NetworkAddr 7=Local",
            "Value":       "variable  TLV-specific content",
            "ChassisID":   "e.g. 6B MAC address if SubType=4",
            "PortID":      "e.g. interface name string if SubType=5",
            "TTL Value":   "2B  seconds until neighbour info expires (0=remove entry)",
            "SysCap":      "2B  Capabilities: bit0=Other bit2=Bridge bit4=Router bit6=Telephone bit8=DOCSIS bit10=StationOnly",
            "Enabled Cap": "2B  subset of SysCap that is enabled",
            "MgmtAddrLen": "1B",
            "MgmtAddrSubType":"1B  1=IPv4 2=IPv6",
            "MgmtAddr":    "4B IPv4 or 16B IPv6",
            "CAUTION":     "TTL=0 immediately removes entry from peer LLDP table — use 0 only for graceful removal",
        },
        applications="LLDP neighbour discovery — topology mapping, PoE negotiation, LLDP-MED",
    ),
    "lldp_orgspec": dict(
        name="LLDP Org-Specific TLV",
        transport="LLDP TLV Type=127 — vendor/standard extensions",
        header_bytes=2,
        fields={
            "TLV Type":  "7b=127",
            "TLV Length":"9b",
            "OUI":       "3B  00:80:C2=IEEE802.1  00:12:0F=IEEE802.3  00:12:BB=TIA-MED",
            "SubType":   "1B  OUI-specific: 802.1/SubType=1=PortVLANID 2=PortProtoVLANID 3=VLANName 4=ProtocolID; 802.3/SubType=1=MacPhy 2=PowerMDI 3=LinkAgg 4=MaxFS",
            "Value":     "variable  SubType-specific",
            "802.3at PoE":"SubType=2 MDIPowerSupport(1B)+MDIPowerPair(1B)+PowerClass(1B)+TypeSource(1B)+Priority(1B)+PDRequested(2B)+PSEAllocated(2B)",
            "CAUTION":   "OUI must match exactly — wrong OUI = TLV ignored by peer; 802.3bt requires 802.3 SubType=2 extended format",
        },
        applications="PoE power negotiation (802.3at/bt) · VLAN info · port protocol · LLDP-MED capabilities",
    ),
    "mrp_attr": dict(
        name="MRP Attribute (MVRP/MMRP attribute declaration)",
        transport="MRP attribute event — VLAN or multicast registration",
        header_bytes=4,
        fields={
            "Protocol ID":    "2B  0x0000=MRP",
            "Attribute Type": "1B  MVRP:0x01=VLAN  MMRP:0x01=ServiceReq 0x02=MAC-VID",
            "Attribute Length":"1B  bytes per attribute value",
            "MRP Event":      "3b  0=New 1=JoinIn 2=In 3=JoinMt 4=Mt 5=Lv (leave)",
            "Number of Values":"1B  packed events per byte",
            "VLAN ID":        "12b  (MVRP) VLAN being registered 1-4094",
            "MAC Address":    "6B  (MMRP) multicast MAC being registered",
            "VID":            "12b  (MMRP MAC-VID) VLAN context",
            "End Mark":       "2B  0x0000",
            "CAUTION":        "Lv event removes registration — accidental Lv = VLAN traffic lost on trunk",
        },
        applications="Dynamic VLAN/multicast registration between 802.1Q switches without manual config",
    ),
    "mrp_pdu": dict(
        name="MRP Ring PDU (IEC 62439-2)",
        transport="MRP ring redundancy control",
        header_bytes=10,
        fields={
            "Version":    "2B  0x0001",
            "Type":       "2B  0x0001=Common 0x0002=Test 0x0003=TopologyChange 0x0004=LinkDown 0x0005=LinkUp",
            "Length":     "2B  data length",
            "Priority":   "2B  MRM priority lower=preferred (0x8000=default)",
            "SA":         "6B  source MAC of MRM",
            "Port Role":  "2B  0x0001=Primary 0x0002=Secondary",
            "Ring State": "2B  0x0000=Open(broken) 0x0001=Closed(healthy)",
            "Interval":   "2B  test frame interval ms (default 10ms)",
            "Transition": "2B  topology change counter",
            "Timestamp":  "4B  millisecond timestamp",
            "CAUTION":    "Two MRMs on same ring = topology oscillation and packet storms — ensure only one MRM",
        },
        applications="Industrial ring redundancy — PROFINET MRP < 200ms failover",
    ),
    "prp_payload": dict(
        name="PRP Redundancy Control Trailer",
        transport="PRP trailer appended to standard Ethernet frame",
        header_bytes=6,
        fields={
            "Sequence Number":"2B  same value on both LAN-A and LAN-B copies",
            "LAN-ID":         "4b  0xA=LAN-A  0xB=LAN-B  (upper nibble of byte)",
            "LSDU Size":      "12b  original frame payload length (LSDU)",
            "PRP Suffix":     "2B  0x88FB — marks frame as PRP-tagged for Supervision",
            "CAUTION":        "Supervision frames (EtherType 0x88FB) must be sent on both LANs — missing on one LAN = incorrect VDAN state",
        },
        applications="Zero-switchover redundancy — IEC 61850 protection relays, process bus, ring-free dual-LAN",
    ),
    "ptp_msg": dict(
        name="PTP Message (IEEE 1588-2008/2019)",
        transport="IEEE 1588 precision time protocol over L2",
        header_bytes=34,
        fields={
            "messageType":     "4b  0=Sync 1=Delay_Req 2=Pdelay_Req 3=Pdelay_Resp 8=Follow_Up 9=Delay_Resp 11=Announce",
            "versionPTP":      "4b  must be 2",
            "messageLength":   "2B  total PDU bytes",
            "domainNumber":    "1B  clock domain 0-127 (0=default)",
            "minorVersionPTP": "1B  0 for 2008, 1 for 2019",
            "flagField":       "2B  twoStepFlag+unicastFlag+alternateMasterFlag+PTP_TIMESCALE+timeTraceable+frequencyTraceable",
            "correctionField": "8B  sub-nanosecond correction in 2^-16 ns units (usually 0)",
            "messageTypeSpecific":"4B",
            "sourcePortIdentity":"10B  clockIdentity(8B=EUI-64)+portNumber(2B)",
            "sequenceId":      "2B  per-messageType counter (wraps 0-65535)",
            "controlField":    "1B  deprecated: 0=Sync 1=Delay_Req 2=Follow_Up 3=Delay_Resp 4=Management 5=others",
            "logMessageInterval":"1B  log2 of interval (-3=0.125s 0=1s 1=2s 7=128s)",
            "originTimestamp": "10B  seconds(6B)+nanoseconds(4B) — Sync/Announce/Delay_Req",
            "utcOffset":       "2B  (Announce) current UTC-TAI offset in seconds",
            "grandmasterPriority1":"1B  (Announce) BMCA priority1 (lower=preferred) default 128",
            "grandmasterPriority2":"1B  (Announce) BMCA priority2 default 128",
            "grandmasterClockQuality":"4B  (Announce) clockClass+clockAccuracy+offsetScaledLogVariance",
            "CAUTION":         "Sync+Follow_Up sequenceId must match — mismatch causes slave to discard Follow_Up and miss sync",
        },
        applications="Sub-µs clock sync: financial trading · telecom (G.8275.2) · industrial (IEC 61588) · AES67 audio",
    ),
    "trill_inner": dict(
        name="TRILL Inner Ethernet Frame",
        transport="Original Ethernet frame inside TRILL encapsulation",
        header_bytes=6,
        fields={
            "Hop Count":   "6b  decremented per RBridge — frame dropped at 0",
            "Egress RB":   "16b  egress RBridge nickname (must be reachable in IS-IS topology)",
            "Ingress RB":  "16b  ingress RBridge nickname (this RBridge's nickname)",
            "Inner Dst":   "6B  original destination MAC (preserved inside TRILL)",
            "Inner Src":   "6B  original source MAC",
            "Inner EtherType":"2B  original EtherType of the encapsulated frame",
            "Payload":     "variable  original frame payload",
            "CAUTION":     "Egress RB nickname 0xFFFF = unknown unicast flood — IS-IS must converge before forwarding",
        },
        applications="TRILL multi-path L2 fabric — data centre Ethernet without STP blocking",
    ),
    "isis_pdu": dict(
        name="IS-IS PDU (for TRILL control plane)",
        transport="IS-IS link-state routing directly over Ethernet",
        header_bytes=3,
        fields={
            "NLPID":       "1B  0x83=IS-IS",
            "Header Length":"1B  fixed header portion length",
            "IS Version":  "1B  must be 1",
            "PDU Type":    "1B  15=L1-Hello 16=L2-Hello 17=P2P-Hello 18=L1-LSP 20=L2-LSP 24=L1-CSNP 25=L2-CSNP",
            "Version":     "1B  must be 1",
            "MaxAreaAddr": "1B  0=3 areas max",
            "System ID":   "6B  RBridge system ID (usually derived from MAC)",
            "TLVs":        "variable  1=AreaAddr 2=ISReach 6=ISNeighbors 22=ExtISReach 135=ExtIPReach 137=Hostname 141=MT-ISReach 228=NicknamePri 229=Nickname 232=VLANsEnabled",
            "Auth TLV":    "optional  TLV type=10 SubType=3 HMAC-SHA256 authentication",
            "CAUTION":     "IS-IS authentication must be configured — unauthenticated IS-IS = rogue RBridge injection",
        },
        applications="TRILL control plane — RBridge hello/LSP exchange for nickname and topology distribution",
    ),
    "avb_stream": dict(
        name="AVB Stream Reservation (FQTSS — 802.1Qav)",
        transport="Credit-based shaper stream descriptor",
        header_bytes=8,
        fields={
            "StreamID":      "8B  Talker MAC(6B)+UniqueID(2B) — globally identifies stream",
            "Priority":      "3b  802.1Q priority class (5=A 4=B for AVB)",
            "MaxIntervalFrames":"2B  max frames per class measurement interval",
            "MaxFrameSize":  "2B  max SDU size including all headers in bytes",
            "CAUTION":       "StreamID must be globally unique — duplicate = stream rejection; UniqueID assigned by talker application",
        },
        applications="AVB/TSN audio/video stream reservation — coordinate shaper across switches",
    ),
    "tsn_gcl": dict(
        name="TSN Gate Control List Entry (IEEE 802.1Qbv)",
        transport="Time-Aware Shaper gate schedule",
        header_bytes=10,
        fields={
            "GateState":    "1B  8-bit field, each bit=gate open/close for queues 0-7 (1=open 0=closed)",
            "TimeInterval": "4B  duration of this GCL entry in nanoseconds",
            "BaseTime":     "10B  PTP-synchronised start time: seconds(6B)+nanoseconds(4B)",
            "CycleTime":    "8B  Numerator(4B)/Denominator(4B) Hz fraction",
            "CycleTimeExt": "4B  extension time to complete current frame at end of cycle",
            "ConfigChange": "1B  applies new GCL atomically — only set when not mid-cycle",
            "CAUTION":      "All switches must be PTP-synchronised to nanosecond accuracy — clock drift = guard band violations and dropped frames",
        },
        applications="Deterministic latency: industrial robot motion · in-vehicle Ethernet (802.1Qbv) · pro AV",
    ),
    "msrp_attr": dict(
        name="MSRP Attribute (Talker-Advertise / Listener)",
        transport="Multiple Stream Registration Protocol attribute",
        header_bytes=4,
        fields={
            "Attr Type":      "1B  0x01=Talker-Advertise 0x02=Talker-Failed 0x03=Listener 0x04=Domain",
            "MRP Event":      "3b  0=New 1=JoinIn 2=In 3=JoinMt 4=Mt 5=Lv",
            "StreamID":       "8B  MAC(6B)+UniqueID(2B)",
            "DataFrameParams":"4B  DestAddr(6B)+VLAN+Prio+RankInterval",
            "Accumulated Latency":"4B  µs  end-to-end latency accumulation",
            "FailureInfo":    "1B+6B (Talker-Failed only) BridgeID+FailureCode",
            "CAUTION":        "Listener must register before data flows — talker-only without listener = bandwidth reserved but unused (wasteful)",
        },
        applications="AVB/TSN stream bandwidth reservation — coordinate talker and listener path",
    ),
    "ecp_vdp": dict(
        name="ECP VDP (VSI Discovery Protocol — IEEE 802.1Qbg)",
        transport="Edge Control Protocol — hypervisor VM port assignment",
        header_bytes=4,
        fields={
            "Subtype":     "2B  0x0001=VDP",
            "Sequence":    "2B  monotonic ACK correlation",
            "Op":          "4b  0=Request 1=ACK",
            "Response":    "4b  0=Success 1=InvalidFormat 2=Busy 3=ResourcesExhausted",
            "VSI Type":    "4B  VSI type identifier (UUID-based)",
            "VSI Type Ver":"1B  VSI type version",
            "VSI ID Format":"1B  1=IPv4 2=IPv6 3=local 4=UUID",
            "VSI ID":      "16B  UUID identifying this VSI instance",
            "Filter Info": "variable  VLAN/Group filter for this VSI",
            "CAUTION":     "VSI ID must be unique per VM instance — duplicate UUID = incorrect port assignment",
        },
        applications="Hypervisor VEPA mode — 802.1BR virtual port assignment for VM NICs",
    ),
    "nsh_payload": dict(
        name="NSH Service Chain Payload",
        transport="Network Service Header — SFC chaining",
        header_bytes=8,
        fields={
            "Ver":          "2b  must be 0",
            "O":            "1b  OAM — frame is OAM not data",
            "TTL":          "6b  decremented per service function — drop at 0",
            "Length":       "6b  header length in 4-byte words",
            "MD-Type":      "4b  1=Fixed-Length(4×32b) 2=Variable-Length(TLVs)",
            "NextProto":    "4b  1=IPv4 2=IPv6 3=Ethernet 4=NSH 5=MPLS",
            "SPI":          "24b  Service Path Identifier — identifies the service chain",
            "SI":           "8b  Service Index — decremented per function hop",
            "Context Headers":"16B (MD-Type=1) 4×32b mandatory context fields",
            "CAUTION":      "TTL must be ≥ number of service functions — TTL=0 at any hop = silent drop with no error",
        },
        applications="SFC: Firewall→IDS→LB→NAT ordered function chaining without topology change",
    ),
    "macsec_payload": dict(
        name="MACSec Encrypted Payload",
        transport="IEEE 802.1AE per-hop Ethernet encryption",
        header_bytes=8,
        fields={
            "TCI":     "1B  V(1b)=0 + ES(1b) + SC(1b) + SCB(1b) + E(1b)=encryption + C(1b)=changed + Ver(2b)=0",
            "AN":      "2b  Association Number 0-3 (identifies active SAK key)",
            "SL":      "6b  Short Length 0=full frame 1-60=short frame actual length",
            "PN":      "4B  Packet Number — must be strictly increasing per SA (replay window check)",
            "SCI":     "8B  Secure Channel ID = Src-MAC(6B)+Port(2B) — only if SC bit=1",
            "Payload": "variable  GCM-AES encrypted original Ethernet payload",
            "ICV":     "16B  GCM-AES authentication tag (integrity check value)",
            "CAUTION": "PN rollover at 0xFFFFFFFF terminates SA — must rekey via MKA (EAPOL-Key) before 0xC0000000 to avoid SA expiry during traffic",
        },
        applications="Data centre inter-switch link encryption · WAN MACsec · 802.1X MACsec session",
    ),
    "hyperscsi_pdu": dict(
        name="HyperSCSI PDU (deprecated)",
        transport="HyperSCSI SCSI command over Ethernet — obsolete",
        header_bytes=4,
        fields={
            "Version":   "1B  0",
            "Type":      "1B  0=Command 1=Data 2=Response 3=Sense",
            "Sequence":  "2B",
            "Initiator": "1B",
            "CDB Len":   "1B",
            "CDB":       "variable  SCSI Command Descriptor Block",
            "Data":      "variable  payload",
            "CAUTION":   "Deprecated — no security, no auth; use iSCSI (TCP port 3260) or FCoE instead",
        },
    ),
    "iser_pdu": dict(
        name="iSER PDU (iSCSI Extensions for RDMA)",
        transport="iSCSI over RDMA — zero-copy block I/O",
        header_bytes=28,
        fields={
            "Flags":      "1B  W(bit7)=Write-STag-Valid  R(bit6)=Read-STag-Valid",
            "Reserved":   "1B",
            "Write STag": "4B  RDMA Steering Tag for target-to-initiator Write",
            "Write TO":   "8B  Tagged Offset for iSER write",
            "Read STag":  "4B  RDMA Steering Tag for Read",
            "Read TO":    "8B  Tagged Offset for Read",
            "iSCSI BHS":  "48B  standard iSCSI Basic Header Segment (same as iSCSI/TCP)",
            "CAUTION":    "Both STag and TO must be registered via RDMA BIND before use — unregistered STag = remote access violation and QP error",
        },
        applications="High-performance iSCSI — eliminates kernel copy overhead via RDMA zero-copy path",
    ),
    "fcoe_ip": dict(
        name="IP over Fibre Channel (FC-BB-5)",
        transport="IP datagrams encapsulated in FC frames",
        header_bytes=4,
        fields={
            "TYPE":    "1B  0x20=IP-over-FC",
            "IP HDR":  "20B  standard IPv4 header",
            "Payload": "variable  IP payload",
            "CAUTION": "Rarely used — FCoE normally carries FCP SCSI, not raw IP",
        },
    ),
    "fip_linkserv": dict(
        name="FIP Link Service (FLOGI/FDISC/LOGO over FIP)",
        transport="FCoE fabric login carried over FIP",
        header_bytes=4,
        fields={
            "Op":         "2B  0x0002=Link-Service",
            "Subcode":    "1B  0x01=FLOGI 0x02=FDISC 0x03=LOGO 0x04=FLOGI-LS_ACC 0x05=FLOGI-LS_RJT",
            "Desc ListLen":"2B",
            "Local MAC":  "6B  ENode MAC address",
            "FC-MAP":     "3B  0x0E:FC:00 default",
            "Switch Name":"8B  FCF WWN (in LS_ACC)",
            "N_Port ID":  "3B  assigned by FCF (in LS_ACC)",
            "CAUTION":    "FLOGI must be sent to FCF-MAC not broadcast — use FIP advertisement MAC",
        },
        applications="FCoE fabric login — derives FPMA (Fabric Provided MAC Address)",
    ),
    "fip_ctrl": dict(
        name="FIP Control (Keep-Alive / Clear-Virtual-Links)",
        transport="FIP session maintenance",
        header_bytes=4,
        fields={
            "Op":       "2B  0x0003=Control",
            "Subcode":  "1B  0x01=Keep-Alive 0x02=Clear-Virtual-Links",
            "Desc Len": "2B",
            "Local MAC":"6B  ENode MAC",
            "CAUTION":  "FKA_ADV_Period default 8s — no keep-alive within 3×period = FCF drops virtual link",
        },
    ),
    "aoe_macmask": dict(
        name="AoE MAC Mask List (access control)",
        transport="AoE target MAC address ACL",
        header_bytes=8,
        fields={
            "CMD":      "1B  0x02=MAC-Mask-List",
            "MCmd":     "1B  0=Read 1=Edit-ACL",
            "MCount":   "2B  number of directives",
            "Directives":"variable  4B each: Reserved(1B)+Cmd(1B)+MAC(6B) Cmd: 0=NoDirective 1=Add 2=Delete 255=DeleteAll",
            "CAUTION":  "Empty ACL = all MACs allowed — explicitly add allowed MACs before deploying to production",
        },
    ),
    "iscsi_r2t": dict(
        name="iSCSI R2T (Ready to Transfer — write flow control)",
        transport="iSCSI target-driven write pacing",
        header_bytes=48,
        fields={
            "Opcode":       "1B  0x31=R2T",
            "Flags":        "1B  F=Final",
            "DataSegLen":   "3B  0 (no data segment in R2T)",
            "LUN":          "8B",
            "ITT":          "4B  matches initiator command ITT",
            "TTT":          "4B  Target Transfer Tag — must be echoed in Data-Out",
            "StatSN":       "4B  target status sequence number",
            "ExpCmdSN":     "4B",
            "BufferOffset": "4B  byte offset into write buffer for this R2T",
            "DesiredDataLen":"4B  bytes target wants in this Data-Out burst",
            "CAUTION":      "Initiator must not send more than DesiredDataLen bytes — overflow = target abort",
        },
        applications="iSCSI write flow control — target paces write data in bursts",
    ),
    "oui_ext_payload": dict(
        name="OUI-Extended Payload (IEEE 802 0x88B7)",
        transport="Vendor/org-specific payload under registered OUI",
        header_bytes=5,
        fields={
            "OUI":           "3B  IEEE-registered Organisation Unique Identifier",
            "Ext EtherType": "2B  sub-protocol (vendor-defined)",
            "Payload":       "variable  organisation-specific frame content",
            "CAUTION":       "OUI must be your registered IEEE OUI — using another org's OUI violates IEEE 802 policy",
        },
    ),
    "mih_pdu": dict(
        name="MIH PDU (IEEE 802.21 Media Independent Handover)",
        transport="Vertical handover signalling",
        header_bytes=6,
        fields={
            "Version":     "4b  must be 1",
            "AID":         "12b  Action ID — identifies MIH service and operation",
            "OPCode":      "4b  0=Indication 1=Request 2=Response 3=Push",
            "TransactionID":"12b  correlation ID",
            "PayloadLen":  "16b  payload byte count",
            "Payload":     "variable  MIH events/commands/information elements",
            "CAUTION":     "MIH requires pre-configured MIIS server address — missing server = handover decision failure",
        },
        applications="IEEE 802.21 — seamless vertical handover between 802.3/802.11/3GPP/WiMAX",
    ),
    # ── Legacy passthrough handlers (raw/simple) ──────────────────────────────
    "raw_idp":   dict(name="XNS Raw IDP Datagram",        transport="raw passthrough", header_bytes=0, fields={"Data":"variable XNS raw payload"}),
    "raw_ipx":   dict(name="Novell IPX Raw Datagram",     transport="raw passthrough", header_bytes=0, fields={"Data":"variable IPX raw payload"}),
    "netbios":   dict(name="NetBIOS over IPX (type-20)",  transport="broadcast propagation", header_bytes=0, fields={"Data":"NetBIOS datagram payload"}),
    "snmp":      dict(name="SNMP over DDP (AppleTalk)",   transport="SNMP management", header_bytes=0, fields={"Data":"SNMPv1/v2c PDU"}),
    "aurp":      dict(name="AURP (AppleTalk Update Routing)", transport="WAN routing", header_bytes=4, fields={"ConnectionID":"2B","Sequence":"2B","Data":"variable AURP tuples"}),
    "pup_error": dict(name="Xerox PUP Error",             transport="error notification", header_bytes=4, fields={"Error Code":"2B","Error Param":"2B","Original":"first 22B of offending PUP"}),
    "pup_echo":  dict(name="Xerox PUP Echo/Echo Reply",   transport="reachability test", header_bytes=2, fields={"Type":"2B 130=Request 131=Reply","Data":"variable echoed data"}),
    # ── Additional L4 handlers for new EtherTypes ─────────────────────────────
    "pbb_payload": dict(
        name="PBB Customer Frame (MAC-in-MAC payload)",
        transport="Provider Backbone Bridging inner customer frame",
        header_bytes=14,
        fields={"Inner Dst MAC":"6B customer destination MAC",
                "Inner Src MAC":"6B customer source MAC",
                "Inner EtherType":"2B customer protocol (0x0800=IPv4 etc.)",
                "Customer Payload":"variable original customer Ethernet payload",
                "CAUTION":"I-SID collision causes cross-customer frame delivery — unique I-SID per service mandatory"},
    ),
    "avtp_aaf": dict(
        name="AVTP AAF (Audio — IEEE 1722)",
        transport="AVTP Audio Format — professional PCM/AES3",
        header_bytes=24,
        fields={"Format":"1B 0x02=INT16 0x03=INT24 0x04=INT32 0x05=FLOAT32 0x09=AES3",
                "NSR":"4b nominal sample rate 0x03=44.1kHz 0x04=48kHz 0x05=88.2kHz 0x06=96kHz 0x07=192kHz",
                "Channels":"10b number of audio channels 1-1024",
                "Bit Depth":"8b 0=Padded 16=16b 24=24b 32=32b",
                "Evt":"4b 0=normal 1=mute 2=pullup 3=pulldown",
                "SP":"1b sparse timestamp — 1=not every frame has timestamp",
                "Payload":"variable interleaved PCM samples (channels × samples × bytes/sample)",
                "CAUTION":"Channels × BitDepth × SampleRate must fit in Ethernet MTU — use VLAN with QoS for priority"},
        applications="AES67/AVnu/Milan audio networking",
    ),
    "avtp_cvf": dict(
        name="AVTP CVF (Compressed Video — IEEE 1722)",
        transport="AVTP Compressed Video Format — H.264/MJPEG/JPEG2000",
        header_bytes=28,
        fields={"Format":"1B 0=MJpeg 1=H264 2=JPEG2000",
                "Format Subtype":"1B codec-specific",
                "PTD":"1b PTS discontinuity",
                "M":"1b RTP marker (last fragment of frame)",
                "Evt":"4b",
                "H264 Timestamp":"4B (H264) PTP timestamp of video frame",
                "NAL Header":"1B H264 NAL unit type (1=slice 5=IDR 7=SPS 8=PPS)",
                "Payload":"variable NAL unit or JPEG data",
                "CAUTION":"IDR frame (NAL type=5) must precede all P/B frames — missing IDR = decoder error on stream join"},
        applications="Professional video over Ethernet",
    ),
    "avtp_crf": dict(
        name="AVTP CRF (Clock Reference — IEEE 1722)",
        transport="AVTP media clock reference distribution",
        header_bytes=24,
        fields={"Type":"1B 0=User 1=AudioSample 2=VideoFrame 3=VideoLine 4=MachineCycle",
                "Pull":"3b clock multiplier/divisor",
                "Base Freq":"29b base frequency in Hz (e.g. 48000 for audio)",
                "CRF Data Count":"4B number of timestamps in payload",
                "CRF Timestamps":"variable 8B PTP timestamps × count",
                "CAUTION":"Base frequency must match across all listeners — mismatch causes clock drift and AV sync failure"},
    ),
    "avtp_iec61883": dict(
        name="AVTP IEC 61883 (FireWire A/V over AVTP)",
        transport="IEC 61883 audio/video over IEEE 1722",
        header_bytes=24,
        fields={"CIP Qi":"2b 0=IEC61883-1","CIP FN":"2b","CIP QPC":"3b","CIP SPH":"1b",
                "CIP DBC":"1B data block counter","CIP Fmt":"6b 0x10=61883-4(DV) 0x20=61883-6(audio) 0x22=61883-8(MIDI)",
                "CIP FDF":"3B format-dependent field","Payload":"variable A/V data blocks",
                "CAUTION":"DBC must be monotonically increasing — reset causes audio glitch on receiver"},
    ),
    "avtp_ctrl": dict(
        name="AVTP Control Message (IEEE 1722)",
        transport="AVTP control and management",
        header_bytes=24,
        fields={"Control Data Length":"2B","Stream Data Length":"2B",
                "Control Data":"variable AVTP control payload",
                "CAUTION":"Control messages must not use reserved subtypes — reserved subtype = undefined behaviour"},
    ),
    "bfd_control": dict(
        name="BFD Control Packet (RFC 5880)",
        transport="BFD session control — fast failure detection",
        header_bytes=24,
        fields={"Version":"3b=1","Diag":"5b diagnostic code",
                "Sta":"2b 0=AdminDown 1=Down 2=Init 3=Up",
                "P":"1b Poll","F":"1b Final","C":"1b CtrlPlaneIndependent","A":"1b Auth","D":"1b Demand","M":"1b=0",
                "Detect Mult":"1B timeout multiplier (e.g. 3)",
                "Length":"1B 24 minimum","My Discrim":"4B local discriminator (non-zero)",
                "Your Discrim":"4B peer discriminator (0 during Init)",
                "Desired Min TX Interval":"4B µs desired TX rate (e.g. 50000=50ms)",
                "Required Min RX Interval":"4B µs minimum RX rate",
                "Required Min Echo Interval":"4B µs echo interval (0=no echo)",
                "CAUTION":"Your Discriminator=0 only in Down state — sending 0 in Up state terminates session"},
        applications="Fast link failure detection < 50ms · ECMP/LAG failover · L2VPN path monitoring",
    ),
    "ncsi_cmd": dict(
        name="NC-SI Command/Response",
        transport="NIC sideband management",
        header_bytes=8,
        fields={"MC ID":"1B 0=primary management controller",
                "Hdr Rev":"1B must be 0x01",
                "IID":"1B instance ID for response correlation 0-15",
                "Type":"1B command type (see NC-SI spec)",
                "Channel":"1B NIC channel 0-3",
                "Payload Len":"2B payload byte count",
                "Payload":"variable command-specific data",
                "Checksum":"4B XOR over all previous bytes or 0x00000000",
                "CAUTION":"IID must be unique per outstanding request — reuse causes response routing to wrong request"},
        applications="BMC network passthrough · NIC firmware update · link status monitoring",
    ),
    "gre_inner_eth": dict(
        name="GRE Inner Ethernet Frame",
        transport="Ethernet-in-GRE L2VPN payload",
        header_bytes=14,
        fields={"Inner Dst MAC":"6B destination MAC inside tunnel",
                "Inner Src MAC":"6B source MAC inside tunnel",
                "Inner EtherType":"2B 0x0800=IPv4 etc.",
                "Inner Payload":"variable — original frame payload",
                "CAUTION":"ARP broadcasts inside GRE flood to all tunnel endpoints — use proxy ARP or limit broadcast domains"},
    ),
    "gre_inner_fr": dict(
        name="GRE Inner Frame Relay",
        transport="Frame Relay PVC in GRE",
        header_bytes=4,
        fields={"DLCI High":"6b bits 15-10 of DLCI","C/R":"1b","EA0":"1b=0",
                "DLCI Low":"4b bits 9-6","FECN":"1b","BECN":"1b","DE":"1b","EA1":"1b=1",
                "Information":"variable frame relay payload",
                "FCS":"2B CRC-16-CCITT",
                "CAUTION":"DLCI 0 is reserved for LMI signalling — data frames must use DLCI 16-991"},
    ),
    "gre_ctrl_msg": dict(
        name="GRE Control Message (RFC 8157)",
        transport="GRE tunnel OAM",
        header_bytes=4,
        fields={"Control Type":"2B 0x0001=Keepalive-Req 0x0002=Keepalive-Reply 0x0003=Error 0x0004=BFD-Discrim",
                "Transaction ID":"2B request/response correlation",
                "Error Code":"2B (Error type) — error reason",
                "BFD Discrim":"4B (BFD-Discrim type) — local discriminator",
                "CAUTION":"Keepalive-Req expects Keepalive-Reply within hold timer — missing reply = tunnel teardown"},
    ),
    "vjcomp_pdu": dict(
        name="Van Jacobson Compressed TCP/IP",
        transport="VJ header compression for serial/PPP links",
        header_bytes=1,
        fields={"Type":"1B 0x45=Uncompressed 0x70-0x7F=Compressed",
                "Connection ID":"1B (compressed) — index into compression state table",
                "Delta Flags":"1B change mask indicating which header fields changed",
                "Urgent Ptr":"optional 2B (if changed)","Ack":"optional 2B/4B (if changed)",
                "Seq Num":"optional 4B (if changed)","IP ID Delta":"optional 2B",
                "Checksum":"2B","Data":"variable — TCP payload",
                "CAUTION":"Compression state must be flushed (uncompressed) after any packet loss — desync causes all subsequent packets to fail"},
    ),
    "ppp_lcp": dict(
        name="PPP LCP (Link Control Protocol)",
        transport="PPP link establishment and configuration",
        header_bytes=4,
        fields={"Code":"1B 1=Configure-Req 2=Configure-Ack 3=Configure-Nak 4=Configure-Reject 5=Terminate-Req 6=Terminate-Ack 7=Code-Reject 8=Protocol-Reject 9=Echo-Req 10=Echo-Reply 11=Discard-Req",
                "ID":"1B request/reply correlation",
                "Length":"2B total LCP message length",
                "Options":"variable TLV options: 1=MRU(2B) 3=Auth-Protocol(2B+) 4=Quality-Protocol 5=Magic-Number(4B) 7=Protocol-Field-Compress 8=Addr-Ctrl-Compress",
                "MRU":"2B Maximum Receive Unit (default 1500)",
                "Magic Number":"4B random — detect looped-back links",
                "Auth Protocol":"2B 0xC023=PAP 0xC223=CHAP",
                "CAUTION":"Magic Number collision (both peers same random) indicates looped link — abort and regenerate"},
    ),
    "ppp_auth": dict(
        name="PPP PAP/CHAP Authentication",
        transport="PPP password or challenge authentication",
        header_bytes=4,
        fields={"Code":"1B PAP: 1=Auth-Req 2=Auth-Ack 3=Auth-Nak  CHAP: 1=Challenge 2=Response 3=Success 4=Failure",
                "ID":"1B","Length":"2B",
                "Peer-ID Length":"1B (PAP) username length",
                "Peer-ID":"variable (PAP) username in plaintext",
                "Passwd Length":"1B (PAP) password length",
                "Password":"variable (PAP) password in plaintext",
                "Value Size":"1B (CHAP) challenge/response length",
                "Value":"variable (CHAP) MD5/SHA hash of challenge+password",
                "Name":"variable peer identifier",
                "CAUTION":"PAP sends password in plaintext — use CHAP or EAP-TLS instead; CHAP uses MD5 which is broken for offline attacks"},
    ),
    "gsmp_msg": dict(
        name="GSMP Message",
        transport="General Switch Management Protocol command",
        header_bytes=8,
        fields={"Version":"4b=3","Message Type":"1B","Result":"1B 0=Success 1=Failure 2=Ignored",
                "Code":"1B failure reason","Port Session No":"1B",
                "Transaction ID":"4B",
                "Port":"4B target switch port",
                "Session Number":"4B per-adjacency session",
                "Payload":"variable type-specific data",
                "CAUTION":"No authentication — GSMP must be confined to management VLAN; never expose to untrusted hosts"},
    ),
    "mcap_msg": dict(
        name="MCAP Message",
        transport="Multicast channel allocation",
        header_bytes=8,
        fields={"Op":"1B 1=GetReq 2=GetResp 3=Setup 4=Delete",
                "Rpt Count":"1B repetition count",
                "Trans ID":"2B","Channel ID":"2B",
                "Timestamp":"8B 802.11 TSF time for channel start",
                "Duration":"2B channel duration in TUs (×1024µs)",
                "CAUTION":"Timestamp must be coordinated with 802.11 BSS TSF — wrong timestamp causes channel miss"},
    ),
    "lowpan_iphc": dict(
        name="6LoWPAN IPHC Compressed IPv6",
        transport="IPv6 header compression for low-power wireless",
        header_bytes=2,
        fields={"TF":"2b traffic class compression","NH":"1b next header compression",
                "HLIM":"2b hop limit compression 0=inline 1=1 2=64 3=255",
                "CID":"1b context identifier extension","SAC":"1b source addr compression",
                "SAM":"2b source addr mode 0=inline 1=64b 2=16b 3=from context",
                "M":"1b multicast compression","DAC":"1b destination addr compression",
                "DAM":"2b destination addr mode","Payload":"variable compressed fields",
                "CAUTION":"SAM/DAM context must be provisioned on all nodes — missing context = decompression failure and packet drop"},
    ),
    "lowpan_mesh": dict(
        name="6LoWPAN Mesh Header",
        transport="6LoWPAN multi-hop mesh routing",
        header_bytes=4,
        fields={"V":"1b 1=16b source addr","F":"1b 1=16b dest addr",
                "HopsLeft":"4b remaining hops (0=drop)",
                "Orig Addr":"2B or 8B mesh originator address",
                "Final Addr":"2B or 8B mesh final destination",
                "CAUTION":"HopsLeft must be > diameter of mesh network — too-small value causes premature discard"},
    ),
    "lowpan_frag": dict(
        name="6LoWPAN Fragmentation Header",
        transport="6LoWPAN IPv6 fragmentation",
        header_bytes=4,
        fields={"Type":"5b 0x18=first frag 0x1C=subsequent",
                "Datagram Size":"11b total reassembled datagram bytes",
                "Datagram Tag":"2B identifies fragment group (same across all fragments)",
                "Datagram Offset":"1B (subsequent frags only) byte offset ÷8",
                "Payload":"variable fragment data",
                "CAUTION":"Reassembly timer default 60s — fragment storm causes memory exhaustion in constrained devices"},
    ),
    "loopback_test": dict(
        name="Ethernet Loopback Test Pattern",
        transport="IEEE 802.3 loopback for cable qualification",
        header_bytes=4,
        fields={"Function":"2B 0x0001=Reply/Forward 0x0002=Reply-Only",
                "Reply Count":"2B remaining forward count before replying",
                "Test Data":"variable fill pattern for cable stress test (min 60B)",
                "CAUTION":"Loopback frames must not be forwarded to external ports — use dedicated VLAN or dedicated test port"},
    ),
    "frer_payload": dict(
        name="FRER Sequenced Frame Payload",
        transport="IEEE 802.1CB FRER inner payload",
        header_bytes=0,
        fields={"Inner EtherType":"2B original frame type","Payload":"variable original frame data",
                "CAUTION":"Sequence number window must be > max propagation delay difference between paths — narrow window = valid duplicate frames discarded"},
    ),
    "ipv4_inner": dict(
        name="Inner IPv4 (inside Q-in-Q tunnel)",
        transport="IPv4 datagram inside Q-in-Q double-tagged frame",
        header_bytes=20,
        fields={"Version+IHL":"1B","DSCP+ECN":"1B","Total Length":"2B",
                "ID":"2B","Flags+FragOffset":"2B","TTL":"1B","Protocol":"1B",
                "Checksum":"2B","Src IP":"4B","Dst IP":"4B","Payload":"variable",
                "CAUTION":"Inner IP TTL still decremented per hop — ensure TTL sufficient for path through provider network"},
    ),
    "ipv6_inner": dict(
        name="Inner IPv6 (inside Q-in-Q tunnel)",
        transport="IPv6 datagram inside Q-in-Q",
        header_bytes=40,
        fields={"Version+TC+Flow":"4B","Payload Len":"2B","Next Header":"1B","Hop Limit":"1B",
                "Src IPv6":"16B","Dst IPv6":"16B","Payload":"variable"},
    ),
    # ── Switch protocol L4 handlers ───────────────────────────────────────────
    "mac_ctrl_pause": dict(
        name="IEEE 802.3x Pause Frame",
        transport="MAC-level symmetric flow control",
        header_bytes=4,
        fields={
            "Opcode":        "2B  0x0001",
            "Pause Quanta":  "2B  0-65535  pause duration × 512 bit-times at link speed  (e.g. 65535 = max pause)",
            "Reserved":      "42B  padding to minimum 64B frame size",
            "CAUTION":       "Pause is symmetric — pauses the ENTIRE link including control traffic; prefer PFC (per-priority) for mixed workloads",
        },
        applications="Flow control on full-duplex Ethernet links — prevent receiver buffer overflow",
    ),
    "mac_ctrl_pfc": dict(
        name="IEEE 802.1Qbb PFC (Priority-based Flow Control)",
        transport="Per-priority flow control for lossless Ethernet",
        header_bytes=20,
        fields={
            "Opcode":           "2B  0x0101",
            "Priority Enable":  "2B  bitmask P0(b0)-P7(b7) — 1=pause this priority class",
            "Quanta P0":        "2B  pause duration for priority 0 × 512 bit-times",
            "Quanta P1":        "2B  priority 1",
            "Quanta P2":        "2B  priority 2",
            "Quanta P3":        "2B  priority 3  (used by FCoE — must be non-zero for lossless SAN)",
            "Quanta P4":        "2B  priority 4",
            "Quanta P5":        "2B  priority 5",
            "Quanta P6":        "2B  priority 6",
            "Quanta P7":        "2B  priority 7  (network control — never pause this in practice)",
            "CAUTION":          "Never pause priority 7 (network control) — LACP/STP/BFD PDUs use high priority; pausing them causes topology reconvergence",
        },
        applications="Lossless Ethernet for FCoE(P3)/RoCE(P3-5)/NVMe-oF — prevents frame drop in storage networks",
    ),
    "mac_ctrl_epon": dict(
        name="EPON MPCP Gate / Report (0x8808 opcode 0x0002/0x0003)",
        transport="Ethernet PON multi-point control",
        header_bytes=8,
        fields={
            "Opcode":       "2B  0x0002=Gate  0x0003=Report",
            "Timestamp":    "4B  MPCP timestamp in 16ns units (OLT clock reference)",
            "Grant Start":  "4B  (Gate) start time for ONU transmission grant",
            "Grant Len":    "2B  (Gate) grant length × 16ns",
            "Grant Count":  "1B  (Gate) number of grants in this PDU (1-4)",
            "Sync Time":    "2B  (Gate) guard band / laser on-time in 16ns units",
            "Report Bitmap":"1B  (Report) bitmask of queue sets being reported",
            "Queue Length": "2B per queue  (Report) bytes pending in each queue",
            "CAUTION":      "MPCP timestamp rollover at 2^32 × 16ns ≈ 68s — OLT and ONU must handle rollover consistently or grants become misaligned",
        },
    ),
    "lacp_actor_partner": dict(
        name="LACP Actor+Partner TLVs (IEEE 802.3ad)",
        transport="Link Aggregation Control Protocol PDU",
        header_bytes=110,
        fields={
            "Subtype":            "1B  0x01",
            "Version":            "1B  0x01",
            "Actor TLV Type":     "1B  0x01",
            "Actor TLV Length":   "1B  0x14",
            "Actor System Priority":"2B  lower=preferred  default 32768",
            "Actor System MAC":   "6B  actor (local) system MAC",
            "Actor Key":          "2B  aggregation key — must match across all ports in LAG",
            "Actor Port Priority":"2B  lower=active vs standby  default 32768",
            "Actor Port Number":  "2B  port identifier",
            "Actor State":        "1B  bits: LACP_Activity(0)+LACP_Timeout(1)+Aggregation(2)+Synchronization(3)+Collecting(4)+Distributing(5)+Defaulted(6)+Expired(7)",
            "Actor Reserved":     "3B  0x000000",
            "Partner TLV Type":   "1B  0x02",
            "Partner TLV Length": "1B  0x14",
            "Partner System Priority":"2B",
            "Partner System MAC": "6B",
            "Partner Key":        "2B",
            "Partner Port Priority":"2B",
            "Partner Port Number":"2B",
            "Partner State":      "1B  same bit layout as Actor State",
            "Partner Reserved":   "3B",
            "Collector TLV":      "1B=0x03  Len=0x10  MaxDelay(2B)+12B-padding",
            "Terminator TLV":     "2B  0x0000  + 50B padding to 128B",
            "CAUTION":            "Actor Key mismatch: ports with different admin keys cannot form LAG even with same MAC/speed — verify 'channel-group N mode active' uses same group N on both ends",
        },
        applications="IEEE 802.3ad / 802.1AX LAG — multi-vendor link aggregation up to 8 active ports",
    ),
    "lacp_marker": dict(
        name="LACP Marker PDU",
        transport="LACP marker for loopback and reorder detection",
        header_bytes=64,
        fields={
            "Subtype":         "1B  0x02",
            "Version":         "1B  0x01",
            "Marker TLV Type": "1B  0x01=MarkerInfo  0x02=MarkerResponse",
            "Marker TLV Len":  "1B  0x16",
            "Requester Port":  "2B  port ID of requestor",
            "Requester System":"6B  system MAC of requestor",
            "Requester Trans": "4B  transaction ID (echoed in Response)",
            "Reserved":        "2B",
            "Terminator TLV":  "2B  0x0000",
            "Padding":         "90B  to 128B total",
            "CAUTION":         "Marker is used to verify all frames from a port have been received before rebalancing — improper implementation causes out-of-order delivery during LAG rebalance",
        },
    ),
    "oam_pdu": dict(
        name="Ethernet OAM PDU (IEEE 802.3ah — EFM OAM)",
        transport="First/last mile Ethernet OAM",
        header_bytes=3,
        fields={
            "Subtype":      "1B  0x03",
            "Flags":        "2B  Link-Fault(b0)+Dying-Gasp(b1)+Critical-Event(b2)+Local-Evaluating(b6)+Local-Stable(b7)+Remote-Evaluating(b8)+Remote-Stable(b9)",
            "Code":         "1B  0x00=Info 0x01=EventNotif 0x02=UniqueEventNotif 0x03=LB-Control 0x04=VarRequest 0x05=VarResponse 0xFE=OrgSpecific",
            "TLV chain":    "variable  per-Code payload: Info=Local/Remote OAMPDU; EventNotif=error event TLVs; LB=Disable/Enable loopback",
            "Local Info TLV":"OAM_version(1B)+MaxPDU_size(2B)+Config(1B)+capabilities(2B)+OUI(3B)+Vendor(4B)",
            "Event TLV":    "Type=1=Symbol-Period 2=Frame-Period 3=Frame-Seconds  Timestamp(2B)+Window+Threshold+Errors+Total+RunningTotal+EventTotal",
            "CAUTION":      "Loopback-Enable (Code=0x03 Enable) puts remote OAM client into loopback — all frames forwarded back; accidentally left enabled causes complete link failure for normal traffic",
        },
        applications="DSL/fibre access OAM — link monitoring, loopback testing, event notification to NOC",
    ),
    "ossp_pdu": dict(
        name="OSSP PDU (Organisation Specific Slow Protocol)",
        transport="Vendor-specific extension to slow protocol",
        header_bytes=10,
        fields={
            "Subtype":   "1B  0x0A",
            "OUI":       "3B  organisation OUI (e.g. 0x00-12-0F=IEEE 0x00-00-0C=Cisco)",
            "ITU-T App": "2B  ITU-T application identifier (if OUI=ITU-T)",
            "Payload":   "variable  organisation-specific PDU content",
            "CAUTION":   "OSSP frames not recognised by peer are silently discarded — verify OUI registration before deployment",
        },
    ),
    "cdp_tlv": dict(
        name="CDP TLV (Cisco Discovery Protocol)",
        transport="CDP Type-Length-Value chain",
        header_bytes=4,
        fields={
            "TLV Type":      "2B  see CDP TLV type list in l2_builder",
            "TLV Length":    "2B  total TLV bytes including Type+Length",
            "TLV Value":     "variable  type-specific content",
            "DeviceID":      "hostname string or chassis serial number",
            "Addresses":     "Count(4B) + per-address: Protocol-Type(1B)+Protocol-Length(1B)+Protocol+Address-Length(2B)+Address",
            "Capabilities":  "4B bitmask: 0x01=Router 0x02=TB-Bridge 0x04=SR-Bridge 0x08=Switch 0x10=Host 0x20=IGMP 0x40=Repeater 0x80=Phone 0x100=Remote",
            "PowerAvailable":"4B  milliwatts available (PoE request/offer)",
            "CAUTION":       "CDP contains full device inventory — disable on untrusted ports; enable CDP only on inter-device uplinks",
        },
        applications="Network topology discovery · NMS polling · PoE negotiation · VoIP phone VLAN assignment",
    ),
    "vtp_pdu": dict(
        name="VTP PDU (Cisco VLAN Trunk Protocol)",
        transport="VTP VLAN database synchronisation",
        header_bytes=36,
        fields={
            "VTP Version":     "1B  0x01/0x02/0x03",
            "Code":            "1B  0x01=Summary 0x02=Subset 0x03=Request 0x04=Join",
            "Followers":       "1B  (Summary) Subset-Advertisement count to follow",
            "Domain Length":   "1B  VTP domain name byte count",
            "VTP Domain":      "32B  null-padded  — MUST match to accept advertisements",
            "Config Revision": "4B  higher always wins — increment resets entire VLAN DB",
            "Updater Identity":"4B  IPv4 of last updater",
            "Update Timestamp":"12B  YYMMDDHHMMSS ASCII",
            "MD5 Digest":      "16B  HMAC-MD5(domain+password+payload)  empty if no auth",
            "VLAN Info":       "(Subset) per VLAN: InfoLen+Status+VLANtype+NameLen+ISL-VLAN+MTU+802.10+Name",
            "VTPv3 Features":  "MST(0x0002) VLAN(0x0001) Private(0x0003) domains separate",
            "CAUTION":         "Config Revision attack: a switch with higher revision and same domain name immediately overwrites ALL VLANs on entire VTP domain — use VTPv3 + password or VTP transparent mode",
        },
        applications="Enterprise VLAN provisioning — single point of VLAN config propagated to all switches in domain",
    ),
    "dtp_pdu": dict(
        name="DTP PDU (Cisco Dynamic Trunking Protocol)",
        transport="Cisco auto-trunk negotiation",
        header_bytes=1,
        fields={
            "DTP Version":   "1B  0x01",
            "Domain TLV":    "Type=0x01  Len=4+34B  trunk domain name  (must match for trunking)",
            "Status TLV":    "Type=0x02  Len=4+1B  0x81=Trunk/Desirable 0x83=Trunk/Auto 0x84=Access/On 0x85=Access/Off",
            "Type TLV":      "Type=0x03  Len=4+1B  0x01=ISL 0x02=802.1Q 0x03=Negotiate 0x04=None",
            "Neighbor TLV":  "Type=0x04  Len=4+6B  neighbor MAC address",
            "CAUTION":       "Send DTP Desirable frame to switch port → port forms trunk → VLAN hopping possible; disable: 'switchport mode access' + 'switchport nonegotiate' on ALL access ports",
        },
        applications="Switch uplink auto-configuration — legacy use only; disable on all access/untrusted ports",
    ),
    "stp_bpdu": dict(
        name="STP / PVST+ Configuration BPDU (802.1D / Cisco)",
        transport="Spanning Tree Protocol bridge PDU",
        header_bytes=35,
        fields={
            "Protocol ID":    "2B  0x0000",
            "Version":        "1B  0x00=STP/PVST+",
            "BPDU Type":      "1B  0x00=Configuration  0x80=TCN (Topology Change Notification)",
            "Flags":          "1B  TC(b0)+TCA(b7)  — TCA=Topology Change Acknowledgement",
            "Root BID":       "8B  Priority(2B)+MAC(6B)  — 4b priority + 12b SystemID-Ext(VLAN for PVST+) + 6B MAC",
            "Root Path Cost": "4B  cumulative cost: 100M=19 1G=4 10G=2 100G=1",
            "Bridge BID":     "8B  sending bridge ID (same format as Root BID)",
            "Port ID":        "2B  4b priority(0x80=default) + 12b port number",
            "Message Age":    "2B  1/256-second units  hops×1s from root",
            "Max Age":        "2B  1/256-second units  default 5120(=20s)",
            "Hello Time":     "2B  1/256-second units  default 512(=2s)",
            "Forward Delay":  "2B  1/256-second units  default 3840(=15s)",
            "PVST+ VLAN TLV": "Type=0x00+Len=0x02+VLAN-ID(2B)  — PVST+ proprietary extension",
            "CAUTION":        "Root bridge election: any switch with lower bridge ID becomes root — rogue switch with priority 0 takes root and re-routes all traffic; protect with BPDU Guard + Root Guard",
        },
        applications="Layer 2 loop prevention — all Cisco switches; PVST+ per-VLAN load balancing",
    ),
    "rstp_bpdu": dict(
        name="RSTP / Rapid-PVST+ BPDU (802.1w / Cisco)",
        transport="Rapid Spanning Tree Protocol PDU",
        header_bytes=36,
        fields={
            "Protocol ID":    "2B  0x0000",
            "Version":        "1B  0x02=RSTP  (Rapid-PVST+ also 0x02 with SNAP PID 0x010B)",
            "BPDU Type":      "1B  0x02=RST BPDU",
            "Flags":          "1B  TC(b0)+Proposal(b1)+PortRole(b2-b3)+Learning(b4)+Forwarding(b5)+Agreement(b6)+TCA(b7)",
            "Port Role":      "bits 2-3: 00=Unknown 01=Alternate/Backup 10=Root 11=Designated",
            "Root BID":       "8B",
            "Root Path Cost": "4B",
            "Bridge BID":     "8B",
            "Port ID":        "2B",
            "Message Age":    "2B",
            "Max Age":        "2B",
            "Hello Time":     "2B",
            "Forward Delay":  "2B",
            "Version1 Length":"1B  0x00  (no Version1 info)",
            "PVST+ VLAN TLV": "VLAN-ID(2B) for Rapid-PVST+",
            "CAUTION":        "RSTP Proposal/Agreement handshake: Proposal from Designated port triggers Agreement from Root port — broken if any port does not support RSTP (mixed RSTP/STP = fallback to 30s convergence)",
        },
        applications="Sub-second convergence L2 — standard in all modern networks; Rapid-PVST+ per-VLAN variant",
    ),
    "udld_pdu": dict(
        name="Cisco UDLD PDU",
        transport="Unidirectional Link Detection",
        header_bytes=4,
        fields={
            "Version":         "4b  0x01",
            "Opcode":          "4b  0x01=Probe 0x02=Echo 0x03=Flush",
            "Flags":           "1B  RT(b0)=Recommended-Timeout(7s)  RSY(b1)=Resync",
            "Checksum":        "2B  CRC over entire UDLD PDU",
            "TLV DeviceID":    "Type=0x0001  device+port identifier string",
            "TLV PortID":      "Type=0x0002  sending port interface name",
            "TLV EchoList":    "Type=0x0003  list of neighbor Device+Port IDs heard (echoed back in Echo PDU)",
            "TLV MsgInterval": "Type=0x0004  1B  probe interval 7s(normal) 1s(aggressive)",
            "TLV TimeoutInt":  "Type=0x0005  1B  detection timeout (3× interval by default)",
            "TLV DeviceName":  "Type=0x0006  hostname string",
            "TLV SeqNumber":   "Type=0x0007  4B  monotonic sequence counter",
            "CAUTION":         "UDLD Aggressive mode: port goes err-disabled if no Echo received within timeout — do not use on links with asymmetric delays or protection-switching paths (DWDM)",
        },
        applications="Fibre uplink protection — detect TX-only or RX-only failure on GigE/10G fibre links",
    ),
    "pagp_tlvs": dict(
        name="PAgP TLVs (Cisco Port Aggregation Protocol)",
        transport="Cisco EtherChannel negotiation",
        header_bytes=6,
        fields={
            "SNAP Header":   "5B  0xAAAA03+0x00000C+0x0104",
            "Version":       "1B  0x01",
            "Flags":         "1B  0x00=Info 0x40=Flush",
            "Group Capability":"4B  bitmask of grouping capabilities",
            "Group IfIndex": "4B  interface index for aggregation grouping",
            "Port Name":     "variable  interface name string",
            "Device ID":     "6B  device MAC address",
            "Learn Method":  "1B  0=Src-MAC 1=Any",
            "CAUTION":       "PAgP is Cisco-proprietary — use LACP (IEEE 802.3ad) for multi-vendor LAG; PAgP Auto+Auto = no channel formed (both passive)",
        },
        applications="Cisco EtherChannel formation — same function as LACP but Cisco-only",
    ),
}

# ── Merge all into NON_IP_L4_REGISTRY ─────────────────────────────────────────
NON_IP_L4_REGISTRY.update(STORAGE_L4_REGISTRY)
