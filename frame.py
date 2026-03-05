import socket
import struct

def get(prompt, default=""):
    val = input(f"{prompt} [{default}]: ").strip()
    return val if val else default


def mac_bytes(mac_str):
    cleaned = mac_str.replace(":", "").replace("-", "").replace(" ", "").upper()
    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC: {mac_str}")
    return bytes.fromhex(cleaned)


def hex_bytes(hex_str, length):
    cleaned = hex_str.lower().replace("0x", "").replace(" ", "")
    if len(cleaned) % 2 != 0:
        cleaned = "0" + cleaned
    try:
        b = bytes.fromhex(cleaned)
        if len(b) > length:
            b = b[-length:]
        elif len(b) < length:
            b = b'\x00' * (length - len(b)) + b
        return b
    except ValueError:
        raise ValueError(f"Invalid hex for {length} bytes: {hex_str}")


def ip_bytes(ip_str):
    return socket.inet_aton(ip_str)


def print_detailed(name, frame, fields, ops_count, ops_desc):
    print(f"\n{'═' * 90}")
    print(f" {name.upper()}")
    print(f"{'═' * 90}")
    print(f"Total length : {len(frame)} bytes ({len(frame)*8} bits)")
    print(f"Main operations / types : {ops_count}")
    print(f"  → {ops_desc}\n")

    offset = 0
    for fname, flen, fbytes, human in fields:
        bits = flen * 8
        hexs = ' '.join(f"{x:02x}" for x in fbytes)
        line = f" {offset:3d}–{offset+flen-1:3d} | {fname:<28} | {flen:2d} B / {bits:3d} bit | {hexs}"
        if human:
            line += f"  → {human}"
        print(line)
        offset += flen

    print(f"{'─' * 90}")

    # Two styles of full hex dump
    hex_gapped = ' '.join(f"{b:02x}" for b in frame)
    hex_nogap  = ''.join(f"{b:02x}" for b in frame)

    print("Full hex dump (with gaps / spaces between bytes):")
    print(hex_gapped)
    print()

    print("Full hex dump (without gaps / continuous string):")
    print(hex_nogap)
    print()


# ────────────────────────────────────────────────
# ARP
# ────────────────────────────────────────────────

def create_arp():
    print("\n=== ARP (request or reply) ===")
    dst_mac   = get("Ethernet Destination MAC",   "ff:ff:ff:ff:ff:ff")
    src_mac   = get("Ethernet Source MAC",        "00:11:22:33:44:55")
    hw_type   = get("Hardware Type",              "1")
    proto_type= get("Protocol Type (hex)",        "0800")
    hw_len    = get("Hardware Addr Len",          "6")
    proto_len = get("Protocol Addr Len",          "4")
    opcode    = get("Opcode (1=request, 2=reply)", "1")
    sender_ha = get("Sender MAC",                 src_mac)
    sender_pa = get("Sender IP",                  "192.168.1.10")
    target_ha = get("Target MAC",                 "00:00:00:00:00:00")
    target_pa = get("Target IP",                  "192.168.1.100")

    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + bytes.fromhex("0806")

    arp_hdr = struct.pack("!HHBBH",
        int(hw_type),
        int(proto_type, 16),
        int(hw_len),
        int(proto_len),
        int(opcode)
    )

    arp_body = mac_bytes(sender_ha) + ip_bytes(sender_pa) + mac_bytes(target_ha) + ip_bytes(target_pa)

    frame = eth + arp_hdr + arp_body

    fields = [
        ("Destination MAC",      6, eth[0:6],       dst_mac),
        ("Source MAC",           6, eth[6:12],      src_mac),
        ("EtherType",            2, eth[12:14],     "0x0806 ARP"),
        ("Hardware Type",        2, arp_hdr[0:2],   hw_type),
        ("Protocol Type",        2, arp_hdr[2:4],   f"0x{proto_type.upper()}"),
        ("HW Address Length",    1, arp_hdr[4:5],   hw_len),
        ("Protocol Addr Length", 1, arp_hdr[5:6],   proto_len),
        ("Opcode",               2, arp_hdr[6:8],   "Request" if opcode=="1" else "Reply" if opcode=="2" else opcode),
        ("Sender MAC",           6, arp_body[0:6],  sender_ha),
        ("Sender IP",            4, arp_body[6:10], sender_pa),
        ("Target MAC",           6, arp_body[10:16],target_ha),
        ("Target IP",            4, arp_body[16:20],target_pa),
    ]

    return frame, fields, "ARP", 2, "1 = Request, 2 = Reply"


# ────────────────────────────────────────────────
# STP / RSTP
# ────────────────────────────────────────────────

def create_stp():
    print("\n=== STP / RSTP BPDU ===")
    dst_mac   = get("Destination MAC",            "01:80:c2:00:00:00")
    src_mac   = get("Source MAC (bridge)",        "00:11:22:33:44:55")
    version   = get("Version (0=STP, 2=RSTP)",    "2")
    bpdu_type = get("BPDU Type (00=config)",      "00")
    flags     = get("Flags (hex)",                "00")
    root_prio = get("Root Priority",              "32768")
    root_mac  = get("Root MAC",                   "00:00:00:00:00:00")
    path_cost = get("Root Path Cost",             "0")
    br_prio   = get("Bridge Priority",            "32768")
    br_mac    = get("Bridge MAC",                 src_mac)
    port_id   = get("Port ID (hex)",              "8001")
    msg_age   = get("Message Age (sec)",          "0")
    max_age   = get("Max Age (sec)",              "20")
    hello     = get("Hello Time (sec)",           "2")
    fwd_delay = get("Forward Delay (sec)",        "15")

    llc = bytes.fromhex("424203")

    root_id = struct.pack("!H", int(root_prio)) + mac_bytes(root_mac)
    br_id   = struct.pack("!H", int(br_prio))   + mac_bytes(br_mac)

    bpdu = (
        bytes.fromhex("0000") +
        hex_bytes(version,   1) +
        hex_bytes(bpdu_type, 1) +
        hex_bytes(flags,     1) +
        root_id +
        struct.pack("!I", int(path_cost)) +
        br_id +
        hex_bytes(port_id, 2) +
        struct.pack("!HHHH", int(msg_age)*256, int(max_age)*256, int(hello)*256, int(fwd_delay)*256)
    )

    len_field = struct.pack("!H", len(llc) + len(bpdu))
    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + len_field

    frame = eth + llc + bpdu

    fields = [
        ("Destination MAC",  6, eth[0:6],      dst_mac),
        ("Source MAC",       6, eth[6:12],     src_mac),
        ("Length (802.3)",   2, eth[12:14],    str(int.from_bytes(len_field,'big'))),
        ("LLC DSAP",         1, llc[0:1],      "0x42"),
        ("LLC SSAP",         1, llc[1:2],      "0x42"),
        ("LLC Control",      1, llc[2:3],      "0x03"),
        ("Version",          1, bpdu[2:3],     "STP" if version in ("0","00") else "RSTP" if version in ("2","02") else version),
        ("BPDU Type",        1, bpdu[3:4],     "Config" if bpdu_type in ("00","0") else bpdu_type),
        ("Flags",            1, bpdu[4:5],     f"0x{flags.upper()}"),
        ("Root ID",          8, bpdu[5:13],    f"prio {root_prio} / {root_mac}"),
        ("Path Cost",        4, bpdu[13:17],   path_cost),
        ("Bridge ID",        8, bpdu[17:25],   f"prio {br_prio} / {br_mac}"),
        ("Port ID",          2, bpdu[25:27],   port_id),
        ("Message Age",      2, bpdu[27:29],   f"{msg_age} s"),
        ("Max Age",          2, bpdu[29:31],   f"{max_age} s"),
        ("Hello Time",       2, bpdu[31:33],   f"{hello} s"),
        ("Forward Delay",    2, bpdu[33:35],   f"{fwd_delay} s"),
    ]

    return frame, fields, "STP/RSTP BPDU", 2, "STP: Config + TCN | RSTP: mostly Config + flags"


# ────────────────────────────────────────────────
# DTP
# ────────────────────────────────────────────────

def create_dtp():
    print("\n=== DTP (Dynamic Trunking Protocol) ===")
    dst_mac = get("Dst MAC", "01:00:0c:cc:cc:cc")
    src_mac = get("Src MAC", "00:11:22:33:44:55")
    mode    = get("Mode (02=desirable,03=auto,04=on,05=off)", "02")

    snap = bytes.fromhex("00000c 0104")

    payload = (
        b"\x01" +               # version
        b"\x03" +               # status
        b"\x01" +               # trunk type 802.1Q
        hex_bytes(mode, 1) +
        b"\x00" * 26
    )

    len_field = struct.pack("!H", len(snap) + len(payload))
    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + len_field

    frame = eth + snap + payload

    mode_name = {"02":"desirable", "03":"auto", "04":"on", "05":"off"}.get(mode, f"0x{mode}")

    fields = [
        ("Destination MAC",  6, eth[0:6],      dst_mac),
        ("Source MAC",       6, eth[6:12],     src_mac),
        ("Length",           2, eth[12:14],    str(int.from_bytes(len_field,'big'))),
        ("SNAP OUI",         3, snap[0:3],     "Cisco"),
        ("SNAP PID",         2, snap[3:5],     "DTP"),
        ("Version",          1, payload[0:1],  "1"),
        ("DTP Mode",         1, payload[4:5],  mode_name),
    ]

    return frame, fields, "DTP", 1, "One advertisement type"


# ────────────────────────────────────────────────
# PAgP
# ────────────────────────────────────────────────

def create_pagp():
    print("\n=== PAgP (Port Aggregation Protocol) ===")
    dst_mac = get("Dst MAC", "01:00:0c:cc:cc:cc")
    src_mac = get("Src MAC", "00:11:22:33:44:55")
    state   = get("Port State (hex)", "05")

    snap = bytes.fromhex("00000c 0104")

    payload = (
        b"\x01" +
        b"\x01" +
        bytes.fromhex("8001") +
        bytes.fromhex("00000001") +
        hex_bytes(state, 1) +
        b"\x00" * 25
    )

    len_field = struct.pack("!H", len(snap) + len(payload))
    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + len_field

    frame = eth + snap + payload

    fields = [
        ("Destination MAC",  6, eth[0:6],      dst_mac),
        ("Source MAC",       6, eth[6:12],     src_mac),
        ("Length",           2, eth[12:14],    str(int.from_bytes(len_field,'big'))),
        ("SNAP OUI",         3, snap[0:3],     "Cisco"),
        ("SNAP PID",         2, snap[3:5],     "PAgP"),
        ("Version",          1, payload[0:1],  "1"),
        ("Port State",       1, payload[8:9],  f"0x{state.upper()}"),
    ]

    return frame, fields, "PAgP", 1, "One advertisement type"


# ────────────────────────────────────────────────
# LACP
# ────────────────────────────────────────────────

def create_lacp():
    print("\n=== LACP (802.3ad / 802.1AX) ===")
    dst_mac     = get("Dst MAC",                "01:80:c2:00:00:02")
    src_mac     = get("Src MAC",                "00:11:22:33:44:55")
    actor_mac   = get("Actor System MAC",       src_mac)
    actor_key   = get("Actor Key (hex)",        "0001")
    actor_state = get("Actor State (hex)",      "3d")

    subtype  = b"\x01"
    version  = b"\x01"

    actor_tlv = (
        b"\x01\x14" +
        bytes.fromhex("8000") + mac_bytes(actor_mac) +
        hex_bytes(actor_key, 2) +
        bytes.fromhex("8000 8001") +
        hex_bytes(actor_state, 1) + b"\x00\x00\x00"
    )

    frame = (
        mac_bytes(dst_mac) + mac_bytes(src_mac) +
        bytes.fromhex("8809") + subtype + version +
        actor_tlv + b"\x00\x00"
    )

    fields = [
        ("Destination MAC",  6, frame[0:6],      dst_mac),
        ("Source MAC",       6, frame[6:12],     src_mac),
        ("EtherType",        2, frame[12:14],    "0x8809 (Slow Protocols)"),
        ("Subtype",          1, frame[14:15],    "LACP (1)"),
        ("Version",          1, frame[15:16],    "1"),
        ("Actor Information",len(actor_tlv), actor_tlv, f"System {actor_mac}  Key {actor_key}  State 0x{actor_state}"),
    ]

    return frame, fields, "LACP", 1, "One LACPDU type (TLVs)"


# ────────────────────────────────────────────────
# Main
# ────────────────────────────────────────────────

if __name__ == "__main__":
    print("Layer 2 frame creator (ARP, STP/RSTP, DTP, PAgP, LACP)")
    print("1 = ARP")
    print("2 = STP / RSTP BPDU")
    print("3 = DTP")
    print("4 = PAgP")
    print("5 = LACP")
    print()

    choice = get("Choose (1–5)", "1")

    creators = {
        "1": create_arp,
        "2": create_stp,
        "3": create_dtp,
        "4": create_pagp,
        "5": create_lacp,
    }

    if choice not in creators:
        print("Invalid choice.")
        exit(1)

    frame, fields, name, ops_count, ops_desc = creators[choice]()

    print_detailed(name, frame, fields, ops_count, ops_desc)

    if get("Save to file? (y/n)", "n").lower().startswith('y'):
        fn = get("Filename", "frame.bin")
        with open(fn, "wb") as f:
            f.write(frame)
        print(f"Saved → {fn}")
