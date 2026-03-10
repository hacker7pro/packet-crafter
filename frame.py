"""
Network Frame Builder
Layered input flow:  L1 (Physical) -> L2 (Data Link) -> L3 (Network) -> L4 (Transport/Control)
Every field is labelled with its layer in the final output table.
"""
import struct, zlib, socket

# ═══════════════════════════════════════════════════════════════════════════════
#  CONSTANTS & FORMATTING
# ═══════════════════════════════════════════════════════════════════════════════

W   = 118           # total print width
SEP = "═" * W
DIV = "─" * W
HDR = "─" * W

# Layer colour tags used in the field table
LAYER_TAG = {
    1: "[L1-PHY ]",
    2: "[L2-DL  ]",
    3: "[L3-NET ]",
    4: "[L4-CTRL]",
    0: "[TRAILER]",
}

# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITIES
# ═══════════════════════════════════════════════════════════════════════════════

def get(prompt, default=""):
    """Simple prompted input with default."""
    val = input(f"    {prompt} [{default}]: ").strip()
    return val if val else default

def get_hex(prompt, default_hex, byte_len=None):
    """Prompt for hex bytes, validate length."""
    while True:
        raw = input(f"    {prompt} [{default_hex}]: ").strip().lower()
        if not raw:
            print(f"      -> using default: {default_hex}")
            return bytes.fromhex(default_hex.replace(" ","").replace(":",""))
        try:
            cleaned = raw.replace(":","").replace("-","").replace(" ","")
            b = bytes.fromhex(cleaned)
            if byte_len and len(b) != byte_len:
                print(f"      -> need exactly {byte_len} bytes ({byte_len*2} hex chars)")
                continue
            return b
        except ValueError:
            print("      -> invalid hex, try again")

def mac_b(s):
    c = s.replace(":","").replace("-","").replace(" ","").upper()
    if len(c) != 12: raise ValueError(f"bad MAC: {s!r}")
    return bytes.fromhex(c)

def mac_s(b): return ':'.join(f'{x:02x}' for x in b)

def ip_b(s): return socket.inet_aton(s)

def hpad(s, n):
    c = s.lower().replace("0x","").replace(" ","")
    if len(c) % 2: c = "0"+c
    b = bytes.fromhex(c)
    if len(b) > n: b = b[-n:]
    elif len(b) < n: b = b'\x00'*(n-len(b)) + b
    return b

def crc32_eth(data):
    """Ethernet FCS: CRC-32 stored little-endian."""
    return (zlib.crc32(data) & 0xFFFFFFFF).to_bytes(4, 'little')

def crc16_ccitt(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
    return crc ^ 0xFFFF

def inet_cksum(data):
    """RFC 1071 one's-complement checksum."""
    if len(data) % 2: data += b'\x00'
    s = sum((data[i] << 8) + data[i+1] for i in range(0, len(data), 2))
    while s >> 16: s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF

def byte_escape(data):
    out = bytearray()
    for b in data:
        if b == 0x7E: out += b'\x7D\x5E'
        elif b == 0x7D: out += b'\x7D\x5D'
        else: out.append(b)
    return bytes(out)

def bit_stuff(data):
    bits=[]; ones=0
    for byte in data:
        for i in range(7,-1,-1):
            bit=(byte>>i)&1; bits.append(bit)
            if bit==1:
                ones+=1
                if ones==5: bits.append(0); ones=0
            else: ones=0
    res=bytearray()
    for i in range(0,len(bits),8):
        byt=0
        for j in range(8):
            byt=(byt<<1)|(bits[i+j] if i+j<len(bits) else 0)
        res.append(byt)
    return bytes(res)

def slip_enc(data):
    out=bytearray(b'\xC0')
    for b in data:
        if b==0xC0: out+=b'\xDB\xDC'
        elif b==0xDB: out+=b'\xDB\xDD'
        else: out.append(b)
    return bytes(out+b'\xC0')

# ═══════════════════════════════════════════════════════════════════════════════
#  PRINT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

def banner(title, subtitle=""):
    print(f"\n{SEP}")
    print(f"  {title}")
    if subtitle: print(f"  {subtitle}")
    print(SEP)

def section(title):
    print(f"\n  {'▌ '+title}")
    print(f"  {DIV}")

def print_frame_table(records):
    """
    records: list of dicts with keys:
        layer   : int  (1/2/3/4/0)
        name    : str  field name
        raw     : bytes
        note    : str  human-readable value / description
        user_val: str  the exact value the user entered (or auto)
    """
    print(f"\n{SEP}")
    print(f"  {'COMPLETE FRAME  –  FIELD-BY-FIELD TABLE':^{W-2}}")
    print(SEP)
    hdr = (f"  {'Byte':>6}  "
           f"{'Layer':<11}  "
           f"{'Field Name':<28}  "
           f"{'Size':>8}  "
           f"{'Hex Value':<30}  "
           f"{'User Input / Note'}")
    print(hdr)
    print(f"  {DIV}")

    offset = 0
    prev_layer = None
    for r in records:
        lay  = r['layer']
        name = r['name']
        raw  = r['raw']
        note = r.get('note', '')
        uval = r.get('user_val', '')

        # separator when layer changes
        if lay != prev_layer and prev_layer is not None:
            print(f"  {'·'*114}")
        prev_layer = lay

        sz   = len(raw)
        hexs = ' '.join(f'{b:02x}' for b in raw)
        # truncate hex display if very long
        if len(hexs) > 29: hexs = hexs[:27] + '..'

        # Build user-input annotation
        annotation = uval if uval else note
        # show note separately if both exist
        if uval and note and uval != note:
            annotation = f"{uval}  ({note})"

        tag = LAYER_TAG.get(lay, "        ")
        print(f"  {offset:5d}-{offset+sz-1:<4d}  "
              f"{tag}  "
              f"  {name:<28}  "
              f"{sz:3d}B/{sz*8:4d}b  "
              f"  {hexs:<30}  "
              f"  {annotation}")
        offset += sz

    print(f"  {DIV}")
    print(f"  {'Total':>5}: {offset} bytes  /  {offset*8} bits")
    print(SEP)

def print_final_hex(frame):
    print(f"\n{SEP}")
    print(f"  {'FINAL HEX OUTPUT  (no gaps)':^{W-2}}")
    print(DIV)
    hex_str = ''.join(f'{b:02x}' for b in frame)
    # print in rows of 32 bytes (64 hex chars) for readability
    for i in range(0, len(hex_str), 64):
        print(f"  {hex_str[i:i+64]}")
    print(DIV)
    print(f"  Total bytes : {len(frame)}")
    print(f"  Total bits  : {len(frame)*8}")
    print(SEP+"\n")

def ask_fcs_eth(fcs_input_bytes):
    """Ask user for Ethernet FCS preference, return (fcs_bytes, fcs_note)."""
    print(f"\n  ▌ ETHERNET FCS  (CRC-32 over {len(fcs_input_bytes)} bytes: Dst MAC → end of payload)")
    print(f"  {DIV}")
    ch = input("    1=Auto-calculate  2=Custom  [1]: ").strip() or '1'
    if ch == '2':
        fcs_hex = input("    Enter 8 hex digits: ").strip()
        try:
            fcs = bytes.fromhex(fcs_hex)
            if len(fcs) == 4: return fcs, "custom"
        except: pass
        print("    -> invalid, using auto")
    fcs = crc32_eth(fcs_input_bytes)
    return fcs, f"CRC-32 auto over {len(fcs_input_bytes)}B"

def ask_serial_crc(crc_input_bytes, crc_type, byte_order='big'):
    """Ask user for serial CRC preference."""
    print(f"\n  ▌ {crc_type}  (covers {len(crc_input_bytes)} bytes)")
    print(f"  {DIV}")
    ch = input(f"    1=Auto-calculate  2=Custom  [1]: ").strip() or '1'
    crc_val = crc16_ccitt(crc_input_bytes)
    fcs_auto = crc_val.to_bytes(2, byte_order)
    if ch == '2':
        fcs_hex = input("    Enter hex: ").strip()
        try:
            fcs = bytes.fromhex(fcs_hex)
            if len(fcs) == len(fcs_auto): return fcs, f"{crc_type} custom"
        except: pass
        print("    -> invalid, using auto")
    return fcs_auto, f"{crc_type} auto over {len(crc_input_bytes)}B"

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 1  –  PHYSICAL
# ═══════════════════════════════════════════════════════════════════════════════

def ask_layer1_eth():
    """Preamble + SFD for Ethernet."""
    section("LAYER 1 — Physical (Preamble + SFD)")
    preamble = get_hex("Preamble  7 bytes (14 hex)", "55555555555555", 7)
    sfd      = get_hex("SFD       1 byte  ( 2 hex)", "d5", 1)
    return preamble, sfd

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 2  –  DATA LINK
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  L2-A  Ethernet II / 802.3
# ──────────────────────────────────────────────────────────────────────────────

def ask_l2_ethernet(ethertype_hint="0800"):
    """Returns (dst_mac, src_mac, ethertype_bytes, llc_bytes, snap_bytes, variant_name)."""
    section("LAYER 2 — Ethernet / 802.3  (MAC Header)")

    print("    Variants:")
    print("      1 = Ethernet II        (EtherType >= 0x0600)")
    print("      2 = IEEE 802.3 Raw     (Length only)")
    print("      3 = IEEE 802.3 + LLC")
    print("      4 = IEEE 802.3 + LLC + SNAP")
    v = input("    Select variant [1]: ").strip() or '1'

    dst = get("Destination MAC", "ff:ff:ff:ff:ff:ff")
    src = get("Source MAC",      "00:11:22:33:44:55")

    llc_b = b''; snap_b = b''

    if v == '1':
        et = get_hex(f"EtherType (4 hex)", ethertype_hint, 2)
        variant_name = "Ethernet II"
        type_len_b = et
    elif v == '2':
        variant_name = "IEEE 802.3 Raw"
        type_len_b = None   # computed after payload known
    elif v == '3':
        variant_name = "IEEE 802.3 + LLC"
        dsap = get_hex("DSAP (2 hex)", "42", 1)
        ssap = get_hex("SSAP (2 hex)", "42", 1)
        ctl  = get_hex("Control (2 hex)", "03", 1)
        llc_b = dsap + ssap + ctl
        type_len_b = None
    elif v == '4':
        variant_name = "IEEE 802.3 + LLC + SNAP"
        dsap = get_hex("DSAP (2 hex, SNAP=aa)", "aa", 1)
        ssap = get_hex("SSAP (2 hex, SNAP=aa)", "aa", 1)
        ctl  = get_hex("Control (2 hex)", "03", 1)
        llc_b = dsap + ssap + ctl
        oui  = get_hex("SNAP OUI (6 hex)", "000000", 3)
        pid  = get_hex("SNAP Protocol ID (4 hex)", ethertype_hint, 2)
        snap_b = oui + pid
        type_len_b = None
    else:
        v = '1'
        et = get_hex(f"EtherType (4 hex)", ethertype_hint, 2)
        variant_name = "Ethernet II"
        type_len_b = et

    return mac_b(dst), mac_b(src), type_len_b, llc_b, snap_b, variant_name, dst, src, v

# ──────────────────────────────────────────────────────────────────────────────
#  L2-B  Serial / WAN protocols
# ──────────────────────────────────────────────────────────────────────────────

SERIAL_TYPES = {
    '1': "Raw",
    '2': "SLIP",
    '3': "PPP",
    '4': "HDLC",
    '5': "COBS (placeholder)",
    '6': "KISS",
    '7': "Modbus RTU",
    '8': "HDLC + Bit-Stuffing",
    '9': "ATM AAL5",
   '10': "Cisco HDLC",
}

def ask_l2_serial():
    section("LAYER 2 — Serial / WAN  (choose protocol)")
    for k,v in SERIAL_TYPES.items():
        print(f"      {k:>2} = {v}")
    ch = input("    Select [3]: ").strip() or '3'
    if ch not in SERIAL_TYPES: ch = '3'
    return ch, SERIAL_TYPES[ch]

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 3  –  NETWORK
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  ARP
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_arp():
    section("LAYER 3 — ARP")
    hw_type    = get("Hardware Type (1=Ethernet)", "1")
    proto_type = get("Protocol Type hex (0800=IPv4)", "0800")
    hw_len     = get("HW Address Length", "6")
    proto_len  = get("Protocol Address Length", "4")
    opcode     = get("Opcode  1=Request  2=Reply", "1")
    sender_ha  = get("Sender MAC", "00:11:22:33:44:55")
    sender_pa  = get("Sender IP",  "192.168.1.10")
    target_ha  = get("Target MAC", "00:00:00:00:00:00")
    target_pa  = get("Target IP",  "192.168.1.100")
    return (hw_type, proto_type, hw_len, proto_len, opcode,
            sender_ha, sender_pa, target_ha, target_pa)

def build_arp(inputs):
    hw_type, proto_type, hw_len, proto_len, opcode, sha, spa, tha, tpa = inputs
    hdr  = struct.pack("!HHBBH",
               int(hw_type), int(proto_type, 16),
               int(hw_len), int(proto_len), int(opcode))
    body = mac_b(sha) + ip_b(spa) + mac_b(tha) + ip_b(tpa)
    raw  = hdr + body
    op_s = "Request" if opcode=="1" else "Reply" if opcode=="2" else opcode
    fields = [
        {"layer":3,"name":"ARP HW Type",       "raw":hdr[0:2],   "user_val":hw_type,    "note":"1=Ethernet"},
        {"layer":3,"name":"ARP Protocol Type", "raw":hdr[2:4],   "user_val":proto_type, "note":"0800=IPv4"},
        {"layer":3,"name":"ARP HW Addr Len",   "raw":hdr[4:5],   "user_val":hw_len,     "note":"bytes"},
        {"layer":3,"name":"ARP Proto Addr Len","raw":hdr[5:6],   "user_val":proto_len,  "note":"bytes"},
        {"layer":3,"name":"ARP Opcode",        "raw":hdr[6:8],   "user_val":opcode,     "note":op_s},
        {"layer":3,"name":"ARP Sender MAC",    "raw":body[0:6],  "user_val":sha,        "note":""},
        {"layer":3,"name":"ARP Sender IP",     "raw":body[6:10], "user_val":spa,        "note":""},
        {"layer":3,"name":"ARP Target MAC",    "raw":body[10:16],"user_val":tha,        "note":""},
        {"layer":3,"name":"ARP Target IP",     "raw":body[16:20],"user_val":tpa,        "note":""},
    ]
    return raw, fields

# ──────────────────────────────────────────────────────────────────────────────
#  IPv4
# ──────────────────────────────────────────────────────────────────────────────

L3_PROTO_NAMES = {1:"ICMP", 6:"TCP", 17:"UDP", 41:"IPv6", 89:"OSPF", 47:"GRE"}

def ask_l3_ipv4():
    section("LAYER 3 — IPv4")
    src_ip  = get("Source IP",                  "192.168.1.10")
    dst_ip  = get("Destination IP",             "192.168.1.20")
    ttl     = get("TTL",                        "64")
    ip_id   = get("Identification (decimal)",   "4660")
    dscp    = get("DSCP/ECN (decimal, usu. 0)", "0")
    df      = get("DF flag? (y/n)",             "y")

    print("    L4 protocol inside IPv4:")
    print("      1=ICMP   6=TCP   17=UDP   [other: enter number]")
    proto_raw = get("Protocol number", "1")
    proto_num = int(proto_raw)

    return src_ip, dst_ip, int(ttl), int(ip_id), int(dscp), df.lower().startswith('y'), proto_num

def build_ipv4(l4_payload, src_ip, dst_ip, ttl, ip_id, dscp, df, proto_num):
    flags_frag = 0x4000 if df else 0x0000
    ver_ihl    = (4 << 4) | 5
    tot_len    = 20 + len(l4_payload)
    hdr0 = struct.pack("!BBHHHBBH4s4s",
               ver_ihl, dscp, tot_len, ip_id, flags_frag,
               ttl, proto_num, 0, ip_b(src_ip), ip_b(dst_ip))
    ck = inet_cksum(hdr0)
    hdr = struct.pack("!BBHHHBBH4s4s",
               ver_ihl, dscp, tot_len, ip_id, flags_frag,
               ttl, proto_num, ck, ip_b(src_ip), ip_b(dst_ip))

    flag_s = ("DF" if flags_frag & 0x4000 else "") + ("MF" if flags_frag & 0x2000 else "")
    proto_s = L3_PROTO_NAMES.get(proto_num, str(proto_num))

    fields = [
        {"layer":3,"name":"IP Version + IHL",    "raw":hdr[0:1],  "user_val":"4 / 5",    "note":"IPv4, 20B header"},
        {"layer":3,"name":"IP DSCP/ECN",          "raw":hdr[1:2],  "user_val":str(dscp),  "note":""},
        {"layer":3,"name":"IP Total Length",      "raw":hdr[2:4],  "user_val":"auto",     "note":f"{tot_len}B (20+{len(l4_payload)})"},
        {"layer":3,"name":"IP Identification",    "raw":hdr[4:6],  "user_val":str(ip_id), "note":f"0x{ip_id:04x}"},
        {"layer":3,"name":"IP Flags + FragOffset","raw":hdr[6:8],  "user_val":flag_s or "none", "note":"frag offset=0"},
        {"layer":3,"name":"IP TTL",               "raw":hdr[8:9],  "user_val":str(ttl),   "note":"hops"},
        {"layer":3,"name":"IP Protocol",          "raw":hdr[9:10], "user_val":str(proto_num), "note":proto_s},
        {"layer":3,"name":"IP Header Checksum",   "raw":hdr[10:12],"user_val":"auto",     "note":f"0x{ck:04x} RFC791"},
        {"layer":3,"name":"IP Source Address",    "raw":hdr[12:16],"user_val":src_ip,     "note":""},
        {"layer":3,"name":"IP Destination Addr",  "raw":hdr[16:20],"user_val":dst_ip,     "note":""},
    ]
    return hdr, fields, ck

# ──────────────────────────────────────────────────────────────────────────────
#  STP / RSTP BPDU   (L2/L3 hybrid – uses 802.3 + LLC wrapper)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_stp():
    section("LAYER 3 — STP / RSTP BPDU")
    version   = get("Version  0=STP  2=RSTP", "2")
    bpdu_type = get("BPDU Type  00=Config  80=TCN", "00")
    flags     = get("Flags (hex)", "00")
    root_prio = get("Root Priority", "32768")
    root_mac  = get("Root MAC",     "00:00:00:00:00:00")
    path_cost = get("Root Path Cost", "0")
    br_prio   = get("Bridge Priority", "32768")
    br_mac    = get("Bridge MAC",      "00:11:22:33:44:55")
    port_id   = get("Port ID (hex)",   "8001")
    msg_age   = get("Message Age (sec)","0")
    max_age   = get("Max Age (sec)",   "20")
    hello     = get("Hello Time (sec)","2")
    fwd_delay = get("Forward Delay (sec)","15")
    return (version, bpdu_type, flags, root_prio, root_mac, path_cost,
            br_prio, br_mac, port_id, msg_age, max_age, hello, fwd_delay)

def build_stp(inputs):
    (version, bpdu_type, flags, root_prio, root_mac, path_cost,
     br_prio, br_mac, port_id, msg_age, max_age, hello, fwd_delay) = inputs

    root_id = struct.pack("!H", int(root_prio)) + mac_b(root_mac)
    br_id   = struct.pack("!H", int(br_prio))   + mac_b(br_mac)
    bpdu = (bytes.fromhex("0000") +
            hpad(version,1) + hpad(bpdu_type,1) + hpad(flags,1) +
            root_id + struct.pack("!I", int(path_cost)) + br_id +
            hpad(port_id,2) +
            struct.pack("!HHHH",
                int(msg_age)*256, int(max_age)*256,
                int(hello)*256,   int(fwd_delay)*256))
    fields = [
        {"layer":3,"name":"BPDU Protocol ID",  "raw":bpdu[0:2],  "user_val":"0x0000","note":"always 0"},
        {"layer":3,"name":"BPDU Version",       "raw":bpdu[2:3],  "user_val":version, "note":"0=STP 2=RSTP"},
        {"layer":3,"name":"BPDU Type",          "raw":bpdu[3:4],  "user_val":bpdu_type,"note":"00=Config 80=TCN"},
        {"layer":3,"name":"BPDU Flags",         "raw":bpdu[4:5],  "user_val":flags,   "note":""},
        {"layer":3,"name":"BPDU Root ID",       "raw":bpdu[5:13], "user_val":f"prio={root_prio} mac={root_mac}","note":"8B"},
        {"layer":3,"name":"BPDU Root Path Cost","raw":bpdu[13:17],"user_val":path_cost,"note":""},
        {"layer":3,"name":"BPDU Bridge ID",     "raw":bpdu[17:25],"user_val":f"prio={br_prio} mac={br_mac}","note":"8B"},
        {"layer":3,"name":"BPDU Port ID",       "raw":bpdu[25:27],"user_val":port_id, "note":""},
        {"layer":3,"name":"BPDU Message Age",   "raw":bpdu[27:29],"user_val":msg_age, "note":"sec"},
        {"layer":3,"name":"BPDU Max Age",       "raw":bpdu[29:31],"user_val":max_age, "note":"sec"},
        {"layer":3,"name":"BPDU Hello Time",    "raw":bpdu[31:33],"user_val":hello,   "note":"sec"},
        {"layer":3,"name":"BPDU Forward Delay", "raw":bpdu[33:35],"user_val":fwd_delay,"note":"sec"},
    ]
    return bpdu, fields

# ──────────────────────────────────────────────────────────────────────────────
#  DTP  (Cisco proprietary – carried in 802.3+SNAP frame)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_dtp():
    section("LAYER 3 — DTP  (Dynamic Trunking Protocol)")
    print("    Modes:  02=desirable  03=auto  04=on  05=off")
    mode = get("DTP Mode (hex)", "02")
    return mode

def build_dtp(mode):
    snap    = bytes.fromhex("00000c0104")
    payload = b"\x01\x03\x01" + hpad(mode,1) + b"\x00"*26
    mode_s  = {"02":"desirable","03":"auto","04":"on","05":"off"}.get(mode, f"0x{mode}")
    fields  = [
        {"layer":3,"name":"DTP SNAP OUI",  "raw":snap[0:3],    "user_val":"00000c","note":"Cisco"},
        {"layer":3,"name":"DTP SNAP PID",  "raw":snap[3:5],    "user_val":"0104",  "note":"DTP"},
        {"layer":3,"name":"DTP Version",   "raw":payload[0:1], "user_val":"1",     "note":""},
        {"layer":3,"name":"DTP Flags",     "raw":payload[1:2], "user_val":"03",    "note":""},
        {"layer":3,"name":"DTP Domain",    "raw":payload[2:3], "user_val":"01",    "note":""},
        {"layer":3,"name":"DTP Mode",      "raw":payload[3:4], "user_val":mode,    "note":mode_s},
        {"layer":3,"name":"DTP Pad",       "raw":payload[4:],  "user_val":"0x00*26","note":""},
    ]
    return snap + payload, fields

# ──────────────────────────────────────────────────────────────────────────────
#  PAgP  (Cisco proprietary)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_pagp():
    section("LAYER 3 — PAgP  (Port Aggregation Protocol)")
    print("    Port State flags: 0x01=Active 0x04=Consistent 0x05=Active+Consistent")
    state = get("Port State (hex)", "05")
    return state

def build_pagp(state):
    snap    = bytes.fromhex("00000c0104")
    payload = (b"\x01\x01" + bytes.fromhex("8001") +
               bytes.fromhex("00000001") + hpad(state,1) + b"\x00"*25)
    fields = [
        {"layer":3,"name":"PAgP SNAP OUI",    "raw":snap[0:3],    "user_val":"00000c","note":"Cisco"},
        {"layer":3,"name":"PAgP SNAP PID",    "raw":snap[3:5],    "user_val":"0104",  "note":"PAgP"},
        {"layer":3,"name":"PAgP Version",     "raw":payload[0:1], "user_val":"1",     "note":""},
        {"layer":3,"name":"PAgP Flags",       "raw":payload[1:2], "user_val":"01",    "note":""},
        {"layer":3,"name":"PAgP Port ID",     "raw":payload[2:4], "user_val":"8001",  "note":""},
        {"layer":3,"name":"PAgP System ID",   "raw":payload[4:8], "user_val":"00000001","note":""},
        {"layer":3,"name":"PAgP Port State",  "raw":payload[8:9], "user_val":state,   "note":""},
        {"layer":3,"name":"PAgP Pad",         "raw":payload[9:],  "user_val":"0x00*25","note":""},
    ]
    return snap + payload, fields

# ──────────────────────────────────────────────────────────────────────────────
#  LACP  (IEEE 802.3ad)
# ──────────────────────────────────────────────────────────────────────────────

def ask_l3_lacp():
    section("LAYER 3 — LACP  (802.3ad Link Aggregation)")
    actor_mac   = get("Actor System MAC",  "00:11:22:33:44:55")
    actor_key   = get("Actor Key (hex)",   "0001")
    actor_state = get("Actor State (hex)  [3d=Active+Short+Aggregating+Sync+Col+Dist]", "3d")
    return actor_mac, actor_key, actor_state

def build_lacp(actor_mac, actor_key, actor_state):
    subtype_ver = b"\x01\x01"   # subtype=LACP, version=1
    tlv = (b"\x01\x14" +
           bytes.fromhex("8000") + mac_b(actor_mac) +
           hpad(actor_key,2) + bytes.fromhex("80008001") +
           hpad(actor_state,1) + b"\x00\x00\x00")
    terminator = b"\x00\x00"
    raw = subtype_ver + tlv + terminator
    # offsets into raw
    fields = [
        {"layer":3,"name":"LACP Subtype",       "raw":raw[0:1],  "user_val":"1",       "note":"LACP"},
        {"layer":3,"name":"LACP Version",        "raw":raw[1:2],  "user_val":"1",       "note":""},
        {"layer":3,"name":"LACP Actor TLV Type", "raw":raw[2:3],  "user_val":"01",      "note":"Actor Info"},
        {"layer":3,"name":"LACP Actor TLV Len",  "raw":raw[3:4],  "user_val":"20",      "note":"bytes=20"},
        {"layer":3,"name":"LACP Actor Sys Prio", "raw":raw[4:6],  "user_val":"8000",    "note":"32768"},
        {"layer":3,"name":"LACP Actor Sys MAC",  "raw":raw[6:12], "user_val":actor_mac, "note":""},
        {"layer":3,"name":"LACP Actor Key",      "raw":raw[12:14],"user_val":actor_key, "note":""},
        {"layer":3,"name":"LACP Actor Port Prio","raw":raw[14:16],"user_val":"8000",    "note":""},
        {"layer":3,"name":"LACP Actor Port",     "raw":raw[16:18],"user_val":"8001",    "note":""},
        {"layer":3,"name":"LACP Actor State",    "raw":raw[18:19],"user_val":actor_state,"note":"0x3d=Active+Sync+Agg"},
        {"layer":3,"name":"LACP Actor Reserved", "raw":raw[19:22],"user_val":"000000",  "note":""},
        {"layer":3,"name":"LACP Terminator",     "raw":raw[22:24],"user_val":"0000",    "note":""},
    ]
    return raw, fields

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 4  –  TRANSPORT / CONTROL
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  ICMP
# ──────────────────────────────────────────────────────────────────────────────

ICMP_TABLE = {
    0:  ("Echo Reply",              {0:"Echo reply"}),
    3:  ("Destination Unreachable", {
            0:"Net unreachable",         1:"Host unreachable",
            2:"Protocol unreachable",    3:"Port unreachable",
            4:"Fragmentation needed/DF", 5:"Source route failed",
            6:"Dest network unknown",    7:"Dest host unknown",
            9:"Net admin prohibited",   10:"Host admin prohibited",
           13:"Comm admin prohibited"}),
    4:  ("Source Quench",           {0:"Source quench (deprecated)"}),
    5:  ("Redirect",                {0:"Redirect network",1:"Redirect host",
                                     2:"Redirect TOS+net",3:"Redirect TOS+host"}),
    8:  ("Echo Request",            {0:"Echo request"}),
    9:  ("Router Advertisement",    {0:"Normal advertisement"}),
   10:  ("Router Solicitation",     {0:"Router solicitation"}),
   11:  ("Time Exceeded",           {0:"TTL exceeded in transit",
                                     1:"Fragment reassembly exceeded"}),
   12:  ("Parameter Problem",       {0:"Pointer error",1:"Missing option",2:"Bad length"}),
   13:  ("Timestamp Request",       {0:"Timestamp request"}),
   14:  ("Timestamp Reply",         {0:"Timestamp reply"}),
   17:  ("Address Mask Request",    {0:"Address mask request"}),
   18:  ("Address Mask Reply",      {0:"Address mask reply"}),
   30:  ("Traceroute",              {0:"Information (deprecated)"}),
}
ICMP_ECHO_TYPES = {0, 8, 13, 14, 17, 18}

def print_icmp_table():
    print(f"\n  {'─'*100}")
    print(f"  {'ICMP TYPE / CODE REFERENCE TABLE':^100}")
    print(f"  {'─'*100}")
    print(f"  {'Type':>5}  {'Type Name':<28}  {'Code':>5}  Code Description")
    print(f"  {'─'*100}")
    for t, (tname, codes) in sorted(ICMP_TABLE.items()):
        first = True
        for c, cdesc in sorted(codes.items()):
            if first:
                print(f"  {t:5d}  {tname:<28}  {c:5d}  {cdesc}")
                first = False
            else:
                print(f"  {'':5}  {'':28}  {c:5d}  {cdesc}")
    print(f"  {'─'*100}")

def ask_l4_icmp():
    print_icmp_table()
    section("LAYER 4 — ICMP")
    icmp_type = int(get("ICMP Type  (default=8 Echo Request)", "8"))
    if icmp_type in ICMP_TABLE:
        codes = ICMP_TABLE[icmp_type][1]
        code_hint = "  ".join(f"{c}={d}" for c,d in sorted(codes.items()))
        print(f"    Valid codes: {code_hint}")
    icmp_code = int(get("ICMP Code", "0"))
    icmp_id   = int(get("ICMP Identifier (decimal)", "1"))
    icmp_seq  = int(get("ICMP Sequence   (decimal)", "1"))
    print("    ICMP data payload hex  (default = ping pattern 'abcdefgh')")
    data_hex  = get("ICMP payload hex", "6162636465666768")
    try:
        icmp_data = bytes.fromhex(data_hex.replace(" ",""))
    except ValueError:
        print("    -> invalid hex, using default"); icmp_data = bytes.fromhex("6162636465666768")
    return icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex

def build_icmp(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex_repr=""):
    rest = struct.pack("!HH", icmp_id, icmp_seq) if icmp_type in ICMP_ECHO_TYPES else b'\x00\x00\x00\x00'
    msg0 = struct.pack("!BBH", icmp_type, icmp_code, 0) + rest + icmp_data
    ck   = inet_cksum(msg0)
    msg  = struct.pack("!BBH", icmp_type, icmp_code, ck) + rest + icmp_data

    tname = ICMP_TABLE.get(icmp_type, (f"Type {icmp_type}",{}))[0]
    cname = ICMP_TABLE.get(icmp_type,("",{}))[1].get(icmp_code, f"Code {icmp_code}")

    fields = [
        {"layer":4,"name":"ICMP Type",     "raw":msg[0:1], "user_val":str(icmp_type), "note":tname},
        {"layer":4,"name":"ICMP Code",     "raw":msg[1:2], "user_val":str(icmp_code), "note":cname},
        {"layer":4,"name":"ICMP Checksum", "raw":msg[2:4], "user_val":"auto",         "note":f"0x{ck:04x} RFC792 over full ICMP"},
    ]
    if icmp_type in ICMP_ECHO_TYPES:
        fields += [
            {"layer":4,"name":"ICMP Identifier","raw":msg[4:6],"user_val":str(icmp_id), "note":f"0x{icmp_id:04x}"},
            {"layer":4,"name":"ICMP Sequence",  "raw":msg[6:8],"user_val":str(icmp_seq),"note":""},
        ]
    else:
        fields.append({"layer":4,"name":"ICMP Rest-of-Header","raw":msg[4:8],"user_val":"0","note":"type-specific"})
    if icmp_data:
        fields.append({"layer":4,"name":"ICMP Data Payload","raw":icmp_data,
                       "user_val":data_hex_repr[:20] if data_hex_repr else icmp_data.hex()[:20],
                       "note":f"{len(icmp_data)}B"})
    return msg, fields, ck

# ═══════════════════════════════════════════════════════════════════════════════
#  FRAME ASSEMBLERS
# ═══════════════════════════════════════════════════════════════════════════════

def assemble_eth_frame(l3_payload, l3_fields,
                       dst_mb, src_mb, type_len_b,
                       llc_b, snap_b, variant,
                       dst_s, src_s, v,
                       preamble, sfd):
    """
    Assemble Ethernet frame.
    type_len_b: pre-set (Ethernet II) or None (802.3, will be computed).
    Returns (full_frame_bytes, records_for_table).
    """
    if v in ('2','3','4'):
        # 802.3: length = LLC + SNAP + l3_payload
        length_val = len(llc_b) + len(snap_b) + len(l3_payload)
        tl = struct.pack('>H', length_val)
        tl_note = f"Length={length_val}B"
        tl_user = str(length_val)
    else:
        tl = type_len_b
        tl_note = f"EtherType 0x{tl.hex().upper()}"
        tl_user = f"0x{tl.hex().upper()}"

    mac_content = dst_mb + src_mb + tl + llc_b + snap_b + l3_payload
    fcs, fcs_note = ask_fcs_eth(mac_content)
    mac_frame  = mac_content + fcs
    full_frame = preamble + sfd + mac_frame

    # ── Build record list ──────────────────────────────────────────────────────
    records = [
        {"layer":1,"name":"Preamble",        "raw":preamble, "user_val":preamble.hex(), "note":"7×0x55"},
        {"layer":1,"name":"SFD",             "raw":sfd,      "user_val":sfd.hex(),      "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",         "raw":dst_mb,   "user_val":dst_s,          "note":""},
        {"layer":2,"name":"Src MAC",         "raw":src_mb,   "user_val":src_s,          "note":""},
        {"layer":2,"name":"Type / Length",   "raw":tl,       "user_val":tl_user,        "note":tl_note},
    ]
    if llc_b:
        records += [
            {"layer":2,"name":"LLC DSAP",    "raw":llc_b[0:1],"user_val":llc_b[0:1].hex(),"note":""},
            {"layer":2,"name":"LLC SSAP",    "raw":llc_b[1:2],"user_val":llc_b[1:2].hex(),"note":""},
            {"layer":2,"name":"LLC Control", "raw":llc_b[2:3],"user_val":llc_b[2:3].hex(),"note":""},
        ]
    if snap_b:
        records += [
            {"layer":2,"name":"SNAP OUI",    "raw":snap_b[0:3],"user_val":snap_b[0:3].hex(),"note":""},
            {"layer":2,"name":"SNAP PID",    "raw":snap_b[3:5],"user_val":snap_b[3:5].hex(),"note":""},
        ]
    records += l3_fields
    records.append({"layer":0,"name":"Ethernet FCS (CRC-32)","raw":fcs,"user_val":"auto/custom","note":fcs_note})
    return full_frame, records

# ═══════════════════════════════════════════════════════════════════════════════
#  CHECKSUM VERIFY REPORT
# ═══════════════════════════════════════════════════════════════════════════════

def verify_report(checks):
    """checks: list of (name, stored_val, verify_fn, pass_cond, pass_str)"""
    print(f"\n  {'─'*80}")
    print(f"  CHECKSUM / CRC VERIFICATION")
    print(f"  {'─'*80}")
    for name, stored, result, passed in checks:
        status = "PASS ✓" if passed else "FAIL ✗"
        print(f"  {name:<30}  stored={stored}   verify={result}   {status}")
    print(f"  {'─'*80}")

# ═══════════════════════════════════════════════════════════════════════════════
#  TOP-LEVEL FLOW CONTROLLERS
# ═══════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + ARP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_arp():
    banner("ETHERNET  +  ARP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0806)  |  L3: ARP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0806")
    arp_inputs    = ask_l3_arp()
    arp_raw, arp_fields = build_arp(arp_inputs)
    full_frame, records = assemble_eth_frame(
        arp_raw, arp_fields, dst_mb, src_mb, type_len_b,
        llc_b, snap_b, variant, dst_s, src_s, v, preamble, sfd)
    print_frame_table(records)
    # verify FCS
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([
        ("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref),
    ])
    print_final_hex(full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + IPv4 + ICMP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_ip_icmp():
    banner("ETHERNET  +  IPv4  +  ICMP",
           "L1: Preamble+SFD  |  L2: Ethernet II (0x0800)  |  L3: IPv4  |  L4: ICMP")
    preamble, sfd = ask_layer1_eth()
    (dst_mb, src_mb, type_len_b, llc_b, snap_b,
     variant, dst_s, src_s, v) = ask_l2_ethernet("0800")
    (src_ip, dst_ip, ttl, ip_id, dscp,
     df, proto_num) = ask_l3_ipv4()
    # L4
    icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
    icmp_msg, icmp_fields, icmp_ck = build_icmp(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex)
    ip_hdr, ip_fields, ip_ck = build_ipv4(icmp_msg, src_ip, dst_ip, ttl, ip_id, dscp, df, 1)
    l3_payload = ip_hdr + icmp_msg
    all_upper  = ip_fields + icmp_fields

    full_frame, records = assemble_eth_frame(
        l3_payload, all_upper, dst_mb, src_mb, type_len_b,
        llc_b, snap_b, variant, dst_s, src_s, v, preamble, sfd)

    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    ip_ver     = inet_cksum(ip_hdr)
    icmp_ver   = inet_cksum(icmp_msg)
    verify_report([
        ("IP Header Checksum",    f"0x{ip_ck:04x}",  f"0x{ip_ver:04x}",   ip_ver==0),
        ("ICMP Checksum",         f"0x{icmp_ck:04x}",f"0x{icmp_ver:04x}", icmp_ver==0),
        ("Ethernet FCS (CRC-32)", fcs_stored.hex(),  fcs_ref.hex(),        fcs_stored==fcs_ref),
    ])
    print_final_hex(full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + STP/RSTP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_stp():
    banner("ETHERNET (802.3 + LLC)  +  STP / RSTP BPDU",
           "L1: Preamble+SFD  |  L2: 802.3+LLC  |  L3: BPDU")
    preamble, sfd = ask_layer1_eth()
    stp_inputs = ask_l3_stp()
    bpdu_raw, bpdu_fields = build_stp(stp_inputs)

    # STP always uses 802.3+LLC, fixed MACs
    section("LAYER 2 — 802.3 + LLC  (STP uses fixed multicast)")
    dst_s = get("Destination MAC", "01:80:c2:00:00:00")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    llc_b = bytes.fromhex("424203")   # DSAP=0x42 SSAP=0x42 Ctrl=0x03
    length_val = len(llc_b) + len(bpdu_raw)
    tl    = struct.pack('>H', length_val)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)

    mac_content = dst_mb + src_mb + tl + llc_b + bpdu_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs

    records = [
        {"layer":1,"name":"Preamble",        "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",             "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",         "raw":dst_mb,  "user_val":dst_s,         "note":"STP multicast"},
        {"layer":2,"name":"Src MAC",         "raw":src_mb,  "user_val":src_s,         "note":"bridge MAC"},
        {"layer":2,"name":"802.3 Length",    "raw":tl,      "user_val":str(length_val),"note":"bytes"},
        {"layer":2,"name":"LLC DSAP",        "raw":llc_b[0:1],"user_val":"42",        "note":"STP SAP"},
        {"layer":2,"name":"LLC SSAP",        "raw":llc_b[1:2],"user_val":"42",        "note":"STP SAP"},
        {"layer":2,"name":"LLC Control",     "raw":llc_b[2:3],"user_val":"03",        "note":"UI frame"},
    ] + bpdu_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_final_hex(full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + DTP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_dtp():
    banner("ETHERNET (802.3 + SNAP)  +  DTP",
           "L1: Preamble+SFD  |  L2: 802.3+SNAP  |  L3: DTP")
    preamble, sfd = ask_layer1_eth()
    section("LAYER 2 — Ethernet 802.3")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cc")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    mode  = ask_l3_dtp()
    dtp_raw, dtp_fields = build_dtp(mode)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    length_val = len(dtp_raw)
    tl = struct.pack('>H', length_val)
    mac_content = dst_mb + src_mb + tl + dtp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",     "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC", "raw":dst_mb,  "user_val":dst_s,         "note":"Cisco multicast"},
        {"layer":2,"name":"Src MAC", "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"802.3 Length","raw":tl,  "user_val":str(length_val),"note":"bytes"},
    ] + dtp_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_final_hex(full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + PAgP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_pagp():
    banner("ETHERNET (802.3 + SNAP)  +  PAgP",
           "L1: Preamble+SFD  |  L2: 802.3+SNAP  |  L3: PAgP")
    preamble, sfd = ask_layer1_eth()
    section("LAYER 2 — Ethernet 802.3")
    dst_s = get("Destination MAC", "01:00:0c:cc:cc:cc")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    state = ask_l3_pagp()
    pagp_raw, pagp_fields = build_pagp(state)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    length_val = len(pagp_raw)
    tl = struct.pack('>H', length_val)
    mac_content = dst_mb + src_mb + tl + pagp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble","raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",     "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC", "raw":dst_mb,  "user_val":dst_s,         "note":"Cisco multicast"},
        {"layer":2,"name":"Src MAC", "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"802.3 Length","raw":tl,  "user_val":str(length_val),"note":"bytes"},
    ] + pagp_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_final_hex(full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Ethernet + LACP
# ──────────────────────────────────────────────────────────────────────────────

def flow_eth_lacp():
    banner("ETHERNET II (0x8809)  +  LACP",
           "L1: Preamble+SFD  |  L2: Ethernet II  |  L3: LACP")
    preamble, sfd = ask_layer1_eth()
    section("LAYER 2 — Ethernet II")
    dst_s = get("Destination MAC", "01:80:c2:00:00:02")
    src_s = get("Source MAC",      "00:11:22:33:44:55")
    actor_mac, actor_key, actor_state = ask_l3_lacp()
    lacp_raw, lacp_fields = build_lacp(actor_mac, actor_key, actor_state)
    dst_mb, src_mb = mac_b(dst_s), mac_b(src_s)
    et = bytes.fromhex("8809")
    mac_content = dst_mb + src_mb + et + lacp_raw
    fcs, fcs_note = ask_fcs_eth(mac_content)
    full_frame = preamble + sfd + mac_content + fcs
    records = [
        {"layer":1,"name":"Preamble",  "raw":preamble,"user_val":preamble.hex(),"note":"7×0x55"},
        {"layer":1,"name":"SFD",       "raw":sfd,     "user_val":sfd.hex(),     "note":"0xD5"},
        {"layer":2,"name":"Dst MAC",   "raw":dst_mb,  "user_val":dst_s,         "note":"Slow Protocol multicast"},
        {"layer":2,"name":"Src MAC",   "raw":src_mb,  "user_val":src_s,         "note":""},
        {"layer":2,"name":"EtherType", "raw":et,      "user_val":"0x8809",      "note":"Slow Protocols"},
    ] + lacp_fields + [
        {"layer":0,"name":"Ethernet FCS","raw":fcs,"user_val":"auto/custom","note":fcs_note},
    ]
    print_frame_table(records)
    fcs_stored = full_frame[-4:]
    fcs_ref    = crc32_eth(full_frame[8:-4])
    verify_report([("Ethernet FCS (CRC-32)", fcs_stored.hex(), fcs_ref.hex(), fcs_stored==fcs_ref)])
    print_final_hex(full_frame)

# ──────────────────────────────────────────────────────────────────────────────
#  FLOW: Serial / WAN
# ──────────────────────────────────────────────────────────────────────────────

def flow_serial():
    banner("SERIAL / WAN FRAME BUILDER",
           "L2: PPP | HDLC | SLIP | Modbus RTU | ATM AAL5 | Cisco HDLC | KISS | COBS")
    ch, proto_name = ask_l2_serial()

    start_flag = b'\x7E'; end_flag = b'\x7E'
    if ch in ('3','4','8','10'):
        start_flag = get_hex("Start Flag (2 hex)", "7e", 1)
        end_flag   = get_hex("End   Flag (2 hex)", "7e", 1)

    addr_map = {'3':'ff','4':'ff','8':'ff','10':'0f','7':'01'}
    address = b''
    if ch in addr_map:
        address = get_hex(f"Address/Slave (2 hex)", addr_map[ch], 1)

    control = b''
    if ch in ('3','4','8','10'):
        control = get_hex("Control field (2 hex)", "03", 1)

    # L3 inside serial
    l3_payload = b''
    l3_fields  = []
    if ch in ('3','4','8','10'):
        section("LAYER 3 — Payload inside Serial frame")
        print("    Options:  1=None (empty)   2=Raw hex   3=IPv4+ICMP")
        l3ch = input("    Choose [1]: ").strip() or '1'
        if l3ch == '2':
            phex = get("Payload hex", "")
            try:    l3_payload = bytes.fromhex(phex.replace(" ",""))
            except: l3_payload = b''
        elif l3ch == '3':
            (src_ip, dst_ip, ttl, ip_id, dscp, df, proto_num) = ask_l3_ipv4()
            icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex = ask_l4_icmp()
            icmp_msg, icmp_flds, icmp_ck = build_icmp(icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, data_hex)
            ip_hdr, ip_flds, ip_ck = build_ipv4(icmp_msg, src_ip, dst_ip, ttl, ip_id, dscp, df, 1)
            l3_payload = ip_hdr + icmp_msg
            l3_fields  = ip_flds + icmp_flds

    header    = address + control
    crc_input = header + l3_payload

    # CRC selection
    fcs = b''; fcs_desc = "none"
    if ch in ('3','4','8','10'):
        fcs, fcs_desc = ask_serial_crc(crc_input, "FCS-16 CCITT", 'big')
    elif ch == '7':
        fcs, fcs_desc = ask_serial_crc(crc_input, "Modbus CRC-16", 'little')
    elif ch == '9':
        crc_val = zlib.crc32(crc_input) & 0xFFFFFFFF
        section("ATM AAL5 CRC-32")
        cx = input("    1=Auto  2=Custom  [1]: ").strip() or '1'
        if cx == '2':
            fh = input("    Enter 8 hex digits: ").strip()
            try:
                cf = bytes.fromhex(fh)
                if len(cf)==4: fcs=cf; fcs_desc="AAL5 CRC-32 custom"
                else: raise ValueError
            except:
                fcs = crc_val.to_bytes(4,'big'); fcs_desc=f"AAL5 CRC-32 auto over {len(crc_input)}B"
        else:
            fcs = crc_val.to_bytes(4,'big'); fcs_desc=f"AAL5 CRC-32 auto over {len(crc_input)}B"

    content = header + l3_payload + fcs

    # Apply framing
    if ch == '2':
        full_frame = slip_enc(content)
    elif ch in ('3','4','10'):
        full_frame = start_flag + byte_escape(content) + end_flag
    elif ch == '8':
        full_frame = start_flag + bit_stuff(byte_escape(content)) + end_flag
    elif ch == '9':
        pad_len = (48 - (len(content)+8) % 48) % 48
        full_frame = content + b'\x00'*pad_len + fcs
    else:
        full_frame = content

    # Build records
    records = []
    if ch in ('3','4','8','10'):
        records.append({"layer":1,"name":"Start Flag","raw":start_flag,"user_val":start_flag.hex(),"note":""})
    if address:
        records.append({"layer":2,"name":"Address","raw":address,"user_val":address.hex(),"note":""})
    if control:
        records.append({"layer":2,"name":"Control","raw":control,"user_val":control.hex(),"note":""})
    records += l3_fields
    if fcs:
        records.append({"layer":0,"name":f"CRC/FCS","raw":fcs,"user_val":"auto/custom","note":fcs_desc})
    if ch in ('3','4','8','10'):
        records.append({"layer":1,"name":"End Flag","raw":end_flag,"user_val":end_flag.hex(),"note":""})

    banner(f"SERIAL FRAME — {proto_name}")
    print_frame_table(records)
    print_final_hex(full_frame)

# ═══════════════════════════════════════════════════════════════════════════════
#  LAYER 3 MENU  (what runs inside Ethernet)
# ═══════════════════════════════════════════════════════════════════════════════

L3_ETH_MENU = """
  ┌─────────────────────────────────────────────────────────────────────┐
  │           LAYER 3  —  Choose protocol to carry in Ethernet          │
  ├───┬─────────────────────────────────────────────────────────────────┤
  │ 1 │ ARP                      (EtherType 0x0806)                     │
  │ 2 │ IPv4 + ICMP              (EtherType 0x0800)                     │
  │ 3 │ STP / RSTP BPDU          (802.3 + LLC wrapper)                  │
  │ 4 │ DTP  – Cisco Trunking    (802.3 + SNAP)                         │
  │ 5 │ PAgP – Cisco Port Agg.   (802.3 + SNAP)                         │
  │ 6 │ LACP – 802.3ad           (EtherType 0x8809)                     │
  └───┴─────────────────────────────────────────────────────────────────┘"""

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ═══════════════════════════════════════════════════════════════════════════════

MAIN_MENU = """
╔═══════════════════════════════════════════════════════════════════════════╗
║           NETWORK FRAME BUILDER  —  LAYERED INPUT FLOW                   ║
╠═══════════════════════════════════════════════════════════════════════════╣
║  SELECT LAYER 2 TECHNOLOGY FIRST                                          ║
╠═══╦═══════════════════════════════════════════════════════════════════════╣
║ 1 ║ Ethernet / 802.3  →  then choose Layer 3 protocol                    ║
║   ║   Supports:  ARP  |  IPv4+ICMP  |  STP/RSTP  |  DTP  |  PAgP  |LACP ║
╠═══╬═══════════════════════════════════════════════════════════════════════╣
║ 2 ║ Serial / WAN  →  then choose L2 protocol + optional L3/L4 payload    ║
║   ║   Supports:  PPP  |  HDLC  |  SLIP  |  Modbus RTU  |  ATM AAL5      ║
║   ║             Cisco HDLC  |  KISS  |  COBS  |  HDLC+BitStuff           ║
╚═══╩═══════════════════════════════════════════════════════════════════════╝"""

L3_DISPATCH = {
    '1': flow_eth_arp,
    '2': flow_eth_ip_icmp,
    '3': flow_eth_stp,
    '4': flow_eth_dtp,
    '5': flow_eth_pagp,
    '6': flow_eth_lacp,
}

def main():
    print(MAIN_MENU)
    top = input("  Choose L2 technology  (1=Ethernet  2=Serial): ").strip()

    if top == '1':
        print(L3_ETH_MENU)
        l3ch = input("  Choose L3 protocol (1-6): ").strip()
        fn = L3_DISPATCH.get(l3ch)
        if fn: fn()
        else:  print("  Invalid choice.")

    elif top == '2':
        flow_serial()
    else:
        print("  Invalid choice.")

if __name__ == "__main__":
    try:
        main()
        while input("\nBuild another frame? (y/n): ").strip().lower() == 'y':
            print()
            main()
    except KeyboardInterrupt:
        print("\nExited.")
