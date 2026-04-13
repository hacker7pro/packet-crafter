"""
phy_builder.py — Complete PHY Layer Engine
IEEE 802.3 compliant encoding for all Ethernet speeds + FC native + Serial PHY.
"""

from __future__ import annotations


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 1 — PHY REGISTRY  (all IEEE 802.3 speeds + FC + Serial)
# ══════════════════════════════════════════════════════════════════════════════

PHY_REGISTRY: dict[str, dict] = {

    # ── 1 Mbps — IEEE 802.3e-1987 ─────────────────────────────────────────────
    '1M': dict(
        name='1 Mbps Ethernet — 1BASE5 (StarLAN) — IEEE 802.3e Clause 10',
        ieee_clause='Clause 10', amendment='802.3e-1987',
        line_rate='2 Mbaud (Manchester)', encoding='Manchester',
        media='1-pair 24AWG UTP ≤250 m (star topology)',
        frame_start=dict(mechanism='Preamble 7B + SFD 1B',
                         preamble_hex='55 55 55 55 55 55 55', sfd_hex='D5'),
        frame_end=dict(mechanism='End of carrier — no explicit symbol'),
        ifg=dict(min_bits=96, duration_us=96.0,
                 pattern='No carrier (silence)', purpose='Receiver recovery'),
        encoding_detail=dict(scheme='Manchester IEEE 802.3',
                             bit_0='High→Low', bit_1='Low→High'),
        control_symbols={},
        caution='1BASE5 obsolete — only legacy StarLAN installations',
    ),

    # ── 10 Mbps — IEEE 802.3 Clause 7/14 ────────────────────────────────────
    '10M': dict(
        name='10 Mbps Ethernet — 10BASE-T/5/2 — IEEE 802.3 Clause 7/14',
        ieee_clause='Clause 7 (10BASE5/2) · Clause 14 (10BASE-T)',
        amendment='802.3-1985, 802.3a-1985, 802.3i-1990',
        line_rate='20 Mbaud (Manchester doubles baud rate)',
        encoding='Manchester — IEEE 802.3 Biphase-L',
        media='10BASE-T: Cat3 UTP ≤100 m | 10BASE5: thick coax ≤500 m | 10BASE2: thin coax ≤185 m',
        frame_start=dict(
            mechanism='Preamble (7B) + SFD (1B) — Manchester carrier appears with preamble',
            preamble_pattern='10101010 × 7 bytes — self-clocking allows RX PLL lock',
            preamble_hex='55 55 55 55 55 55 55', sfd_hex='D5',
            note='No PHY delimiter beyond preamble; Manchester carrier start = frame start',
        ),
        frame_end=dict(mechanism='End of Manchester carrier — RX detects when modulation stops'),
        ifg=dict(min_bits=96, duration_us=9.6,
                 pattern='No carrier (line idle — no Manchester signal)',
                 purpose='Collision detect, receiver buffer drain, collision back-off'),
        encoding_detail=dict(
            scheme='IEEE 802.3 Manchester (Biphase-L)',
            bit_0='High→Low transition at mid-bit period (send 1 then 0)',
            bit_1='Low→High transition at mid-bit period (send 0 then 1)',
            clock_recovery='Self-clocking — every bit has a transition; no separate clock needed',
            bandwidth='20 MHz required for 10 Mbps data rate',
        ),
        control_symbols={},
        phy_detection='Link Integrity Test (LIT) pulses every 16 ms on 10BASE-T when idle',
        caution='Manchester doubles RF bandwidth; cannot run on Cat3 longer than 100 m at 10 Mbps',
    ),

    # ── 100 Mbps — IEEE 802.3u Clause 24/25 ──────────────────────────────────
    '100M': dict(
        name='100 Mbps Fast Ethernet — 100BASE-TX/FX — IEEE 802.3u Clause 24/25',
        ieee_clause='Clause 24 (MII) · Clause 25 (100BASE-X PCS/PMA) · Clause 26 (T4)',
        amendment='802.3u-1995',
        line_rate='125 Mbaud (100 Mbps ÷ 0.8 efficiency)',
        encoding='4B/5B block code → MLT-3 line signal (TX copper) or NRZI (FX fibre)',
        media='100BASE-TX: Cat5 UTP ≤100 m | 100BASE-FX: MMF ≤2 km | 100BASE-T4: Cat3 ≤100 m',
        frame_start=dict(
            mechanism='J/K SSD (Start-Stream-Delimiter) precedes preamble in 4B/5B stream',
            j_symbol='11000 — invalid data code; used exclusively as SSD part 1',
            k_symbol='10001 — invalid data code; used exclusively as SSD part 2',
            preamble_hex='55 55 55 55 55 55 55', sfd_hex='D5',
            note='J+K at PHY level; preamble then encoded as 4B/5B data codes',
        ),
        frame_end=dict(
            mechanism='T/R ESD (End-Stream-Delimiter) in 4B/5B stream after FCS',
            t_symbol='01101 — T = Terminate',
            r_symbol='00111 — R = Reset',
        ),
        ifg=dict(
            min_bits=96, duration_ns=960,
            pattern='Idle (I=11111) symbols fill IFG continuously',
            purpose='96 bit-times minimum; IDLE maintains MLT-3 timing and clock recovery',
        ),
        encoding_detail=dict(
            scheme='4B/5B (ANSI X3.263 TP-PMD) + MLT-3 (TX copper) or NRZI (FX fibre)',
            fourbfiveb='Each 4 data bits → 5 encoded bits; no 3+ consecutive zeros guaranteed',
            mlt3_rule='Transition (level change in +1→0→-1→0 cycle) on each 1-bit in 4B/5B stream',
            nrzi_rule='Fibre: transition on each 1-bit; no transition on 0-bit',
            efficiency='80% (4 data bits per 5 line bits)',
            control_codes='J/K/T/R/I/H/Q are invalid 4B/5B codes repurposed as control symbols',
        ),
        control_symbols={
            'J = 11000': 'SSD part 1 — Start-Stream-Delimiter',
            'K = 10001': 'SSD part 2 — Start-Stream-Delimiter',
            'T = 01101': 'ESD part 1 — End-Stream-Delimiter',
            'R = 00111': 'ESD part 2 — End-Stream-Delimiter',
            'I = 11111': 'IDLE — fills IFG between frames',
            'H = 00100': 'Halt — error indication',
        },
        phy_detection='Fast Link Pulses (FLP) every 8 ms for autoneg; 125 MHz PLL lock on MLT-3',
        caution='100BASE-T4 uses 8B6T encoding (different from 4B/5B); TX and T4 not interoperable',
    ),

    # ── 1 Gbps — IEEE 802.3z/ab Clause 36/40 ─────────────────────────────────
    '1G': dict(
        name='1 Gbps Gigabit Ethernet — 1000BASE-X/T — IEEE 802.3z/ab Clause 36/40',
        ieee_clause='Clause 36 (1000BASE-X PCS 8b/10b) · Clause 40 (1000BASE-T PAM-5)',
        amendment='802.3z-1998 (fibre/CX) · 802.3ab-1999 (1000BASE-T copper)',
        line_rate='1.25 Gbaud (fibre/CX) or 250 Mbaud×4 pairs PAM-5 (1000BASE-T)',
        encoding='8b/10b block code (Clause 36) for fibre/CX; 4D-PAM5 for 1000BASE-T',
        media='1000BASE-SX: MMF ≤550 m | 1000BASE-LX: SMF ≤5 km | 1000BASE-CX: twinax ≤25 m | 1000BASE-T: Cat5e ≤100 m',
        frame_start=dict(
            mechanism='/S/ Start-of-Packet ordered set followed by preamble',
            s_set='K27.7 (0xFB) + D21.5 (0xB5) — 2-character ordered set',
            k27_7_rdm='1101101000', k27_7_rdp='0010010111',
            d21_5='1010101010 (neutral — same for both RD)',
            preamble_hex='55 55 55 55 55 55 55', sfd_hex='D5',
            note='Preamble+SFD transmitted as 8b/10b data characters after /S/',
        ),
        frame_end=dict(
            mechanism='/T/ + /R/ End-of-Packet ordered set',
            t_symbol='K29.7 (0xFD) — /T/ EoP-1',
            r_symbol='K23.7 (0xF7) — /R/ EoP-2 / Carrier-Extend',
            k29_7_rdm='1011101000', k23_7_rdm='1110101000',
        ),
        ifg=dict(
            min_bits=96, duration_ns=96,
            pattern='/I/ IDLE ordered sets: K28.5+D16.2 (RD-) or K28.5+D5.6 (RD+)',
            purpose='Clock recovery + disparity correction + word synchronisation',
            rd_rule='IEEE 802.3z §36.2.5: if RD before K28.5 is positive → use /I1/(K28.5+D5.6); negative → /I2/(K28.5+D16.2)',
        ),
        encoding_detail=dict(
            scheme='8b/10b — IEEE 802.3z Clause 36 / Widmer-Franaszek 1983 / ANSI X3.230',
            split='Byte HGF_EDCBA → 5b/6b (EDCBA→abcdei) + 3b/4b (HGF→fghj)',
            rd_rule='Both sub-blocks chosen using SAME entering Running Disparity',
            k_special='K.x.7 for EDCBA∈{23,27,29,30}: 3b/4b swapped (share D.x.A7 5b/6b pattern)',
            d_a7='D.x.A7 alternate 3b/4b: RD≤0 for x∈{17,18,20}; RD>0 for x∈{11,13,14}',
            comma='K28.5 contains unique 5-bit run (11111 or 00000) → used for word alignment',
            initial_rd='RD- (-1) at transmission start per IEEE 802.3z',
            efficiency='80% (8 data bits per 10 line bits)',
            disparity='Sub-blocks: each ≤±2; combined symbol: ±4 possible (3-7 ones valid)',
        ),
        control_symbols={
            'K28.5 (0xBC)': 'Comma — used in /I/ IDLE ordered sets; unique sync pattern',
            'K27.7 (0xFB)': '/S/ Start-of-Packet ordered set ch1',
            'K29.7 (0xFD)': '/T/ End-of-Packet part 1',
            'K23.7 (0xF7)': '/R/ End-of-Packet part 2 / Carrier-Extend',
            'K30.7 (0xFE)': '/V/ Error propagation',
            'K28.1 (0x3C)': 'Config ordered set during autoneg',
            'K28.3 (0x7C)': 'Idle/Config ordered set',
        },
        phy_detection='K28.5 comma detection for word alignment; 1.25 GHz PLL lock; LR/LRR link init sequence',
        caution='1000BASE-T uses PAM-5 on 4 pairs simultaneously — completely different PHY from 8b/10b fibre; cannot mix',
    ),

    # ── 2.5 Gbps — IEEE 802.3bz-2016 Clause 125 ──────────────────────────────
    '2_5G': dict(
        name='2.5 Gbps Multi-Gigabit — 2.5GBASE-T — IEEE 802.3bz Clause 125',
        ieee_clause='Clause 125 (2.5GBASE-T)', amendment='802.3bz-2016',
        line_rate='3.2 Gbaud×4 pairs (PAM-16 + 128-DSQ)',
        encoding='PAM-16 + 128-DSQ (Dual Square QAM) with LDPC FEC — 4 pairs simultaneously',
        media='Cat5e ≤100 m · Cat6 ≤100 m',
        frame_start=dict(mechanism='Preamble+SFD at MAC level; PHY framing via PAM-16 symbol stream'),
        frame_end=dict(mechanism='End-of-frame at MAC level; PHY continuous symbol stream'),
        ifg=dict(min_bits=96, duration_ns=38.4,
                 pattern='Idle symbols in PAM-16 symbol stream'),
        encoding_detail=dict(
            scheme='PAM-16 (16 voltage levels) + 128-DSQ + Tomlinson-Harashima precoding',
            fec='LDPC (Low-Density Parity-Check) mandatory',
            note='Backward compatible with Cat5e — no rewiring for most installations',
        ),
        control_symbols={},
        phy_detection='IEEE 802.3bz Clause 28 autoneg FLP with 2.5G capability bits',
        caution='2.5GBASE-T and 5GBASE-T not compatible with 10GBASE-T at full speed on same cable',
    ),

    # ── 5 Gbps — IEEE 802.3bz-2016 Clause 126 ────────────────────────────────
    '5G': dict(
        name='5 Gbps Multi-Gigabit — 5GBASE-T — IEEE 802.3bz Clause 126',
        ieee_clause='Clause 126 (5GBASE-T)', amendment='802.3bz-2016',
        line_rate='6.25 Gbaud×4 pairs', encoding='PAM-16 + 128-DSQ + LDPC FEC',
        media='Cat6 ≤100 m · Cat6A ≤100 m',
        frame_start=dict(mechanism='Preamble+SFD at MAC level'),
        frame_end=dict(mechanism='End-of-frame at MAC level'),
        ifg=dict(min_bits=96, duration_ns=19.2, pattern='Idle in PAM-16 stream'),
        encoding_detail=dict(scheme='PAM-16 + 128-DSQ (same architecture as 2.5GBASE-T at higher baud)'),
        control_symbols={},
        phy_detection='802.3bz autoneg with 5G capability bits in FLP burst',
        caution='Cat5e limited to 2.5G at 100 m; Cat6 required for 5G at full distance',
    ),

    # ── 10 Gbps — IEEE 802.3ae-2002 Clause 49 ────────────────────────────────
    '10G': dict(
        name='10 Gbps Ethernet — 10GBASE-R — IEEE 802.3ae Clause 49',
        ieee_clause='Clause 49 (10GBASE-R PCS 64b/66b) · Clause 52 (XGMII)',
        amendment='802.3ae-2002 (fibre) · 802.3an-2006 (10GBASE-T)',
        line_rate='10.3125 Gbaud',
        encoding='64b/66b — 2-bit sync header + 64-bit scrambled data payload',
        media='10GBASE-SR: MMF ≤300 m | 10GBASE-LR: SMF ≤10 km | 10GBASE-ER: SMF ≤40 km | 10GBASE-T: Cat6A ≤100 m',
        frame_start=dict(
            mechanism='Start Block — control block (sync=10) type=0x78',
            sync_ctrl='10 — marks control block',
            sync_data='01 — marks data block',
            start_type='0x78 = Start in lane 0 — preamble in payload bytes 1-7',
            block_size='66 bits: 2-bit sync + 64-bit payload',
            preamble_note='Preamble 0x555555555555+SFD 0xD5 packed in Start Block payload',
        ),
        frame_end=dict(
            mechanism='Terminate Block — control block encoding last valid data octet position',
            types={
                '0xFF': 'T0 — all 8 octets padding (FCS ends in previous block)',
                '0xE1': 'T1 — 1 data octet then 7 padding',
                '0xE2': 'T2 — 2 data octets then 6 padding',
                '0xCC': 'T4 — 4 data octets then 4 padding',
                '0x87': 'T7 — 7 data octets then terminate',
            },
        ),
        ifg=dict(
            min_bits=96, min_blocks=12, duration_ns=9.6,
            pattern='Idle blocks: sync=10, type=0x1E, payload=8×0x00',
            purpose='Block sync, clock compensation, receiver buffer drain',
        ),
        encoding_detail=dict(
            scheme='64b/66b — IEEE 802.3ae Clause 49',
            sync_header='2b: 01=Data  10=Control  (00 and 11 are invalid)',
            scrambling='58-bit LFSR polynomial x^58+x^39+1 applied to data block payloads',
            scramble_purpose='Statistical DC balance; prevents clock starvation from long bit runs',
            efficiency='64/66 = 97.0%',
            block_type_map={
                '0x1E': 'Idle/Error control block',
                '0x2D': 'Ordered Set — OS in octets 0-3',
                '0x33': 'Ordered Set — OS in octets 4-7',
                '0x4B': 'Ordered Set / Alignment Marker (multi-lane)',
                '0x55': 'Start in lane 4',
                '0x66': 'Start in lane 2',
                '0x78': 'Start in lane 0',
                '0x87': 'Terminate at octet 7',
                '0xE1': 'Terminate at octet 1',
                '0xFF': 'Terminate at octet 0',
            },
        ),
        control_symbols={
            'Start 0x78': 'Frame start — preamble in payload',
            'Term 0xFF':  'Frame end — all padding',
            'Term 0x87':  'Frame end — 7 data octets',
            'Idle 0x1E':  'IFG fill block',
            'OS   0x4B':  'Ordered Set / Alignment Marker',
        },
        phy_detection='Sync header lock: 64 consecutive valid 01/10 pairs; LFSR descrambler sync',
        caution='LFSR desync causes ALL blocks misinterpreted as control — resync required',
    ),

    # ── 25 Gbps — IEEE 802.3by-2016 Clause 107 ───────────────────────────────
    '25G': dict(
        name='25 Gbps Ethernet — 25GBASE-R — IEEE 802.3by Clause 107',
        ieee_clause='Clause 107 (25GBASE-R PCS)', amendment='802.3by-2016 · 802.3cc-2017 (SMF)',
        line_rate='25.78125 Gbaud', encoding='64b/66b — identical to 10GBASE-R at 25G baud',
        media='25GBASE-SR: MMF ≤100 m | 25GBASE-LR: SMF ≤10 km | 25GBASE-CR: DAC ≤5 m',
        frame_start=dict(mechanism='Start Block type=0x78 — identical to 10GBASE-R'),
        frame_end=dict(mechanism='Terminate Block — identical types to 10GBASE-R'),
        ifg=dict(min_bits=96, duration_ns=3.84,
                 pattern='Idle blocks 0x1E — identical to 10G'),
        encoding_detail=dict(
            scheme='64b/66b identical to IEEE 802.3ae Clause 49',
            fec='RS-FEC RS(528,514) optional for SR; mandatory for CR copper',
        ),
        control_symbols={'Same as 10G': 'Start/Term/Idle/OS block types identical'},
        phy_detection='64b/66b sync header lock at 25.78G; RS-FEC codeword sync if enabled',
        caution='RS-FEC adds ~3% overhead and latency — required on lossy/long copper links',
    ),

    # ── 40 Gbps — IEEE 802.3ba-2010 Clause 82 ────────────────────────────────
    '40G': dict(
        name='40 Gbps Ethernet — 40GBASE-R — IEEE 802.3ba Clause 82',
        ieee_clause='Clause 82 (40GBASE-R PCS, 4 virtual lanes)',
        amendment='802.3ba-2010',
        line_rate='10.3125 Gbaud × 4 lanes = 41.25 Gbaud aggregate',
        encoding='64b/66b × 4 virtual lanes with per-lane Alignment Markers for deskew',
        media='40GBASE-CR4: DAC ≤10 m | 40GBASE-SR4: MMF ≤150 m | 40GBASE-LR4: SMF ≤10 km (4 WDM λ)',
        frame_start=dict(
            mechanism='Start Block after AM lock across all 4 lanes',
            am_period='Alignment Marker type=0x4B every 16383 blocks per lane',
            deskew='RX reorders lanes using unique per-lane AM pattern',
        ),
        frame_end=dict(mechanism='Terminate Block on lane carrying frame-end bytes'),
        ifg=dict(min_bits=96, duration_ns=2.4,
                 pattern='Idle blocks distributed across 4 lanes',
                 max_lane_skew='4800 ns tolerable inter-lane skew'),
        encoding_detail=dict(
            scheme='64b/66b × 4 virtual lanes + BIP-8 per-lane in AM payload',
            bip8='Bit-Interleaved Parity-8 in each Alignment Marker — per-lane error monitoring',
        ),
        control_symbols={'AM 0x4B × 4': 'Per-lane Alignment Marker for deskew'},
        phy_detection='4-lane AM lock + deskew complete before any frames delivered',
        caution='All 4 lanes must lock; single bad lane disables entire 40G link',
    ),

    # ── 50 Gbps — IEEE 802.3cd-2018 Clause 91A ───────────────────────────────
    '50G': dict(
        name='50 Gbps Ethernet — 50GBASE-R — IEEE 802.3cd Clause 91A',
        ieee_clause='Clause 91A (50GBASE-R PCS)', amendment='802.3cd-2018',
        line_rate='26.5625 Gbaud PAM4 × 1 lane',
        encoding='64b/66b + KP4 RS-FEC + PAM4 (2 bits/symbol) on single lane',
        media='50GBASE-SR: MMF ≤100 m | 50GBASE-FR: SMF ≤2 km | 50GBASE-CR: DAC ≤3 m',
        frame_start=dict(mechanism='Start Block inside KP4 FEC codeword after AM lock'),
        frame_end=dict(mechanism='Terminate Block inside KP4 FEC codeword'),
        ifg=dict(min_bits=96, duration_ns=1.92, pattern='Idle inside KP4 FEC codewords'),
        encoding_detail=dict(
            scheme='64b/66b + PAM4 + KP4 RS(544,514) FEC',
            pam4='4 voltage levels {-3,-1,+1,+3}; Gray coded: 00→-3  01→-1  11→+1  10→+3',
            kp4='KP4 RS(544,514): 30 parity symbols; corrects up to 15 symbol errors',
        ),
        control_symbols={'AM': 'Alignment Marker per PAM4 lane'},
        phy_detection='PAM4 CDR + eye equalisation; KP4 FEC sync; AM lock',
        caution='PAM4 has 3 eye openings, each 6dB smaller than NRZ — requires better SNR and pre-emphasis',
    ),

    # ── 100 Gbps — IEEE 802.3ba/bm/cd ────────────────────────────────────────
    '100G': dict(
        name='100 Gbps Ethernet — 100GBASE-R — IEEE 802.3ba/bm/cd',
        ieee_clause='Clause 82/91 (100GBASE-R PCS) · Clause 86 (100GBASE-KR4)',
        amendment='802.3ba-2010 · 802.3bm-2015 · 802.3cd-2018',
        line_rate='25.78125 Gbaud NRZ × 4 lanes  OR  26.5625 Gbaud PAM4 × 2 lanes',
        encoding='64b/66b × 4 NRZ lanes (100GBASE-SR4) or 64b/66b × 2 PAM4 lanes (100GBASE-DR)',
        media='100GBASE-SR4: MMF ≤100 m | 100GBASE-LR4: SMF ≤10 km | 100GBASE-DR: SMF ≤500 m | 100GBASE-CR4: DAC ≤5 m',
        frame_start=dict(
            mechanism='Start Block per lane after AM lock; PAM4 AM every 4096 symbols',
        ),
        frame_end=dict(mechanism='Terminate Block; KP4 FEC codeword boundary'),
        ifg=dict(min_bits=96, duration_ns=0.96, pattern='Idle inside KP4 FEC codewords'),
        encoding_detail=dict(
            scheme='64b/66b + KP4 RS(544,514) FEC + PAM4 or NRZ depending on variant',
            pam4='2 bits/symbol; Gray coded; 4 voltage levels',
            kp4='5.8% overhead; corrects burst errors up to 15 PAM4 symbols',
        ),
        control_symbols={'AM × 4/2': 'Per-lane Alignment Markers; 4-lane NRZ or 2-lane PAM4'},
        phy_detection='PAM4 CDR; KP4 FEC sync; per-lane AM lock and deskew',
        caution='100GBASE-SR4 requires 4 fibres (8 strands duplex); LR4 uses 4 WDM λ on 2 fibres',
    ),

    # ── 200 Gbps — IEEE 802.3bs-2017 Clause 120 ──────────────────────────────
    '200G': dict(
        name='200 Gbps Ethernet — 200GBASE-R — IEEE 802.3bs Clause 120',
        ieee_clause='Clause 120 (200GBASE-R PCS)', amendment='802.3bs-2017 · 802.3cd-2018',
        line_rate='26.5625 Gbaud PAM4 × 4 lanes = 106.25 Gbaud aggregate',
        encoding='64b/66b × 4 PAM4 lanes + KP4 RS-FEC',
        media='200GBASE-SR4: MMF ≤100 m | 200GBASE-LR4: SMF ≤10 km | 200GBASE-CR4: DAC ≤3 m',
        frame_start=dict(mechanism='Start Block per lane after AM lock on all 4 PAM4 lanes'),
        frame_end=dict(mechanism='Terminate Block inside KP4 FEC codeword'),
        ifg=dict(min_bits=96, duration_ns=0.48, pattern='Idle inside FEC codewords × 4 lanes'),
        encoding_detail=dict(
            scheme='64b/66b + PAM4 × 4 lanes + KP4 RS(544,514) FEC',
            pam4_eyes='3 eye openings per lane; each 1/3 height of NRZ single eye'),
        control_symbols={'AM × 4': 'Per-lane alignment markers'},
        phy_detection='4-lane PAM4 CDR; KP4 FEC sync; AM deskew',
        caution='200G requires all 4 lanes simultaneously; single lane failure = link down',
    ),

    # ── 400 Gbps — IEEE 802.3bs-2017 Clause 119/130 ──────────────────────────
    '400G': dict(
        name='400 Gbps Ethernet — 400GBASE-R — IEEE 802.3bs Clause 119/130',
        ieee_clause='Clause 119 (400GBASE-R 8-lane) · Clause 130 (400GBASE-DR4)',
        amendment='802.3bs-2017 · 802.3cm-2020 · 802.3cu-2021',
        line_rate='26.5625 Gbaud PAM4 × 8 lanes = 212.5 Gbaud aggregate',
        encoding='64b/66b × 8 PAM4 lanes + KP4 RS-FEC  OR  256b/257b for some variants',
        media='400GBASE-SR8: MMF ≤100 m | 400GBASE-DR4: SMF ≤500 m | 400GBASE-LR8: SMF ≤10 km | 400GBASE-CR8: DAC ≤3 m',
        frame_start=dict(
            mechanism='Start Block after AM lock on all 8 lanes',
            b256_257='256b/257b variant: 1-bit sync + 256-bit data = 257 bits; 99.6% efficiency',
        ),
        frame_end=dict(mechanism='Terminate Block inside FEC codeword across 8 lanes'),
        ifg=dict(min_bits=96, duration_ns=0.24, pattern='Idle inside FEC codewords × 8 lanes'),
        encoding_detail=dict(
            scheme='64b/66b × 8 lanes PAM4 + KP4 RS(544,514)  OR  256b/257b + RS-FEC',
            efficiency_256_257='256/257 = 99.6%',
        ),
        control_symbols={'AM × 8': '8-lane Alignment Markers for complete deskew'},
        phy_detection='8-lane PAM4 CDR; KP4 FEC sync; 8-lane AM deskew',
        caution='400G DR4 needs 4 SMF fibres (8 strands duplex); SR8 needs 8 MMF fibres',
    ),

    # ── 800 Gbps — IEEE 802.3df-2024 ─────────────────────────────────────────
    '800G': dict(
        name='800 Gbps Ethernet — 800GBASE-R — IEEE 802.3df-2024',
        ieee_clause='Clause 162+ (800GBASE-R, 100G/lane)', amendment='802.3df-2024',
        line_rate='53.125 Gbaud PAM4 × 8 lanes = 425 Gbaud aggregate',
        encoding='64b/66b × 8 PAM4 lanes at 53.125 Gbaud + KP4 RS-FEC',
        media='800GBASE-SR8: MMF ≤50 m | 800GBASE-DR8: SMF ≤500 m | 800GBASE-CR8: DAC ≤3 m',
        frame_start=dict(mechanism='Start Block per lane after AM lock; 100G/lane PCS'),
        frame_end=dict(mechanism='Terminate Block inside FEC codeword'),
        ifg=dict(min_bits=96, duration_ns=0.12, pattern='Idle inside FEC × 8 lanes at 53G'),
        encoding_detail=dict(
            scheme='64b/66b × 8 lanes at 53.125 Gbaud PAM4 + KP4 RS-FEC',
            lane_speed='53.125 Gbaud PAM4 = 100 Gbps/lane (2 bits/symbol)',
        ),
        control_symbols={'AM × 8': 'Per-lane AM for 8-lane deskew at 800G'},
        phy_detection='53G PAM4 CDR + tight equalization; RS-FEC mandatory; AM lock',
        caution='800G uses QSFP-DD or OSFP form factors; requires ultra-low-loss connectors',
    ),

    # ── FC native PHY variants ─────────────────────────────────────────────────
    'FC_1G': dict(
        name='Fibre Channel 1GFC — 1.0625 Gbaud — FC-PI / ANSI INCITS 373',
        ieee_clause='FC-PI T11 / ANSI X3.230 (not IEEE 802.3)',
        amendment='FC-PI', line_rate='1.0625 Gbaud',
        encoding='8b/10b — identical algorithm to IEEE 802.3z 1000BASE-X',
        media='MMF ≤500 m · SMF ≤10 km',
        frame_start=dict(
            mechanism='SOF (Start-of-Frame) ordered set — 4 transmission words (40 bits in 8b/10b)',
            sof_types={
                'SOFi3': '0xBC 0xB5 0xE6 0xE6 — Class-3 Initiate (standard FCP first frame)',
                'SOFn3': '0xBC 0x55 0xE5 0xE5 — Class-3 Normal (subsequent FCP frames)',
                'SOFf':  '0xBC 0x95 0x95 0x95 — Fabric',
                'SOFi1': '0xBC 0xB5 0x56 0x56 — Class-1 Initiate',
                'SOFn1': '0xBC 0xB5 0xE5 0xE5 — Class-1 Normal',
                'SOFi2': '0xBC 0x55 0x55 0x56 — Class-2 Initiate',
                'SOFn2': '0xBC 0x55 0xE6 0xE6 — Class-2 Normal',
                'SOFc1': '0xBC 0xB5 0x55 0x55 — Class-1 Connect',
            },
            k28_5='K28.5 (0xBC) always first char — provides comma synchronisation',
        ),
        frame_end=dict(
            mechanism='EOF (End-of-Frame) ordered set — 4 transmission words',
            eof_types={
                'EOFt':   '0xBC 0x42 0x42 0x42 — Terminate (last frame of sequence)',
                'EOFn':   '0xBC 0x46 0x46 0x46 — Normal (more frames follow)',
                'EOFa':   '0xBC 0x41 0x41 0x41 — Abort',
                'EOFdt':  '0xBC 0x49 0x49 0x49 — Disconnect-Terminate',
                'EOFni':  '0xBC 0x4E 0x4E 0x4E — Normal-Invalid',
                'EOFdti': '0xBC 0x4F 0x4F 0x4F — Disconnect-Terminate-Invalid',
            },
        ),
        ifg=dict(
            min_words=6,
            pattern='IDLE: K28.5+D21.4+D21.4+D21.4 (4 chars per primitive word)',
            purpose='Minimum 6 IDLE words between EOF and next SOF',
        ),
        encoding_detail=dict(
            scheme='8b/10b — same algorithm and tables as IEEE 802.3z',
            fc_primitives={
                'IDLE':  'K28.5 D21.4 D21.4 D21.4 — fill between frames',
                'R_RDY': 'K28.5 D21.4 D10.4 D21.4 — Receiver Ready (BB credit)',
                'NOS':   'K28.5 D21.4 D31.5 D21.4 — Not Operational State',
                'OLS':   'K28.5 D21.4 D10.3 D21.5 — Offline State',
                'LR':    'K28.5 D21.4 D21.0 D21.4 — Link Reset',
                'LRR':   'K28.5 D21.4 D21.1 D21.4 — Link Reset Response',
            },
            fc_frame='SOF(4 chars 40b) + Header(24B) + OptHdrs + Payload(0-2112B) + CRC32(4B) + EOF(4 chars 40b)',
        ),
        control_symbols={
            'K28.5 (0xBC)': 'Comma — every primitive word starts with K28.5',
            'SOFi3': 'Most common SOF for Class-3 FCP',
            'EOFt':  'Normal sequence termination',
            'R_RDY': 'Buffer-to-buffer credit return',
            'IDLE':  'Fill between frames',
        },
        phy_detection='K28.5 comma sync; word boundary lock; LR/LRR link initialisation',
        caution='FC Class-3 is unacknowledged — FCP layer handles retries via ABTS/BA_RJT',
    ),

    'FC_4G': dict(
        name='Fibre Channel 4GFC — 4.25 Gbaud — FC-PI-2',
        ieee_clause='FC-PI-2 T11 Project 1506-D', amendment='FC-PI-2',
        line_rate='4.25 Gbaud', encoding='8b/10b — identical to 1GFC',
        media='MMF ≤150 m · SMF ≤10 km',
        frame_start=dict(mechanism='Same SOF ordered sets as 1GFC',
                         sof_types='same as FC_1G'),
        frame_end=dict(mechanism='Same EOF ordered sets as 1GFC'),
        ifg=dict(min_words=6, pattern='IDLE primitives same as 1GFC'),
        encoding_detail=dict(scheme='8b/10b identical to 1GFC'),
        control_symbols={'Same as FC_1G': 'SOF/EOF/IDLE/R_RDY identical'},
        phy_detection='K28.5 at 4.25G; PLL × 4 vs 1GFC',
        caution='4G ports cannot directly interop with 1G at same rate — speed matching required',
    ),

    'FC_16G': dict(
        name='Fibre Channel 16GFC — 14.025 Gbaud — FC-PI-5',
        ieee_clause='FC-PI-5 T11 Project 2118-D', amendment='FC-PI-5',
        line_rate='14.025 Gbaud', encoding='64b/66b with FC-specific block payloads',
        media='MMF ≤100 m · SMF ≤10 km',
        frame_start=dict(
            mechanism='Control block (sync=10) carrying FC SOF type in block payload',
        ),
        frame_end=dict(mechanism='Terminate block with FC EOF type in payload'),
        ifg=dict(min_words=6, pattern='64b/66b Idle blocks'),
        encoding_detail=dict(scheme='64b/66b with 58-bit LFSR scrambler (same as 10GbE Clause 49)'),
        control_symbols={'Start/Term blocks': 'FC SOF/EOF in 64b/66b block payloads'},
        phy_detection='64b/66b sync header lock; LFSR descrambler sync',
        caution='16GFC requires SFP+ rated for 14G — standard 8G SFPs not compatible',
    ),

    'FC_32G': dict(
        name='Fibre Channel 32GFC — 28.05 Gbaud — FC-PI-6',
        ieee_clause='FC-PI-6 T11 Project 2235-D', amendment='FC-PI-6',
        line_rate='28.05 Gbaud', encoding='256b/257b + KP4 RS(544,514) FEC',
        media='MMF ≤100 m · SMF ≤10 km',
        frame_start=dict(mechanism='256b/257b Start block with RS-FEC wrapper'),
        frame_end=dict(mechanism='256b/257b Terminate block inside FEC codeword'),
        ifg=dict(min_words=6, pattern='256b/257b Idle blocks inside FEC codewords'),
        encoding_detail=dict(scheme='256b/257b (1-bit sync + 256-bit data) + KP4 RS(544,514) FEC',
                             efficiency='99.6%'),
        control_symbols={'Same structure as 400GbE 256b/257b': 'Start/Term/Idle/AM'},
        phy_detection='AM lock; FEC sync; 256b/257b sync header',
        caution='32GFC mandates RS-FEC; cannot operate without FEC on most media',
    ),

    # ── Serial legacy PHY ──────────────────────────────────────────────────────
    'SERIAL_NRZ': dict(
        name='NRZ Serial — RS-232 / RS-485 / UART — TIA-232-F / TIA-485-A',
        ieee_clause='TIA-232-F (RS-232) / TIA-485-A (RS-485) — not IEEE 802.3',
        amendment='N/A',
        line_rate='9600–921600 bps (UART) · up to 10 Mbps (RS-485)',
        encoding='NRZ — signal holds level for full bit period; no self-clocking',
        media='RS-232: ≤15 m | RS-485: ≤1200 m at low baud',
        frame_start=dict(
            mechanism='Start bit — line falls LOW (Space) for 1 bit period',
            idle='Idle = continuous Mark (HIGH)',
        ),
        frame_end=dict(mechanism='Stop bit(s) — line HIGH (Mark) for 1 or 2 bit periods'),
        ifg=dict(min_bits=1, pattern='Idle = continuous Mark (HIGH)',
                 purpose='Resync; guard time between characters'),
        encoding_detail=dict(
            scheme='NRZ — voltage directly represents logic level',
            rs232='Logic 1: -3 to -15V  Logic 0: +3 to +15V (inverted vs TTL)',
            rs485='Differential: A>B by ≥200mV=1  B>A by ≥200mV=0',
            frame_format='1 start + 5-9 data bits (LSB first) + optional parity + 1-2 stop',
        ),
        control_symbols={
            'XON  0x11': 'Software flow control — resume TX',
            'XOFF 0x13': 'Software flow control — pause TX',
            'BREAK':     'Continuous LOW > 1 frame — line break signal',
        },
        phy_detection='Falling edge on idle line triggers start-bit timer; baud clock sync',
        caution='NRZ has no clock recovery — baud rate must match exactly; >2% error = framing failures',
    ),

    'SERIAL_NRZI': dict(
        name='NRZI Serial — USB / HDLC / CAN — USB2.0 / ISO 13239 / ISO 11898',
        ieee_clause='USB 2.0 §7.1.8 / ISO 13239 (HDLC) / ISO 11898-1 (CAN) — not IEEE 802.3',
        amendment='N/A',
        line_rate='USB-FS 12Mbps · USB-HS 480Mbps · HDLC ≤2Mbps · CAN ≤1Mbps',
        encoding='NRZI — transition on 0, no transition on 1; bit stuffing after 6 consecutive 1s (USB) or 5 (HDLC)',
        media='USB: ≤5 m | CAN: ≤40 m at 1Mbps | HDLC: varies',
        frame_start=dict(
            mechanism='SYNC field + flag/SOF',
            usb_sync='00000001 (8b) — 7 zeros force 7 transitions for PLL lock',
            hdlc_flag='0x7E — unique flag byte (bit stuffing prevents 0x7E in data)',
            can_sof='Single dominant (0) bit after idle recessive period',
        ),
        frame_end=dict(
            mechanism='EOP (USB SE0) or Flag (HDLC 0x7E) or EOF (CAN 7 recessive bits)',
        ),
        ifg=dict(min_bits=3,
                 pattern='USB: J state · HDLC: 0x7E flags · CAN: recessive bits'),
        encoding_detail=dict(
            scheme='NRZI + bit stuffing',
            nrzi='0=transition  1=no transition (relative to current level)',
            stuffing='Insert 0 after 6 consecutive 1s (USB); receiver removes stuffed bits',
        ),
        control_symbols={
            'SYNC':  'Alignment field — forces PLL lock',
            'EOP':   'USB end-of-packet SE0 (D+=0 D-=0)',
            'Flag':  'HDLC 0x7E frame boundary marker',
        },
        phy_detection='NRZI transition count; bit-stuff validation; flag/SOF detection',
        caution='Bit stuffing adds variable overhead — worst-case throughput depends on data content',
    ),
}

# ── Speed menu lists ────────────────────────────────────────────────────────────

ETH_SPEED_MENU: list[dict] = [
    dict(key='1M',   label='1 Mbps',   tech='1BASE5 (StarLAN)',        encoding='Manchester',         ifg_ns=960,   clause='Clause 10'),
    dict(key='10M',  label='10 Mbps',  tech='10BASE-T/5/2',            encoding='Manchester',         ifg_ns=960,   clause='Clause 7/14'),
    dict(key='100M', label='100 Mbps', tech='100BASE-TX/FX',           encoding='4B/5B+MLT-3/NRZI',  ifg_ns=960,   clause='Clause 24/25'),
    dict(key='1G',   label='1 Gbps',   tech='1000BASE-X/T',            encoding='8b/10b / PAM-5',    ifg_ns=96,    clause='Clause 36/40'),
    dict(key='2_5G', label='2.5 Gbps', tech='2.5GBASE-T',              encoding='PAM-16+128-DSQ',    ifg_ns=38.4,  clause='Clause 125'),
    dict(key='5G',   label='5 Gbps',   tech='5GBASE-T',                encoding='PAM-16+128-DSQ',    ifg_ns=19.2,  clause='Clause 126'),
    dict(key='10G',  label='10 Gbps',  tech='10GBASE-R/T/CX4',         encoding='64b/66b',           ifg_ns=9.6,   clause='Clause 49'),
    dict(key='25G',  label='25 Gbps',  tech='25GBASE-R/CR/SR',         encoding='64b/66b+RS-FEC',    ifg_ns=3.84,  clause='Clause 107'),
    dict(key='40G',  label='40 Gbps',  tech='40GBASE-CR4/SR4/LR4',     encoding='64b/66b×4',         ifg_ns=2.4,   clause='Clause 82'),
    dict(key='50G',  label='50 Gbps',  tech='50GBASE-SR/FR/CR',        encoding='64b/66b+PAM4',      ifg_ns=1.92,  clause='Clause 91A'),
    dict(key='100G', label='100 Gbps', tech='100GBASE-SR4/LR4/DR',     encoding='64b/66b PAM4×4',    ifg_ns=0.96,  clause='Clause 82/91'),
    dict(key='200G', label='200 Gbps', tech='200GBASE-SR4/LR4/CR4',    encoding='64b/66b PAM4×4',    ifg_ns=0.48,  clause='Clause 120'),
    dict(key='400G', label='400 Gbps', tech='400GBASE-SR8/DR4/LR8',    encoding='64b/66b PAM4×8',    ifg_ns=0.24,  clause='Clause 119/130'),
    dict(key='800G', label='800 Gbps', tech='800GBASE-SR8/DR8/CR8',    encoding='64b/66b PAM4×8@53G',ifg_ns=0.12,  clause='Clause 162+'),
]

FC_SPEED_MENU: list[dict] = [
    dict(key='FC_1G',  label='1GFC',  baud='1.0625G',  encoding='8b/10b',        clause='FC-PI'),
    dict(key='FC_4G',  label='4GFC',  baud='4.25G',    encoding='8b/10b',        clause='FC-PI-2'),
    dict(key='FC_16G', label='16GFC', baud='14.025G',  encoding='64b/66b',       clause='FC-PI-5'),
    dict(key='FC_32G', label='32GFC', baud='28.05G',   encoding='256b/257b+FEC', clause='FC-PI-6'),
]

SERIAL_SPEED_MENU: list[dict] = [
    dict(key='SERIAL_NRZ',  label='NRZ  (RS-232 / RS-485 / UART)', encoding='NRZ level'),
    dict(key='SERIAL_NRZI', label='NRZI (USB / HDLC / CAN)',        encoding='NRZI+bit-stuffing'),
]

# ── PHY query helpers ───────────────────────────────────────────────────────────

def get_phy_info(speed_key: str) -> dict:
    return PHY_REGISTRY.get(speed_key, {})
def get_start_mechanism(speed_key: str) -> dict:
    return PHY_REGISTRY.get(speed_key, {}).get('frame_start', {})
def get_end_mechanism(speed_key: str) -> dict:
    return PHY_REGISTRY.get(speed_key, {}).get('frame_end', {})
def get_ifg(speed_key: str) -> dict:
    return PHY_REGISTRY.get(speed_key, {}).get('ifg', {})
def get_control_symbols(speed_key: str) -> dict:
    return PHY_REGISTRY.get(speed_key, {}).get('control_symbols', {})
def get_encoding_detail(speed_key: str) -> dict:
    return PHY_REGISTRY.get(speed_key, {}).get('encoding_detail', {})
def get_ifg_pattern_display(speed_key: str) -> str:
    ifg = get_ifg(speed_key)
    return f"{ifg.get('min_bits',96)}b — {ifg.get('pattern','Idle')} — {ifg.get('purpose','')}"
def uses_preamble_sfd(speed_key: str) -> bool:
    return speed_key in ('1M','10M','100M','1G','2_5G','5G')
def uses_start_block(speed_key: str) -> bool:
    return speed_key in ('10G','25G','40G','50G','100G','200G','400G','800G','FC_16G','FC_32G')
def uses_8b10b_sof(speed_key: str) -> bool:
    return speed_key in ('FC_1G','FC_4G')
def uses_8b10b_encoding(speed_key: str) -> bool:
    return speed_key in ('1G','FC_1G','FC_4G')
def uses_64b66b(speed_key: str) -> bool:
    return speed_key in ('10G','25G','40G','50G','100G','200G','FC_16G')
def uses_pam4(speed_key: str) -> bool:
    return speed_key in ('50G','100G','200G','400G','800G')
def registry_stats_phy() -> dict:
    return dict(eth_speeds=len(ETH_SPEED_MENU), fc_speeds=len(FC_SPEED_MENU),
                serial_modes=len(SERIAL_SPEED_MENU), total_phy_variants=len(PHY_REGISTRY))


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 2 — IEEE 802.3 8b/10b ENCODING ENGINE
#  Source: Widmer & Franaszek 1983 / IEEE 802.3z Clause 36 / ANSI X3.230
#
#  Key rules:
#    • Input byte HGF_EDCBA split: 5b/6b (EDCBA→abcdei) + 3b/4b (HGF→fghj)
#    • BOTH sub-blocks chosen using the SAME entering Running Disparity
#    • Sub-block disparity: 0 or ±2 per sub-block (neutral or paired)
#    • Combined 10-bit symbol: disparity range −4 to +4 (3–7 ones valid)
#    • Running Disparity updated once after full 10-bit symbol
#    • K.x.7 for EDCBA∈{23,27,29,30}: 3b/4b assignment is SWAPPED
#    • D.x.A7 alternate: used for specific (x, RD) combinations
#    • Initial RD = −1 (RD-) per IEEE 802.3z convention
# ══════════════════════════════════════════════════════════════════════════════

# 5b/6b table: EDCBA → (6b_RD_minus, 6b_RD_plus_or_None_if_neutral)
_5B6B_TABLE: dict = {
    0:  (0b100111, 0b011000),  1:  (0b011101, 0b100010),
    2:  (0b101101, 0b010010),  3:  (0b110001, None),
    4:  (0b110101, 0b001010),  5:  (0b101001, None),
    6:  (0b011001, None),      7:  (0b111000, 0b000111),
    8:  (0b111001, 0b000110),  9:  (0b100101, None),
    10: (0b010101, None),      11: (0b110100, None),
    12: (0b001101, None),      13: (0b101100, None),
    14: (0b011100, None),      15: (0b010111, 0b101000),
    16: (0b011011, 0b100100),  17: (0b100011, None),
    18: (0b010011, None),      19: (0b110010, None),
    20: (0b001011, None),      21: (0b101010, None),
    22: (0b011010, None),      23: (0b111010, 0b000101),
    24: (0b110011, 0b001100),  25: (0b100110, None),
    26: (0b010110, None),      27: (0b110110, 0b001001),
    28: (0b001110, None),      29: (0b101110, 0b010001),
    30: (0b011110, 0b100001),  31: (0b101011, 0b010100),
    'K28': (0b001111, 0b110000),   # exclusively for K.28.x symbols
}

# 3b/4b table: HGF → (4b_RD_minus, 4b_RD_plus_or_None_if_neutral)
_3B4B_TABLE: dict[int, tuple] = {
    0: (0b1011, 0b0100),   # D.x.0
    1: (0b1001, None),     # D.x.1  neutral
    2: (0b0101, None),     # D.x.2  neutral
    3: (0b1100, 0b0011),   # D.x.3  RD-dependent neutral
    4: (0b1101, 0b0010),   # D.x.4
    5: (0b1010, None),     # D.x.5  neutral
    6: (0b0110, None),     # D.x.6  neutral
    7: (0b1110, 0b0001),   # D.x.P7 primary; A7 alternate below
}

# K-symbol 3b/4b overrides (differ from D equivalents for .1/.2/.5/.6/.7)
_K_3B4B_TABLE: dict[int, tuple[int, int]] = {
    0: (0b1011, 0b0100),
    1: (0b1001, 0b0110),   # ← differs from D.x.1
    2: (0b0101, 0b1010),   # ← differs from D.x.2
    3: (0b1100, 0b0011),
    4: (0b1101, 0b0010),
    5: (0b1010, 0b0101),   # ← differs from D.x.5
    6: (0b1001, 0b0110),   # ← differs from D.x.6
    7: (0b0111, 0b1000),   # standard K.x.7
}

# K.x.7 special: EDCBA in {23,27,29,30} share 5b/6b with D.x.A7
# Their 3b/4b RD-/RD+ assignment is SWAPPED vs standard K.x.7
_K7_SPECIAL_EDCBA: frozenset = frozenset({23, 27, 29, 30})

# D.x.A7 alternate 3b/4b codes
_A7_RD_MINUS: int = 0b0111   # used when entering RD ≤ 0 for EDCBA ∈ {17,18,20}
_A7_RD_PLUS:  int = 0b1000   # used when entering RD > 0 for EDCBA ∈ {11,13,14}


def _encode_one(bv: int, rd: int, is_k: bool = False) -> tuple[int, int]:
    """
    Core IEEE 802.3 8b/10b encoder.
    Both sub-blocks use SAME entering RD. RD updated from combined symbol.
    Returns (codeword_10b, new_rd).  codeword = (6b << 4) | 4b.
    """
    EDCBA = bv & 0x1F
    HGF   = (bv >> 5) & 0x07

    # 5b/6b
    if is_k and EDCBA == 28:
        p6m, p6p = _5B6B_TABLE['K28']
    else:
        p6m, p6p_r = _5B6B_TABLE.get(EDCBA, (0b100111, 0b011000))
        p6p = p6p_r if p6p_r is not None else p6m
    p6 = p6m if rd <= 0 else p6p

    # 3b/4b
    if is_k:
        p4m, p4p = _K_3B4B_TABLE.get(HGF, (0b1011, 0b0100))
        if HGF == 7 and EDCBA in _K7_SPECIAL_EDCBA:
            p4m, p4p = _A7_RD_PLUS, _A7_RD_MINUS   # swapped for special K.x.7
    else:
        p4m_r, p4p_r = _3B4B_TABLE.get(HGF, (0b1011, 0b0100))
        p4m = p4m_r
        p4p = p4p_r if p4p_r is not None else p4m_r
        if HGF == 7:                               # D.x.A7 alternate
            if (rd <= 0 and EDCBA in (17, 18, 20)) or \
               (rd  > 0 and EDCBA in (11, 13, 14)):
                p4m = _A7_RD_MINUS
                p4p = _A7_RD_PLUS
    p4 = p4m if rd <= 0 else p4p

    cw   = (p6 << 4) | p4
    ones = bin(cw).count('1')
    disp = ones - (10 - ones)
    new_rd = 1 if disp > 0 else (-1 if disp < 0 else rd)
    return cw, new_rd


# Pre-computed full lookup table (all 256 bytes, both RDs)
_8B10B_FULL: dict[int, tuple[int, int]] = {
    b: (_encode_one(b, -1)[0], _encode_one(b, +1)[0]) for b in range(256)
}

# K-character lookup
_8B10B_K_FULL: dict[str, tuple[int, int]] = {}
_K_BYTE_MAP:   dict[int, str]             = {}
for _nm, _bv in [('K28.0',0x1C),('K28.1',0x3C),('K28.2',0x5C),('K28.3',0x7C),
                  ('K28.4',0x9C),('K28.5',0xBC),('K28.6',0xDC),('K28.7',0xFC),
                  ('K23.7',0xF7),('K27.7',0xFB),('K29.7',0xFD),('K30.7',0xFE)]:
    _8B10B_K_FULL[_nm] = (_encode_one(_bv,-1,True)[0], _encode_one(_bv,+1,True)[0])
    _K_BYTE_MAP[_bv]   = _nm

# Legacy aliases for backward compatibility
_8B10B_TABLE   = _8B10B_FULL
_8B10B_K_TABLE = _8B10B_K_FULL


def encode_byte_8b10b(byte_val: int, running_disparity: int,
                       is_k_char: bool = False) -> tuple[int, int]:
    """
    Encode one byte using IEEE 802.3 8b/10b.
    Uses pre-computed lookup table for data bytes; _encode_one for K chars.
    Returns (codeword_10b, new_running_disparity).
    """
    if is_k_char:
        k_name = _K_BYTE_MAP.get(byte_val, 'K28.5')
        rd_minus, rd_plus = _8B10B_K_FULL.get(k_name, (0b0011111010, 0b1100000101))
    else:
        rd_minus, rd_plus = _8B10B_FULL.get(byte_val, _8B10B_FULL[0x00])
    cw    = rd_minus if running_disparity <= 0 else rd_plus
    ones  = bin(cw).count('1')
    disp  = ones - (10 - ones)
    new_rd = 1 if disp > 0 else (-1 if disp < 0 else running_disparity)
    return cw, new_rd


def encode_bytes_8b10b(data: bytes, initial_rd: int = -1,
                        k_positions: set | None = None) -> tuple[list[int], int]:
    """Encode sequence of bytes using 8b/10b. k_positions = set of K-char indices."""
    codewords: list[int] = []
    rd = initial_rd
    k_pos = k_positions or set()
    for i, b in enumerate(data):
        cw, rd = encode_byte_8b10b(b, rd, is_k_char=(i in k_pos))
        codewords.append(cw)
    return codewords, rd


def codewords_to_bitstring(codewords: list[int], bits: int = 10) -> str:
    return ''.join(format(cw, f'0{bits}b') for cw in codewords)


def codewords_to_hex(codewords: list[int], bits: int = 10) -> str:
    bs = codewords_to_bitstring(codewords, bits)
    pad = (8 - len(bs) % 8) % 8
    bs += '0' * pad
    return bytes(int(bs[i:i+8], 2) for i in range(0, len(bs), 8)).hex().upper()


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 3 — 4B/5B + MLT-3 ENCODING  (IEEE 802.3u Clause 24/25)
# ══════════════════════════════════════════════════════════════════════════════

_4B5B_DATA_TABLE: dict[int, int] = {
    0x0: 0b11110, 0x1: 0b01001, 0x2: 0b10100, 0x3: 0b10101,
    0x4: 0b01010, 0x5: 0b01011, 0x6: 0b01110, 0x7: 0b01111,
    0x8: 0b10010, 0x9: 0b10011, 0xA: 0b10110, 0xB: 0b10111,
    0xC: 0b11010, 0xD: 0b11011, 0xE: 0b11100, 0xF: 0b11101,
}

_4B5B_CTRL_TABLE: dict[str, int] = {
    'J': 0b11000,  # SSD part 1
    'K': 0b10001,  # SSD part 2
    'T': 0b01101,  # ESD part 1
    'R': 0b00111,  # ESD part 2
    'I': 0b11111,  # IDLE
    'H': 0b00100,  # Halt
    'Q': 0b00000,  # Quiet
}

def encode_byte_4b5b(byte_val: int) -> tuple[int, int]:
    return (_4B5B_DATA_TABLE[(byte_val >> 4) & 0xF],
            _4B5B_DATA_TABLE[byte_val & 0xF])

def encode_bytes_4b5b(data: bytes) -> tuple[list[int], list[int]]:
    codes:   list[int] = [_4B5B_CTRL_TABLE['J'], _4B5B_CTRL_TABLE['K']]
    nibbles: list[int] = [-1, -1]
    for b in data:
        h, lo = encode_byte_4b5b(b)
        codes.extend([h, lo]); nibbles.extend([(b >> 4), (b & 0xF)])
    codes.extend([_4B5B_CTRL_TABLE['T'], _4B5B_CTRL_TABLE['R']])
    nibbles.extend([-2, -2])
    return codes, nibbles

def apply_mlt3(codes_5b: list[int]) -> list[int]:
    levels: list[int] = []; state = 0
    cycle = [0, 1, 0, -1]
    for code in codes_5b:
        for bit_pos in range(4, -1, -1):
            levels.append(cycle[state])
            if (code >> bit_pos) & 1: state = (state + 1) % 4
    return levels


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 4 — MANCHESTER ENCODING  (IEEE 802.3 Clause 7/14)
# ══════════════════════════════════════════════════════════════════════════════

def encode_bytes_manchester(data: bytes) -> list[int]:
    """IEEE 802.3 Manchester: bit 0 → H↓L (1,0)  bit 1 → L↑H (0,1). MSB first."""
    result: list[int] = []
    for b in data:
        for bit_pos in range(7, -1, -1):
            bit = (b >> bit_pos) & 1
            result.extend([0, 1] if bit else [1, 0])
    return result


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 5 — FC ORDERED SET TABLES
# ══════════════════════════════════════════════════════════════════════════════

FC_SOF_BYTES: dict[str, bytes] = {
    'SOFc1': bytes([0xBC, 0xB5, 0x55, 0x55]),
    'SOFi1': bytes([0xBC, 0xB5, 0x56, 0x56]),
    'SOFn1': bytes([0xBC, 0xB5, 0xE5, 0xE5]),
    'SOFi2': bytes([0xBC, 0x55, 0x55, 0x56]),
    'SOFn2': bytes([0xBC, 0x55, 0xE6, 0xE6]),
    'SOFi3': bytes([0xBC, 0xB5, 0xE6, 0xE6]),
    'SOFn3': bytes([0xBC, 0x55, 0xE5, 0xE5]),
    'SOFf':  bytes([0xBC, 0x95, 0x95, 0x95]),
}

FC_EOF_BYTES: dict[str, bytes] = {
    'EOFt':   bytes([0xBC, 0x42, 0x42, 0x42]),
    'EOFdt':  bytes([0xBC, 0x49, 0x49, 0x49]),
    'EOFa':   bytes([0xBC, 0x41, 0x41, 0x41]),
    'EOFn':   bytes([0xBC, 0x46, 0x46, 0x46]),
    'EOFni':  bytes([0xBC, 0x4E, 0x4E, 0x4E]),
    'EOFdti': bytes([0xBC, 0x4F, 0x4F, 0x4F]),
}

FC_IDLE_BYTES:  bytes = bytes([0xBC, 0xB5, 0xB5, 0xB5])
FC_R_RDY_BYTES: bytes = bytes([0xBC, 0xB5, 0x34, 0xB5])

FC_SOF_DESC: dict[str, str] = {
    'SOFi3': 'Class-3 Initiate — first frame of new sequence (standard FCP)',
    'SOFn3': 'Class-3 Normal — subsequent frames within sequence',
    'SOFf':  'Fabric — F_Port to N_Port',
    'SOFc1': 'Class-1 Connect — dedicated connection establishment',
    'SOFi1': 'Class-1 Initiate',  'SOFn1': 'Class-1 Normal',
    'SOFi2': 'Class-2 Initiate',  'SOFn2': 'Class-2 Normal',
}

FC_EOF_DESC: dict[str, str] = {
    'EOFt':   'Terminate — last frame of sequence',
    'EOFn':   'Normal — more frames follow',
    'EOFa':   'Abort — discard this frame',
    'EOFdt':  'Disconnect-Terminate',
    'EOFni':  'Normal-Invalid — frame has errors',
    'EOFdti': 'Disconnect-Terminate-Invalid',
}

def encode_fc_ordered_set_8b10b(os_bytes: bytes, initial_rd: int = -1) -> tuple[list[int], int]:
    return encode_bytes_8b10b(os_bytes, initial_rd=initial_rd, k_positions={0})


# ══════════════════════════════════════════════════════════════════════════════
#  SECTION 6 — PHY STREAM BUILDER  (correct architecture per requirement)
#
#  Step order:
#    1. Input: full MAC frame bytes (Dst+Src+EtherType+Payload+FCS)
#    2. Encode FULL MAC frame with speed-appropriate encoding
#    3. AFTER encoding, prepend PHY control symbols (IFG, Start block/K-code)
#    4. AFTER encoding, append PHY termination symbols (End block/K-code)
#
#  Output:
#    A. MAC frame hex — before encoding
#    B. Encoded MAC hex — after encoding
#    C. Full PHY stream hex — IFG + Start + Encoded + End
# ══════════════════════════════════════════════════════════════════════════════

def build_phy_stream(mac_frame: bytes, speed_key: str,
                      idle_count: int = 12,
                      initial_rd: int = -1) -> dict:
    """
    Correct PHY stream construction per IEEE 802.3.

    Args:
        mac_frame:   Full MAC frame — Dst(6)+Src(6)+EtherType(2)+Payload+FCS(4)
                     Do NOT include Preamble/SFD — handled as PHY framing here
        speed_key:   PHY_REGISTRY key
        idle_count:  IFG byte count (default 12)
        initial_rd:  Starting RD for 8b/10b (-1 = RD-)

    Returns dict with:
        mac_frame_hex:   hex of MAC frame BEFORE encoding
        encoded_mac_hex: hex of MAC frame AFTER encoding
        phy_stream_hex:  hex of full PHY stream (IFG+Start+Encoded+End)
        components:      list of named segments with type/hex/note
        stats:           encoding statistics
    """
    result = dict(
        mac_frame_hex    = mac_frame.hex().upper(),
        encoded_mac_hex  = '',
        phy_stream_hex   = '',
        phy_stream_bits  = '',
        components       = [],
        encoding         = PHY_REGISTRY.get(speed_key, {}).get('encoding', ''),
        final_rd         = 0,
        stats            = {},
        speed            = speed_key,
    )

    def _bits_to_hex(bits: str) -> str:
        pad = (8 - len(bits) % 8) % 8
        bits += '0' * pad
        return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8)).hex().upper()

    # ── 10M — Manchester ──────────────────────────────────────────────────────
    if speed_key in ('1M', '10M'):
        phy_preamble = bytes([0x55]*7 + [0xD5])
        mac_hb       = encode_bytes_manchester(mac_frame)
        pr_hb        = encode_bytes_manchester(phy_preamble)

        # IFG: silence (no carrier)
        ifg_bits = idle_count * 8 * 2  # half-bits of silence

        # Encoded MAC hex: pack half-bits to bytes (8 half-bits per byte)
        enc_bytes = bytes(
            int(''.join(str(b) for b in mac_hb[i:i+8]), 2)
            for i in range(0, len(mac_hb) - 7, 8)
        )
        phy_bits = ''.join(str(b) for b in (pr_hb + mac_hb))

        result['encoded_mac_hex'] = enc_bytes.hex().upper()
        result['phy_stream_hex']  = _bits_to_hex(phy_bits)
        result['phy_stream_bits'] = phy_bits
        result['components'] = [
            dict(name=f'IFG ({idle_count}B silence)', type='phy_control',
                 hex='(no carrier)', note='Inter-Frame Gap — no Manchester signal'),
            dict(name='Preamble(7B)+SFD(1B)', type='phy_framing',
                 hex=phy_preamble.hex().upper(), note='PHY clock sync + frame boundary'),
            dict(name=f'MAC Frame ({len(mac_frame)}B) ENCODED', type='mac_encoded',
                 hex=mac_frame.hex().upper(), note='Full MAC → Manchester half-bits'),
        ]
        result['stats'] = dict(
            mac_frame_bytes=len(mac_frame), encoded_half_bits=len(mac_hb),
            total_phy_half_bits=len(pr_hb)+len(mac_hb), line_rate='20 Mbaud',
        )

    # ── 100M — 4B/5B + MLT-3 ─────────────────────────────────────────────────
    elif speed_key == '100M':
        phy_preamble   = bytes([0x55]*7 + [0xD5])
        ifg_idle_codes = [_4B5B_CTRL_TABLE['I']] * (idle_count * 2)

        # Encode preamble and MAC frame separately (data only, no SSD/ESD added yet)
        pr_codes  = [_4B5B_DATA_TABLE[(b >> 4)&0xF] for b in phy_preamble] + \
                    [_4B5B_DATA_TABLE[b & 0xF] for b in phy_preamble]
        mac_codes, _ = encode_bytes_4b5b(mac_frame)  # includes J/K SSD and T/R ESD

        # Full 4B/5B stream: IFG idle + SSD(J/K) + preamble data + MAC data + ESD(T/R)
        mac_data_codes = mac_codes[2:-2]   # strip J/K and T/R (already encoded)
        full_codes = (ifg_idle_codes +
                      [_4B5B_CTRL_TABLE['J'], _4B5B_CTRL_TABLE['K']] +
                      pr_codes +
                      mac_data_codes +
                      [_4B5B_CTRL_TABLE['T'], _4B5B_CTRL_TABLE['R']])

        mlt3 = apply_mlt3(full_codes)

        # Encoded MAC bytes: pack 5-bit codes as bits then to bytes
        mac_bits = ''.join(format(c, '05b') for c in mac_data_codes)
        enc_bytes = bytes(int(mac_bits[i:i+8], 2) for i in range(0, len(mac_bits)-7, 8))
        phy_bits  = ''.join(format(c, '05b') for c in full_codes)

        result['encoded_mac_hex'] = enc_bytes.hex().upper()
        result['phy_stream_hex']  = _bits_to_hex(phy_bits)
        result['phy_stream_bits'] = phy_bits
        result['components'] = [
            dict(name=f'IFG ({idle_count}B = {len(ifg_idle_codes)} IDLE codes)',
                 type='phy_control', hex='(I=11111 symbols)',
                 note='Fixed PHY IDLE pattern — NOT encoded from MAC data'),
            dict(name='J+K SSD (Start-Stream-Delimiter)', type='phy_control',
                 hex='11000 10001', note='PHY stream start — NOT from MAC data'),
            dict(name='Preamble+SFD (PHY framing)', type='phy_framing',
                 hex=phy_preamble.hex().upper(), note='Encoded as 4B/5B data codes'),
            dict(name=f'MAC Frame ({len(mac_frame)}B) ENCODED', type='mac_encoded',
                 hex=mac_frame.hex().upper(), note='Full MAC → 4B/5B data codes'),
            dict(name='T+R ESD (End-Stream-Delimiter)', type='phy_control',
                 hex='01101 00111', note='PHY stream end — NOT from MAC data'),
        ]
        result['stats'] = dict(
            mac_frame_bytes=len(mac_frame), mac_4b5b_codes=len(mac_data_codes),
            mac_encoded_bits=len(mac_data_codes)*5, total_phy_codes=len(full_codes),
            total_phy_bits=len(full_codes)*5, line_rate='125 Mbaud',
        )

    # ── 1G — 8b/10b ──────────────────────────────────────────────────────────
    elif speed_key in ('1G', 'FC_1G', 'FC_4G'):
        rd = initial_rd
        phy_preamble = bytes([0x55]*7 + [0xD5])

        # IFG: /I/ ordered sets — K28.5(0xBC) + D16.2(0x50) repeated
        # IEEE 802.3z: /I2/ = K28.5+D16.2 when entering RD-; /I1/ = K28.5+D5.6 when RD+
        ifg_sets  = max(1, idle_count // 4)
        ifg_bytes = bytes([0xBC, 0x50] * ifg_sets)
        ifg_k_pos = set(range(0, len(ifg_bytes), 2))
        ifg_cws, rd = encode_bytes_8b10b(ifg_bytes, rd, k_positions=ifg_k_pos)

        # /S/ Start-of-Packet: K27.7(0xFB) + D21.5(0xB5)
        sop_cws, rd = encode_bytes_8b10b(bytes([0xFB, 0xB5]), rd, k_positions={0})

        # Preamble + SFD (encoded as 8b/10b data characters)
        pr_cws,  rd = encode_bytes_8b10b(phy_preamble, rd)

        # ── FULL MAC FRAME ENCODING ────────────────────────────────────────────
        mac_cws, rd = encode_bytes_8b10b(mac_frame, rd)

        # /T/ + /R/ End-of-Packet: K29.7(0xFD) + K23.7(0xF7)
        eop_cws, rd = encode_bytes_8b10b(bytes([0xFD, 0xF7]), rd, k_positions={0, 1})

        # Encoded MAC hex
        mac_bits_str = codewords_to_bitstring(mac_cws)
        enc_bytes    = bytes(int(mac_bits_str[i:i+8], 2)
                              for i in range(0, len(mac_bits_str)-7, 8))
        result['encoded_mac_hex'] = enc_bytes.hex().upper()
        result['mac_codewords']   = mac_cws

        # Full PHY stream
        all_cws  = ifg_cws + sop_cws + pr_cws + mac_cws + eop_cws
        phy_bits = codewords_to_bitstring(all_cws)
        result['phy_stream_hex']  = _bits_to_hex(phy_bits)
        result['phy_stream_bits'] = phy_bits
        result['final_rd']        = rd

        result['components'] = [
            dict(name=f'IFG ({ifg_sets}× /I/ ordered sets)', type='phy_control',
                 hex=codewords_to_hex(ifg_cws),
                 note='K28.5+D16.2 fixed pattern — NOT encoded from MAC data'),
            dict(name='/S/ Start-of-Packet K27.7+D21.5', type='phy_control',
                 hex=codewords_to_hex(sop_cws),
                 note='Fixed K-code — NOT from MAC data'),
            dict(name='Preamble(7B)+SFD(0xD5)', type='phy_framing',
                 hex=phy_preamble.hex().upper(),
                 note='PHY framing bytes encoded as 8b/10b data symbols'),
            dict(name=f'MAC Frame ({len(mac_frame)}B) ENCODED', type='mac_encoded',
                 hex=mac_frame.hex().upper(),
                 note='FULL MAC: Dst+Src+EtherType+Payload+FCS → 8b/10b codewords'),
            dict(name='/T/+/R/ End-of-Packet K29.7+K23.7', type='phy_control',
                 hex=codewords_to_hex(eop_cws),
                 note='Fixed K-codes — NOT from MAC data'),
        ]
        result['stats'] = dict(
            mac_frame_bytes=len(mac_frame),
            mac_codewords=len(mac_cws),
            mac_encoded_bits=len(mac_cws)*10,
            total_codewords=len(all_cws),
            total_phy_bits=len(all_cws)*10,
            initial_rd='RD-',
            final_rd=f'RD{"+" if rd>0 else "-"}',
            efficiency='80% (8/10)',
            line_rate='1.25 Gbaud' if speed_key=='1G' else '4.25 Gbaud' if speed_key=='FC_4G' else '1.0625 Gbaud',
        )

    # ── 10G/25G/40G/50G/100G/200G — 64b/66b ──────────────────────────────────
    # IEEE 802.3ae Clause 49 / 802.3by Clause 107
    #
    # Every 66-bit block = 2-bit sync header + 64-bit payload
    #
    # CONTROL block (sync = 10):
    #   - 64-bit payload = type_byte[7:0](8b) + data[55:0](56b)
    #   - type_byte = 0x1E (Idle), 0x78 (Start), 0x87/0xE1/0xFF etc (Terminate)
    #   - Only the DATA portion of the payload is scrambled (not type byte, not sync)
    #   - IFG: type=0x1E, 56-bit reserved = 0x00…00
    #   - Start: type=0x78, 56-bit = 7 preamble bytes (0x55×6 + 0xD5 last byte)
    #   - Term:  type=0xNN, 56-bit = remaining data bytes + zero padding
    #
    # DATA block (sync = 01):
    #   - 64-bit payload = 8 bytes of pure data (all scrambled)
    #   - No type byte in data blocks — full 64 bits are data
    #   - Scrambler is CONTINUOUS across all data blocks (state maintained)
    #
    # LFSR scrambler (IEEE 802.3ae Clause 49.2.6):
    #   Polynomial: G(x) = 1 + x^39 + x^58
    #   Initial state: all-ones (58-bit shift register)
    #   Applied to: data block payloads + data portion of control block payloads
    #   NOT applied to: 2-bit sync headers or type bytes
    #   Output bit: s[n] = s[n-39] XOR s[n-58]
    #   Scrambled bit: data_bit XOR s[n]
    elif speed_key in ('10G','25G','40G','50G','100G','200G','FC_16G'):
        phy_preamble_sfd = bytes([0x55]*7 + [0xD5])   # 8 bytes
        ifg_blocks       = max(2, idle_count // 8)

        # ── IEEE 802.3ae Clause 49 LFSR scrambler ─────────────────────────────
        # G(x) = 1 + x^39 + x^58 — 58-bit Fibonacci LFSR
        # State register s[0..57], s[0]=newest, s[57]=oldest
        # Next bit: s_new = s[57] XOR s[38]   (positions 58 and 39 from output end)
        # Scramble:  out = data_bit XOR s[57]  (output before shift)
        lfsr_state: list[int] = [1] * 58   # initial state = all-ones

        def _scr_bit() -> int:
            """Generate one scrambler output bit and advance LFSR."""
            out = lfsr_state[57]                      # output oldest bit
            new = lfsr_state[57] ^ lfsr_state[38]    # feedback
            lfsr_state.pop()                          # shift right
            lfsr_state.insert(0, new)                 # insert new bit at position 0
            return out

        def _scr_byte(b: int) -> int:
            """Scramble one byte (MSB first) using continuous LFSR state."""
            result_byte = 0
            for bit_pos in range(7, -1, -1):          # MSB first
                data_bit = (b >> bit_pos) & 1
                scr_bit  = _scr_bit()
                result_byte = (result_byte << 1) | (data_bit ^ scr_bit)
            return result_byte

        def _scr_bytes(data: bytes) -> bytes:
            """Scramble a sequence of bytes."""
            return bytes(_scr_byte(b) for b in data)

        # ── Block list ─────────────────────────────────────────────────────────
        # Each block: dict with sync(int), payload_bits(str,64b), kind, labels
        all_blocks: list[dict] = []

        # IFG: Idle control blocks
        # Control block payload = type_byte(0x1E) + 56 bits zero = 8 bytes
        # Scrambler is NOT applied to Idle block payloads (per Clause 49.2.6)
        idle_payload_bytes = bytes([0x1E]) + bytes(7)   # 0x1E + 7×0x00
        idle_payload_bits  = ''.join(format(b,'08b') for b in idle_payload_bytes)

        for idx in range(ifg_blocks):
            # 66-bit block: sync(10) + type(0x1E,8b) + 56b zeros
            block_bits = '10' + idle_payload_bits   # 2 + 64 = 66 bits
            all_blocks.append(dict(
                sync='10', kind='phy_control',
                type_byte=0x1E,
                payload_bytes=idle_payload_bytes,
                block_bits=block_bits,
                label=f'Idle Block {idx+1} (IFG)',
                raw_hex='(IDLE — fixed PHY pattern)',
                note=f'sync=10 CTRL | type=0x1E (Idle) | 56b reserved=0x00…',
            ))

        # Start block (type 0x78 — Start in lane 0)
        # Control block payload = type_byte(0x78) + 7 preamble bytes (not SFD)
        # Preamble = 0x55×6 + 0xD5 (note: 0xD5 is last preamble/SFD byte)
        # Per IEEE 802.3ae, Start block carries first 7 bytes of preamble (excluding final 0xD5)
        # Actually: payload[7:1] = preamble (6×0x55), payload[63:56] = 0xD5 (SFD)
        # Simplified: type(0x78) + 0x55×6 + 0xD5 = 8 bytes
        start_data_bytes  = bytes([0x55]*6 + [0xD5])   # 7 bytes (56 bits)
        start_payload     = bytes([0x78]) + start_data_bytes
        start_payload_bits= ''.join(format(b,'08b') for b in start_payload)
        start_block_bits  = '10' + start_payload_bits

        all_blocks.append(dict(
            sync='10', kind='phy_framing',
            type_byte=0x78,
            payload_bytes=start_payload,
            block_bits=start_block_bits,
            label='Start Block (type=0x78)',
            raw_hex=phy_preamble_sfd.hex().upper(),
            note='sync=10 CTRL | type=0x78 (Start lane 0) | 56b = preamble 0x55×6+0xD5',
        ))

        # Data blocks: FULL MAC frame divided into 64-bit (8-byte) units
        # Scrambler state is continuous from this point
        # NOTE: SFD (0xD5) was already in Start block, so MAC frame starts fresh
        mac_raw = mac_frame   # Dst+Src+EtherType+Payload+FCS — exactly what we encode

        # Pad MAC frame to multiple of 8 bytes for block alignment
        pad_needed = (8 - len(mac_raw) % 8) % 8
        mac_padded = mac_raw + bytes(pad_needed)

        n_blocks = len(mac_padded) // 8
        mac_enc_parts: list[str] = []

        for blk_idx in range(n_blocks):
            chunk     = mac_padded[blk_idx*8 : (blk_idx+1)*8]   # 8 bytes = 64 bits
            is_last   = (blk_idx == n_blocks - 1)
            valid_end = blk_idx*8 + 8 - pad_needed               # last valid byte index+1

            if is_last and pad_needed > 0:
                # Terminate control block
                # Number of valid data bytes in this block
                valid_bytes = 8 - pad_needed
                # Terminate type byte encodes position of last valid byte
                # T0(0xFF)=0 valid, T1(0xE1)=1, T2(0xE2)=2, T3(0xCC)=3,
                # T4(0xB4)=4, T5(0x99)=5, T6(0xAA)=6, T7(0x87)=7 valid bytes
                term_type_map = {0:0xFF, 1:0xE1, 2:0xE2, 3:0xCC,
                                  4:0xB4, 5:0x99, 6:0xAA, 7:0x87}
                term_type = term_type_map.get(valid_bytes, 0xFF)

                # Terminate block payload:
                # byte 0 = type_byte
                # bytes 1..valid_bytes = data (scrambled)
                # bytes valid_bytes+1..7 = padding 0x00 (NOT scrambled per spec)
                data_portion = chunk[:valid_bytes]
                scr_data     = _scr_bytes(data_portion)         # scramble only data
                padding      = bytes(8 - 1 - valid_bytes)       # zeros for padding
                term_payload = bytes([term_type]) + scr_data + padding
                term_bits    = '10' + ''.join(format(b,'08b') for b in term_payload)

                all_blocks.append(dict(
                    sync='10', kind='mac_encoded',
                    type_byte=term_type,
                    payload_bytes=term_payload,
                    block_bits=term_bits,
                    label=f'Terminate Block (type=0x{term_type:02X}, T{valid_bytes})',
                    raw_hex=chunk.hex().upper(),
                    note=(f'sync=10 CTRL | type=0x{term_type:02X} ({valid_bytes} valid bytes) | '
                          f'data scrambled | {pad_needed}B padding'),
                ))
                mac_enc_parts.append(scr_data.hex().upper())

            else:
                # Regular data block — full 64 bits of scrambled data
                scr_chunk   = _scr_bytes(chunk)                 # scramble all 8 bytes
                data_bits   = ''.join(format(b,'08b') for b in scr_chunk)
                data_block  = '01' + data_bits                  # sync=01 + 64b data

                all_blocks.append(dict(
                    sync='01', kind='mac_encoded',
                    type_byte=None,
                    payload_bytes=scr_chunk,
                    block_bits=data_block,
                    label=f'Data Block {blk_idx+1}',
                    raw_hex=chunk.hex().upper(),
                    note='sync=01 DATA | 64b = 8 bytes scrambled MAC data (no type byte)',
                ))
                mac_enc_parts.append(scr_chunk.hex().upper())

        # ── Assemble PHY bitstream and component list ──────────────────────────
        phy_bits = ''.join(blk['block_bits'] for blk in all_blocks)

        # Encoded MAC hex = scrambled data from all data+terminate blocks
        enc_mac_hex = ''.join(mac_enc_parts)

        # Component list for display
        comps: list[dict] = []
        for blk in all_blocks:
            type_str = f"0x{blk['type_byte']:02X}" if blk['type_byte'] is not None else 'no type (data)'
            # Show 66-bit block as hex
            blk_hex = _bits_to_hex(blk['block_bits'])[:18]
            comps.append(dict(
                name=blk['label'],
                type=blk['kind'],
                hex=blk['raw_hex'],
                encoded_hex=blk_hex,
                note=blk['note'],
                block_66_bits=blk['block_bits'],
            ))

        result['encoded_mac_hex'] = enc_mac_hex
        result['phy_stream_hex']  = _bits_to_hex(phy_bits)
        result['phy_stream_bits'] = phy_bits
        result['components']      = comps
        result['stats'] = dict(
            mac_frame_bytes   = len(mac_frame),
            data_blocks       = sum(1 for b in all_blocks if b['sync']=='01'),
            terminate_blocks  = sum(1 for b in all_blocks if b['sync']=='10' and b['type_byte'] not in (0x1E,0x78)),
            idle_blocks       = ifg_blocks,
            total_blocks      = len(all_blocks),
            total_phy_bits    = len(all_blocks) * 66,
            block_size_bits   = 66,
            sync_header       = '01=data  10=control  (2 bits, NOT scrambled)',
            type_byte         = '8 bits in control block payload (NOT scrambled)',
            data_payload      = '56 bits in control block OR 64 bits in data block (scrambled)',
            lfsr_polynomial   = 'x^58 + x^39 + 1  (58-bit Fibonacci LFSR)',
            lfsr_init         = 'all-ones (58 bits)',
            scramble_scope    = 'Data bytes only — type_byte and sync header NOT scrambled',
            pad_bytes         = pad_needed,
            efficiency        = '97.0% (64/66)',
            line_rate         = PHY_REGISTRY.get(speed_key,{}).get('line_rate',''),
            fec               = 'KP4 RS(544,514) required for 25G+' if speed_key != '10G' else 'optional',
        )

    # ── 400G/800G — PAM4 8-lane ───────────────────────────────────────────────
    elif speed_key in ('400G','800G','FC_32G'):
        # PAM4 / 256b/257b — symbolic display (hardware-generated)
        lanes = 8
        result['encoded_mac_hex'] = mac_frame.hex().upper()  # symbolic
        result['phy_stream_hex']  = mac_frame.hex().upper()
        result['components'] = [
            dict(name=f'IFG ({idle_count}B across {lanes} lanes)', type='phy_control',
                 hex='(PAM4 idle symbols)', note='Fixed PHY idle — NOT from MAC data'),
            dict(name='Start Blocks (all lanes)', type='phy_framing',
                 hex='(per-lane Start Block)', note='Preamble in Start Block payload'),
            dict(name=f'MAC Frame ({len(mac_frame)}B) ENCODED', type='mac_encoded',
                 hex=mac_frame.hex().upper(),
                 note=f'PAM4 {lanes}-lane + RS-FEC + scrambled 64b/66b or 256b/257b'),
            dict(name='Terminate Blocks + FEC', type='phy_control',
                 hex='(per-lane Terminate)', note='FEC codeword boundary'),
        ]
        result['stats'] = dict(
            mac_frame_bytes=len(mac_frame), lanes=lanes,
            encoding='PAM4 64b/66b' if speed_key in ('400G','800G') else '256b/257b',
            fec='KP4 RS(544,514) mandatory',
            line_rate=PHY_REGISTRY.get(speed_key,{}).get('line_rate',''),
        )

    else:
        # 2.5G, 5G, serial, unknown speeds
        # PHY framing is hardware-managed; show IFG + encoded MAC
        result['encoded_mac_hex'] = mac_frame.hex().upper()
        result['phy_stream_hex']  = mac_frame.hex().upper()
        result['components'] = [
            dict(name=f'IFG ({idle_count}B — hardware managed)', type='phy_control',
                 hex='(PHY idle symbols)', note=f'{speed_key} IFG — hardware-generated idle pattern'),
            dict(name=f'MAC Frame ({len(mac_frame)}B)', type='mac_encoded',
                 hex=mac_frame.hex().upper(),
                 note=f'{speed_key} encoding — PHY hardware applies {PHY_REGISTRY.get(speed_key,{}).get("encoding","")}'),
        ]
        result['stats'] = dict(
            mac_frame_bytes=len(mac_frame),
            note=f'{speed_key}: PHY layer framing (IFG, Start, End) managed by hardware PHY chip',
            encoding=PHY_REGISTRY.get(speed_key,{}).get('encoding',''),
        )

    return result


# ── FC frame encoder ────────────────────────────────────────────────────────────

def encode_fc_frame_8b10b(sof_name: str, header_bytes: bytes,
                            payload: bytes, crc_bytes: bytes,
                            eof_name: str, initial_rd: int = -1) -> dict:
    """Encode complete FC native frame using 8b/10b."""
    sof_b = FC_SOF_BYTES.get(sof_name, FC_SOF_BYTES['SOFi3'])
    eof_b = FC_EOF_BYTES.get(eof_name, FC_EOF_BYTES['EOFt'])
    rd    = initial_rd
    result: dict = {'components': [], 'final_rd': 0, 'total_bits': 0}

    def _add(name: str, data: bytes, k_pos: set | None = None) -> None:
        nonlocal rd
        cws, rd = encode_bytes_8b10b(data, rd, k_positions=k_pos)
        result['components'].append(dict(name=name, codewords=cws, rd_after=rd,
                                          hex_in=data.hex().upper()))

    _add('IDLE',              FC_IDLE_BYTES, {0})
    _add(f'SOF ({sof_name})', sof_b,         {0})
    _add('FC Header (24B)',   header_bytes)
    if payload:
        _add(f'Payload ({len(payload)}B)', payload)
    _add('FC CRC (4B)',       crc_bytes)
    _add(f'EOF ({eof_name})', eof_b, {0})

    result['final_rd']    = rd
    result['total_bits']  = sum(len(c['codewords']) for c in result['components']) * 10
    return result


# ── Encoding display formatter ────────────────────────────────────────────────

def format_phy_stream_display(result: dict, max_hex_chars: int = 56) -> list[str]:
    """
    Format PHY stream result for terminal display.
    Shows A=before encoding, B=after encoding, C=full PHY stream.
    """
    speed = result.get('speed', '')
    enc   = result.get('encoding', '')

    def _tr(s: str, n: int) -> str:
        return (s[:n] + '…') if len(s) > n else s

    lines = [
        f"  ══ PHY ENCODING  [{speed}]  {enc}",
        f"  {'─'*72}",
        f"  A.  MAC Frame (BEFORE encoding)  [{len(result.get('mac_frame_hex',''))//2}B]:",
        f"      {_tr(result.get('mac_frame_hex',''), max_hex_chars)}",
        f"      Dst(6B) + Src(6B) + EtherType(2B) + Payload + FCS(4B)",
        f"  B.  Encoded MAC Frame (AFTER encoding):",
        f"      {_tr(result.get('encoded_mac_hex',''), max_hex_chars)}",
        f"      ↑ Full MAC frame encoded — NOT preamble/SFD alone",
        f"  C.  Full PHY Stream  [IFG + Start + Encoded + End]:",
        f"      {_tr(result.get('phy_stream_hex',''), max_hex_chars)}",
        f"      ↑ Control symbols inserted AFTER encoding",
        f"  {'─'*72}",
        f"  Stream segments:",
    ]
    type_marker = {'phy_control': '[CTL]', 'phy_framing': '[PHY]', 'mac_encoded': '[ENC]'}
    for comp in result.get('components', []):
        mk   = type_marker.get(comp.get('type',''), '[   ]')
        name = comp.get('name', '')
        hx   = _tr(comp.get('encoded_hex') or comp.get('hex', ''), 20)
        note = comp.get('note', '')
        lines.append(f"    {mk}  {name:<38}  {hx:<22}  {note}")
    lines.append(f"  {'─'*72}")
    for k, v in result.get('stats', {}).items():
        lines.append(f"    {k:<30}: {v}")
    if result.get('final_rd', 0) != 0:
        lines.append(f"    {'final_running_disparity':<30}: {'RD+' if result['final_rd']>0 else 'RD-'}")
    return lines


# Legacy alias
def encode_eth_frame_8b10b(frame_bytes: bytes, initial_rd: int = -1,
                             preamble_sfd_included: bool = True) -> dict:
    """Legacy wrapper — uses build_phy_stream internally."""
    mac = frame_bytes[8:] if preamble_sfd_included and len(frame_bytes)>8 else frame_bytes
    return build_phy_stream(mac, '1G', initial_rd=initial_rd)

def format_encoding_display(result: dict, speed_key: str,
                              max_codewords_shown: int = 4) -> list[str]:
    return format_phy_stream_display(result)
