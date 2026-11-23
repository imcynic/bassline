#!/usr/bin/env python3
"""Minimal SDP browser: dumps every service record a Bluetooth device exposes.
Usage: python3 sdp_dump.py AA:BB:CC:DD:EE:FF
"""
import socket, struct, sys

UUID_NAMES = {
    0x0001: "SDP", 0x0003: "RFCOMM", 0x0100: "L2CAP", 0x0017: "AVCTP", 0x0019: "AVDTP",
    0x1101: "SerialPort", 0x110A: "AudioSource", 0x110B: "AudioSink", 0x110C: "AVRCP-Target",
    0x110D: "A2DP", 0x110E: "AVRCP", 0x110F: "AVRCP-Controller", 0x1002: "PublicBrowseGroup",
    0x1200: "PnPInfo", 0x111E: "Handsfree", 0x1108: "Headset", 0x1800: "GAP", 0x1801: "GATT",
}
ATTR_NAMES = {
    0x0000: "RecordHandle", 0x0001: "ServiceClassIDList", 0x0004: "ProtocolDescriptorList",
    0x0005: "BrowseGroupList", 0x0006: "LangBaseAttrIDList", 0x0009: "ProfileDescriptorList",
    0x000D: "AdditionalProtocolDescriptorLists", 0x0100: "ServiceName",
    0x0101: "ServiceDescription", 0x0102: "ProviderName", 0x0311: "SupportedFeatures",
    0x0200: "VersionNumberList/SpecID", 0x0201: "VendorID", 0x0202: "ProductID",
    0x0203: "Version", 0x0205: "VendorIDSource",
}


def parse(buf, i=0):
    """Parse one SDP data element; returns (value, next_index)."""
    d = buf[i]; t, sz = d >> 3, d & 7; i += 1
    if t == 0:
        return None, i
    if sz < 5:
        n = [1, 2, 4, 8, 16][sz]
    else:
        ln = [1, 2, 4][sz - 5]
        n = int.from_bytes(buf[i:i + ln], "big"); i += ln
    raw = buf[i:i + n]; i += n
    if t == 1:
        return ("uint", int.from_bytes(raw, "big")), i
    if t == 2:
        return ("int", int.from_bytes(raw, "big", signed=True)), i
    if t == 3:
        if n == 16:
            h = raw.hex()
            return ("uuid", f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"), i
        v = int.from_bytes(raw, "big")
        return ("uuid", f"0x{v:04x} ({UUID_NAMES.get(v, '?')})"), i
    if t == 4 or t == 8:
        return ("str", raw.decode(errors="replace").rstrip("\x00")), i
    if t == 5:
        return ("bool", bool(raw[0])), i
    if t in (6, 7):
        items, j = [], 0
        while j < len(raw):
            v, j = parse(raw, j)
            items.append(v)
        return ("seq", items), i
    return ("raw", raw.hex()), i


def fmt(v, ind=0):
    pad = "  " * ind
    if v is None:
        return pad + "nil"
    k, x = v
    if k == "seq":
        return "\n".join(fmt(e, ind) for e in x) if x else pad + "[]"
    if k == "uint":
        return f"{pad}0x{x:x} ({x})"
    return f"{pad}{x!r}" if k == "str" else f"{pad}{x}"


def main(addr):
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    s.settimeout(10)
    s.connect((addr, 1))  # PSM 1 = SDP
    pattern = bytes([0x35, 3, 0x19, 0x01, 0x00])           # seq{ UUID16 L2CAP } — matches everything
    attrs = bytes([0x35, 5, 0x0A, 0x00, 0x00, 0xFF, 0xFF])  # seq{ range 0x0000-0xFFFF }
    data, cont, tid = b"", b"\x00", 1
    while True:
        params = pattern + struct.pack(">H", 0xFFFF) + attrs + cont
        s.send(struct.pack(">BHH", 0x06, tid, len(params)) + params)
        resp = s.recv(65535)
        pdu, _, plen = struct.unpack(">BHH", resp[:5])
        if pdu != 0x07:
            sys.exit(f"SDP error PDU 0x{pdu:02x}: {resp.hex()}")
        blen = struct.unpack(">H", resp[5:7])[0]
        data += resp[7:7 + blen]
        cont = resp[7 + blen:]
        tid += 1
        if cont[0] == 0:
            break
    s.close()
    records, _ = parse(data)
    for n, rec in enumerate(records[1]):
        items = rec[1]
        print(f"=== Record {n}")
        for a in range(0, len(items), 2):
            aid = items[a][1]
            print(f" [0x{aid:04x}] {ATTR_NAMES.get(aid, '')}")
            print(fmt(items[a + 1], 2))
    print(f"\n{len(records[1])} records")


if __name__ == "__main__":
    main(sys.argv[1])
