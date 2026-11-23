"""Wire format of the LG Sound Suite BLE Wi-Fi provisioning service.

Reimplemented from the LG ThinQ Android app (com.lgeha.nuts 5.2.12500):
    com/lge/nuts/avservicelib/soundbar/connection/ble/gatt/BleUUID.java
    com/lge/nuts/avservicelib/soundbar/connection/ble/connect/BleDataUtils.java
    com/lge/nuts/avservicelib/soundbar/connection/ble/connect/BleConnectManager.java

Every value the app writes is:
  1. split into 18-byte pieces,
  2. each piece prefixed with a header byte ((total & 0xF) << 4) | (index & 0xF),
  3. the whole piece (header included) XOR'd with the 10-byte key b"musiC floW".
One piece goes in one GATT write, so a piece never exceeds the 20-byte default ATT payload.

Notifications on the NOTIFY characteristic are *not* XOR'd except the Wi-Fi MAC ('J').
"""
from __future__ import annotations

from dataclasses import dataclass

# --- GATT layout ------------------------------------------------------------
SERVICE_UUID_16 = "0000fc79-0000-1000-8000-00805f9b34fb"
SERVICE_UUID_128 = "b02077d0-13be-11e5-ba08-0002a5d5c51b"  # older units
SERVICE_UUIDS = (SERVICE_UUID_16, SERVICE_UUID_128)


def _char(n: str) -> str:
    return f"b02077{n}-13be-11e5-ba08-0002a5d5c51b"


CHAR_SSID = _char("e1")
CHAR_PASSWD = _char("e2")
CHAR_COMMAND = _char("e5")
CHAR_NOTIFY = _char("e6")
CHAR_LG_APP = _char("e9")
CHAR_SECURITY = _char("ea")
CHAR_WIFI_MAC = _char("ec")

CHAR_NAMES = {
    CHAR_SSID: "SSID", CHAR_PASSWD: "PASSWD", CHAR_COMMAND: "COMMAND", CHAR_NOTIFY: "NOTIFY",
    CHAR_LG_APP: "LG_APP", CHAR_SECURITY: "SECURITY", CHAR_WIFI_MAC: "WIFI_MAC",
}

LG_MANUFACTURER_ID = 0x00C4

# --- Commands (strings written to CHAR_COMMAND / CHAR_LG_APP) ----------------
HELLO = "C400"            # -> CHAR_LG_APP, first write after connecting
CMD_CONNECT_SECURED = "0"  # -> CHAR_COMMAND after SECURITY, network has a password
CMD_CONNECT_OPEN = "4"     # -> CHAR_COMMAND after SECURITY, open network
CMD_GET_SSID = "9"         # -> CHAR_COMMAND, speaker answers with 'F' notifications

# --- Encoding ---------------------------------------------------------------
KEY = b"musiC floW"
CHUNK = 18
MAX_CHUNKS = 15  # header nibbles are 4 bits wide
UNKNOWN_BSSID = "02:00:00:00:00:00"  # what the app sends when it can't read the BSSID


def xor(data: bytes) -> bytes:
    """BleDataUtils.b / decryptXOR — symmetric, key index restarts at 0 for every call."""
    return bytes(b ^ KEY[i % len(KEY)] for i, b in enumerate(data))


def encode(data: bytes) -> list[bytes]:
    """BleDataUtils.c — split, add header, XOR. Empty input gives no packets."""
    total = (len(data) + CHUNK - 1) // CHUNK
    if total > MAX_CHUNKS:
        raise ValueError(f"value too long: {len(data)} bytes (max {CHUNK * MAX_CHUNKS})")
    out = []
    for idx in range(total):
        piece = data[idx * CHUNK:(idx + 1) * CHUNK]
        header = ((total & 0xF) << 4) | (idx & 0xF)
        out.append(xor(bytes([header]) + piece))
    return out


def encode_str(text: str) -> list[bytes]:
    """BleDataUtils.dataToByte"""
    return encode(text.encode("utf-8"))


def parse_mac(text: str | None) -> bytes | None:
    if not text:
        return None
    parts = text.strip().split(":")
    if len(parts) != 6:
        return None
    try:
        raw = bytes(int(p, 16) for p in parts)
    except ValueError:
        return None
    return raw


def encode_bssid(bssid: str | None) -> list[bytes]:
    """BleDataUtils.bssidToByteArray — 0x00 followed by the 6 MAC bytes."""
    raw = parse_mac(bssid) or parse_mac(UNKNOWN_BSSID)
    return encode(b"\x00" + raw)


def decode(packets: list[bytes]) -> bytes:
    """Inverse of encode(); used by tests and the `encode` dry run."""
    out = bytearray()
    total = None
    for expected_idx, pkt in enumerate(packets):
        plain = xor(pkt)
        hdr = plain[0]
        t, idx = hdr >> 4, hdr & 0xF
        if total is None:
            total = t
        if t != total or idx != expected_idx:
            raise ValueError(f"bad header 0x{hdr:02x} at packet {expected_idx}")
        out += plain[1:]
    if total is not None and total != len(packets):
        raise ValueError(f"expected {total} packets, got {len(packets)}")
    return bytes(out)


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02X}" for b in raw)


def decode_wifi_mac_read(value: bytes) -> str | None:
    """Value read from CHAR_WIFI_MAC: whole value XOR'd, no header (BleConnectManager.d)."""
    plain = xor(value)
    if len(plain) != 6 or plain in (b"\x00" * 6, b"\xff" * 6):
        return None
    return format_mac(plain)


# --- Notifications ------------------------------------------------------------
STATES = {
    "0": ("DISCONNECTED", "Not connected to Wi-Fi"),
    "1": ("CONNECTING_TO_AP", "Connecting to the network"),
    "2": ("CONNECTING_TO_AP", "Connecting to the network"),
    "3": ("INVALID_PASSWORD", "Wrong Wi-Fi password"),
    "4": ("AP_SCANNING", "Scanning for the network"),
    "5": ("AP_FOUND", "Network found"),
    "6": ("AP_NOT_FOUND", "Network not found (check the name, and that it's in range)"),
    "7": ("ERROR", "Speaker reported an error"),
    "8": ("CONNECTION_FAIL", "Connection failed"),
    "9": ("ERROR_ROUTER_SECURITY", "Router security mode not supported by the speaker"),
    "A": ("AP_INTERNET_NOT_CONNECTED", "Joined Wi-Fi, but no internet access"),
    "B": ("AP_INTERNET_CONNECTED", "Joined Wi-Fi with internet access"),
    "C": ("AP_CONNECT_AND_DISCONNECT", "Connected, then dropped"),
    "D": ("RSSI_VALUE", "Signal strength"),
    "E": ("FEATURE_LIST_VALUE", "Feature list"),
    "F": ("CONNECTED_SSID", "Currently connected network"),
    "I": ("DEVICE_BUTTON_NOTIFICATION", "Button pressed on the speaker"),
    "J": ("WIFI_MAC", "Speaker Wi-Fi MAC address"),
}
PROGRESS_CODES = set("12345")
FAILURE_CODES = set("36789")
SUCCESS_CODE = "B"
NO_INTERNET_CODE = "A"


@dataclass
class Notification:
    code: str
    name: str
    text: str
    raw: bytes
    rssi: str | None = None
    wifi_mac: str | None = None
    ssid_part: bytes | None = None   # for 'F'
    ssid_last: bool = False          # for 'F'

    def __str__(self) -> str:
        extra = ""
        if self.rssi is not None:
            extra = f": {self.rssi}"
        elif self.wifi_mac:
            extra = f": {self.wifi_mac}"
        return f"[{self.code}] {self.text}{extra}"


def parse_notification(data: bytes) -> Notification:
    """BleConnectManager.updateSoundbarState"""
    if not data:
        return Notification("?", "EMPTY", "Empty notification", data)
    code = chr(data[0])
    name, text = STATES.get(code, (f"UNKNOWN_0x{data[0]:02x}", f"Unknown status 0x{data[0]:02x}"))
    n = Notification(code, name, text, bytes(data))
    if code == "D" and len(data) >= 2:
        ln = data[1]
        n.rssi = bytes(data[2:2 + ln]).decode("ascii", "replace")
    elif code == "J" and len(data) >= 3:
        n.wifi_mac = format_mac(xor(bytes(data[1:])))
    elif code == "F" and len(data) >= 3:
        # data[1] = piece length incl. header, data[2] = header (total<<4 | idx), data[3:] = SSID bytes
        ln = data[1] - 1
        hdr = data[2]
        remaining = (hdr >> 4) - (hdr & 0xF)
        if remaining > 0:
            n.ssid_part = bytes(data[3:3 + ln])
        n.ssid_last = remaining == 1
    return n


def parse_manufacturer_data(value: bytes) -> dict:
    """LG beacon payload (company 0x00C4), e.g. c4 98 02 9f 35 8e 2a c1 0e 9f 34 00 00.

    Observed on an M7: bytes[3:5] = last two bytes of the speaker's classic-BT MAC,
    bytes[5:11] = the speaker's Wi-Fi Direct MAC (also the DIRECT-... AP BSSID).
    Meaning of the remaining bytes is unknown.

    In normal (Bluetooth-audio) mode the same speaker advertises a short payload instead,
    e.g. 00 00 01 98 00 26 00, from its fixed public address. Only the long form comes
    with the connectable provisioning service.
    """
    info: dict = {"raw": value.hex(" "), "mode": "unknown"}
    if len(value) >= 11:
        info["mode"] = "setup"
        info["bt_mac_suffix"] = value[3:5].hex(":").upper()
        info["wifi_direct_mac"] = format_mac(value[5:11])
    elif len(value) == 7:
        info["mode"] = "normal"
    return info
