"""Tests for the BLE provisioning codec.

Known-answer vectors were computed by hand from the decompiled ThinQ code
(BleDataUtils.java), not by running codec.py, so they check the reimplementation.
Run:  python3 -m unittest discover -s tests -v
"""
import importlib.machinery
import importlib.util
import os
import subprocess
import sys
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lgsuite import codec  # noqa: E402


def load_cli():
    loader = importlib.machinery.SourceFileLoader("lg_setup_cli", os.path.join(ROOT, "lg-setup"))
    spec = importlib.util.spec_from_loader("lg_setup_cli", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class KeyAndUuids(unittest.TestCase):
    def test_key_matches_decompiled_enc_key(self):
        # BleDataUtils.ENC_KEY = {109,117,115,TLVConstants.BLE_MSY_TYPE_PRODUCT_INFO(=105),67,32,102,108,111,87}
        self.assertEqual(codec.KEY, bytes([109, 117, 115, 105, 67, 32, 102, 108, 111, 87]))

    def test_uuids_match_bleuuid_java(self):
        self.assertEqual(codec.CHAR_SSID, "b02077e1-13be-11e5-ba08-0002a5d5c51b")
        self.assertEqual(codec.CHAR_PASSWD, "b02077e2-13be-11e5-ba08-0002a5d5c51b")
        self.assertEqual(codec.CHAR_COMMAND, "b02077e5-13be-11e5-ba08-0002a5d5c51b")
        self.assertEqual(codec.CHAR_NOTIFY, "b02077e6-13be-11e5-ba08-0002a5d5c51b")
        self.assertEqual(codec.CHAR_LG_APP, "b02077e9-13be-11e5-ba08-0002a5d5c51b")
        self.assertEqual(codec.CHAR_SECURITY, "b02077ea-13be-11e5-ba08-0002a5d5c51b")
        self.assertEqual(codec.CHAR_WIFI_MAC, "b02077ec-13be-11e5-ba08-0002a5d5c51b")
        self.assertIn("0000fc79-0000-1000-8000-00805f9b34fb", codec.SERVICE_UUIDS)


class Encoding(unittest.TestCase):
    def test_hello_known_answer(self):
        # header 0x10 (1 chunk, idx 0) + "C400" = 10 43 34 30 30, XOR 6d 75 73 69 43
        self.assertEqual(codec.encode_str("C400"), [bytes.fromhex("7d 36 47 59 73")])

    def test_single_char_commands(self):
        self.assertEqual(codec.encode_str("9"), [bytes.fromhex("7d 4c")])  # 10^6d, 39^75
        self.assertEqual(codec.encode_str("0"), [bytes.fromhex("7d 45")])  # 30^75
        self.assertEqual(codec.encode_str("4"), [bytes.fromhex("7d 41")])  # 34^75

    def test_unknown_bssid_known_answer(self):
        # 10 | 00 02 00 00 00 00 00  XOR  6d 75 73 69 43 20 66 6c
        self.assertEqual(codec.encode_bssid(None), [bytes.fromhex("7d 75 71 69 43 20 66 6c")])
        self.assertEqual(codec.encode_bssid("garbage"), codec.encode_bssid(None))

    def test_bssid_payload(self):
        pkts = codec.encode_bssid("aa:bb:cc:dd:ee:ff")
        self.assertEqual(len(pkts), 1)
        self.assertEqual(codec.decode(pkts), bytes.fromhex("00 aa bb cc dd ee ff"))

    def test_empty_gives_no_packets(self):
        self.assertEqual(codec.encode_str(""), [])

    def test_chunk_boundaries_and_headers(self):
        for length, expected in [(1, 1), (18, 1), (19, 2), (36, 2), (37, 3), (63, 4)]:
            data = bytes(range(65, 65 + length))
            pkts = codec.encode(data)
            self.assertEqual(len(pkts), expected, length)
            for i, p in enumerate(pkts):
                plain = codec.xor(p)
                self.assertEqual(plain[0], (expected << 4) | i)
                self.assertLessEqual(len(p), 19)  # fits a default-MTU write (20)
            self.assertEqual(codec.decode(pkts), data)

    def test_key_restarts_every_chunk(self):
        pkts = codec.encode(b"\x00" * 30)
        # second chunk: header 0x21, then zeros -> raw key bytes from index 1
        self.assertEqual(pkts[1][:4], bytes([0x21 ^ 0x6D, 0x75, 0x73, 0x69]))

    def test_utf8_ssid(self):
        ssid = "Café 🎶"
        self.assertEqual(codec.decode(codec.encode_str(ssid)).decode(), ssid)

    def test_too_long(self):
        with self.assertRaises(ValueError):
            codec.encode(b"x" * (18 * 15 + 1))

    def test_decode_rejects_bad_order(self):
        pkts = codec.encode(b"y" * 40)
        with self.assertRaises(ValueError):
            codec.decode([pkts[1], pkts[0], pkts[2]])


class Notifications(unittest.TestCase):
    def test_states(self):
        self.assertEqual(codec.parse_notification(b"B").name, "AP_INTERNET_CONNECTED")
        self.assertEqual(codec.parse_notification(b"3").name, "INVALID_PASSWORD")
        self.assertEqual(codec.parse_notification(b"\x99").name, "UNKNOWN_0x99")
        self.assertEqual(codec.parse_notification(b"").name, "EMPTY")

    def test_rssi(self):
        n = codec.parse_notification(b"D\x03-55")
        self.assertEqual(n.rssi, "-55")

    def test_wifi_mac_notification(self):
        mac = bytes.fromhex("8e2ac10e9f34")
        n = codec.parse_notification(b"J" + codec.xor(mac))
        self.assertEqual(n.wifi_mac, "8E:2A:C1:0E:9F:34")

    def test_wifi_mac_read(self):
        mac = bytes.fromhex("8c2ac10e9f36")
        self.assertEqual(codec.decode_wifi_mac_read(codec.xor(mac)), "8C:2A:C1:0E:9F:36")
        self.assertIsNone(codec.decode_wifi_mac_read(b"\x00\x00"))  # value seen before HELLO
        self.assertIsNone(codec.decode_wifi_mac_read(codec.xor(b"\x00" * 6)))

    def test_connected_ssid_pieces(self):
        # BleConnectManager.k: data[1] = len incl. header, data[2] = header, data[3:] = bytes
        single = bytes([ord("F"), 9, 0x10]) + b"STARLINK"
        n = codec.parse_notification(single)
        self.assertEqual(n.ssid_part, b"STARLINK")
        self.assertTrue(n.ssid_last)

        first = bytes([ord("F"), 4, 0x20]) + b"abc"
        last = bytes([ord("F"), 3, 0x21]) + b"de"
        a, b = codec.parse_notification(first), codec.parse_notification(last)
        self.assertEqual((a.ssid_part, a.ssid_last), (b"abc", False))
        self.assertEqual((b.ssid_part, b.ssid_last), (b"de", True))


class Beacon(unittest.TestCase):
    def test_observed_m7_beacon(self):
        info = codec.parse_manufacturer_data(bytes.fromhex("c498029f358e2ac10e9f340000"))
        self.assertEqual(info["wifi_direct_mac"], "8E:2A:C1:0E:9F:34")
        self.assertEqual(info["bt_mac_suffix"], "9F:35")
        self.assertEqual(info["mode"], "setup")

    def test_observed_m7_normal_mode_beacon(self):
        info = codec.parse_manufacturer_data(bytes.fromhex("00000198002600"))
        self.assertEqual(info["mode"], "normal")
        self.assertNotIn("wifi_direct_mac", info)


class Cli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = load_cli()

    def test_nmcli_parsing(self):
        out = ("STARLINK:42\\:7B\\:8F\\:3E\\:04\\:76:100\n"
               "Weird\\:Name:AA\\:BB\\:CC\\:DD\\:EE\\:FF:40\n"
               ":12\\:34\\:56\\:78\\:9A\\:BC:90\n")
        fake = subprocess.CompletedProcess([], 0, stdout=out, stderr="")
        with mock.patch.object(self.cli.shutil, "which", return_value="/usr/bin/nmcli"), \
                mock.patch.object(self.cli.subprocess, "run", return_value=fake):
            nets = self.cli.nmcli_networks()
            self.assertEqual(nets, [("STARLINK", "42:7B:8F:3E:04:76", 100),
                                    ("Weird:Name", "AA:BB:CC:DD:EE:FF", 40)])
            bssid, _ = self.cli.resolve_bssid("auto", "STARLINK")
            self.assertEqual(bssid, "42:7B:8F:3E:04:76")
            bssid, _ = self.cli.resolve_bssid("auto", "NotVisible")
            self.assertEqual(bssid, codec.UNKNOWN_BSSID)
        self.assertEqual(self.cli.resolve_bssid("none", "x")[0], codec.UNKNOWN_BSSID)
        self.assertEqual(self.cli.resolve_bssid("aa:bb:cc:dd:ee:ff", "x")[0], "AA:BB:CC:DD:EE:FF")


if __name__ == "__main__":
    unittest.main()
