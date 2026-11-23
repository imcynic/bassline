#!/usr/bin/env python3
"""Fake BlueZ + fake LG Sound Suite M7, served on a private D-Bus, for end-to-end tests.

It implements the slice of the org.bluez API that lg-setup uses (ObjectManager, Adapter1,
Device1, GattService1, GattCharacteristic1, Properties) and behaves like the real speaker's
provisioning service as reverse-engineered from the ThinQ app:

* its own decoder for the chunk/XOR wire format, written from BleDataUtils.java
  (deliberately not importing lgsuite.codec, so it checks the client's encoder);
* rejects out-of-order chunks, oversized writes and out-of-order steps;
* answers HELLO, Wi-Fi MAC reads and the "get SSID" command like the M7 did;
* reports AP_SCANNING → AP_FOUND → CONNECTING → result over notifications;
* drops the paired "Bluetooth audio" device when the setup service is connected, like the M7.

Usage: fake_bluez.py --report report.json [--scenario options as JSON]
Prints "READY" once it owns org.bluez on $DBUS_SESSION_BUS_ADDRESS.
"""
import argparse
import json
import os
import sys

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

PROPS = "org.freedesktop.DBus.Properties"
OM = "org.freedesktop.DBus.ObjectManager"
ADAPTER = "org.bluez.Adapter1"
DEVICE = "org.bluez.Device1"
SERVICE = "org.bluez.GattService1"
CHAR = "org.bluez.GattCharacteristic1"

KEY = bytes([109, 117, 115, 105, 67, 32, 102, 108, 111, 87])  # BleDataUtils.ENC_KEY
U = lambda n: f"b02077{n}-13be-11e5-ba08-0002a5d5c51b"  # noqa: E731
SSID, PASSWD, COMMAND, NOTIFY, LG_APP, SECURITY, WIFI_MAC = (U(x) for x in ("e1", "e2", "e5", "e6", "e9", "ea", "ec"))
EXTRA = [U(x) for x in ("e3", "e4", "e7", "e8", "eb", "ed", "ee", "ef")]
FC79 = "0000fc79-0000-1000-8000-00805f9b34fb"
A2DP_SINK = "0000110b-0000-1000-8000-00805f9b34fb"

ADAPTER_PATH = "/org/bluez/hci0"
AUDIO_PATH = ADAPTER_PATH + "/dev_8C_2A_C1_0E_9F_35"
BEACON_PATH = ADAPTER_PATH + "/dev_66_67_27_A7_BC_E1"


class Failed(dbus.DBusException):
    _dbus_error_name = "org.bluez.Error.Failed"


class InProgress(dbus.DBusException):
    _dbus_error_name = "org.bluez.Error.InProgress"


def unxor(b: bytes) -> bytes:
    return bytes(x ^ KEY[i % 10] for i, x in enumerate(b))


def ay(b: bytes) -> dbus.Array:
    return dbus.Array([dbus.Byte(x) for x in b], signature="y")


class Obj(dbus.service.Object):
    """An object with BlueZ-style properties."""

    def __init__(self, world, path, iface, props):
        super().__init__(world.bus, path)
        self.world, self.path, self.iface, self.props = world, path, iface, props
        world.objects[path] = self

    def managed(self):
        return {self.iface: self.props}

    def set(self, name, value):
        self.props[name] = value
        self.PropertiesChanged(self.iface, {name: value}, dbus.Array([], signature="s"))

    @dbus.service.method(PROPS, in_signature="ss", out_signature="v")
    def Get(self, iface, name):
        if iface != self.iface or name not in self.props:
            raise dbus.DBusException("org.freedesktop.DBus.Error.InvalidArgs")
        return self.props[name]

    @dbus.service.method(PROPS, in_signature="s", out_signature="a{sv}")
    def GetAll(self, iface):
        return self.props if iface == self.iface else {}

    @dbus.service.method(PROPS, in_signature="ssv")
    def Set(self, iface, name, value):
        self.set(name, value)

    @dbus.service.signal(PROPS, signature="sa{sv}as")
    def PropertiesChanged(self, iface, changed, invalidated):
        pass


class Root(dbus.service.Object):
    def __init__(self, world):
        super().__init__(world.bus, "/")
        self.world = world

    @dbus.service.method(OM, out_signature="a{oa{sa{sv}}}")
    def GetManagedObjects(self):
        return {dbus.ObjectPath(p): o.managed() for p, o in self.world.objects.items()
                if not getattr(o, "hidden", False)}


class Adapter(Obj):
    def __init__(self, world):
        super().__init__(world, ADAPTER_PATH, ADAPTER, {
            "Address": "44:0F:B4:23:06:13", "Powered": dbus.Boolean(True),
            "Discovering": dbus.Boolean(False)})
        self._tick = None

    @dbus.service.method(ADAPTER, in_signature="a{sv}")
    def SetDiscoveryFilter(self, f):
        self.world.log("SetDiscoveryFilter", {str(k): str(v) for k, v in f.items()})

    @dbus.service.method(ADAPTER)
    def StartDiscovery(self):
        self.set("Discovering", dbus.Boolean(True))
        self.world.log("StartDiscovery")

        def tick():
            for path in (BEACON_PATH, AUDIO_PATH):
                dev = self.world.objects.get(path)
                if dev and dev.advertising:
                    dev.set("RSSI", dbus.Int16(-60))
            return bool(self.props["Discovering"])
        self._tick = GLib.timeout_add(300, tick)

    @dbus.service.method(ADAPTER)
    def StopDiscovery(self):
        self.set("Discovering", dbus.Boolean(False))
        self.world.log("StopDiscovery")


class Device(Obj):
    def __init__(self, world, path, props, advertising=True, on_connect=None):
        super().__init__(world, path, DEVICE, props)
        self.advertising = advertising
        self.on_connect = on_connect
        self.hidden = not advertising and not props.get("Paired")

    @dbus.service.method(DEVICE)
    def Connect(self):
        self.world.log("Connect", self.path)
        if self.on_connect:
            self.on_connect(self)
        else:
            self.set("Connected", dbus.Boolean(True))

    @dbus.service.method(DEVICE)
    def Disconnect(self):
        self.world.log("Disconnect", self.path)
        self.set("Connected", dbus.Boolean(False))
        if "ServicesResolved" in self.props:
            self.set("ServicesResolved", dbus.Boolean(False))


class Characteristic(Obj):
    def __init__(self, world, path, service_path, uuid, flags, value=b""):
        super().__init__(world, path, CHAR, {
            "UUID": uuid, "Service": dbus.ObjectPath(service_path),
            "Flags": dbus.Array(flags, signature="s"), "Value": ay(value),
            "Notifying": dbus.Boolean(False)})
        self.uuid = uuid
        self.hidden = True  # appears once services resolve

    @dbus.service.method(CHAR, in_signature="aya{sv}")
    def WriteValue(self, value, options):
        self.world.speaker.on_write(self.uuid, bytes(value), str(options.get("type", "")))

    @dbus.service.method(CHAR, in_signature="a{sv}", out_signature="ay")
    def ReadValue(self, options):
        return ay(self.world.speaker.on_read(self.uuid))

    @dbus.service.method(CHAR)
    def StartNotify(self):
        self.world.log("StartNotify", self.uuid)
        self.set("Notifying", dbus.Boolean(True))

    @dbus.service.method(CHAR)
    def StopNotify(self):
        self.set("Notifying", dbus.Boolean(False))


class FakeM7:
    """Provisioning-service behaviour of the speaker."""

    def __init__(self, world, sc):
        self.world, self.sc = world, sc
        self.buffers: dict[str, list] = {}
        self.got: dict[str, bytes] = {}
        self.hello = False
        self.steps: list[str] = []

    def violation(self, msg):
        self.world.report["violations"].append(msg)
        self.world.log("VIOLATION", msg)
        self.notify(b"7")

    def notify(self, data: bytes, delay_ms: int = 0):
        def emit():
            ch = self.world.chars[NOTIFY]
            if ch.props["Notifying"]:
                ch.set("Value", ay(data))
                self.world.report["notified"].append(data.decode("latin-1"))
            else:
                self.world.report["violations"].append(f"notification {data!r} sent before StartNotify")
            return False
        GLib.timeout_add(max(1, delay_ms), emit)

    def on_read(self, uuid):
        self.world.log("Read", uuid)
        if uuid == WIFI_MAC:
            # Before HELLO the M7 returned 00 00; after, the XOR'd MAC.
            return unxor(bytes.fromhex(self.sc["wifi_mac"])) if self.hello else b"\x00\x00"
        if uuid == SSID:
            return b"ssid"
        return b"\x00\x00"

    def on_write(self, uuid, pkt, wtype):
        name = {SSID: "SSID", PASSWD: "PASSWD", COMMAND: "COMMAND", LG_APP: "LG_APP",
                SECURITY: "SECURITY"}.get(uuid, uuid)
        if wtype != "request":
            self.violation(f"{name}: write without response (type={wtype!r}); the app uses WRITE_TYPE_DEFAULT")
        if len(pkt) > 20:
            self.violation(f"{name}: {len(pkt)}-byte write exceeds the 20-byte default ATT payload")
        plain = unxor(pkt)
        total, idx = plain[0] >> 4, plain[0] & 0xF
        buf = self.buffers.setdefault(uuid, [])
        if idx != len(buf):
            self.violation(f"{name}: chunk index {idx}, expected {len(buf)}")
            self.buffers[uuid] = []
            return
        buf.append((total, plain[1:]))
        if any(t != total for t, _ in buf):
            self.violation(f"{name}: inconsistent chunk totals")
        if len(buf) < total:
            return
        value = b"".join(p for _, p in buf)
        self.buffers[uuid] = []
        self.world.report["writes"].append({"char": name, "chunks": total, "value_hex": value.hex()})
        self.on_value(uuid, name, value)

    def on_value(self, uuid, name, value):
        if uuid != LG_APP and not self.hello:
            self.violation(f"{name} written before HELLO")
        if uuid == LG_APP:
            if value != b"C400":
                self.violation(f"bad HELLO {value!r}")
            self.hello = True
            self.notify(b"E\x02\x01\x00", 50)  # feature list (content unknown on the real unit)
            return
        if uuid == COMMAND and value == b"9":
            ssid = self.sc["saved_ssid"].encode()
            pieces = [ssid[i:i + 16] for i in range(0, len(ssid), 16)] or [b""]
            for i, p in enumerate(pieces):
                hdr = (len(pieces) << 4) | i
                self.notify(bytes([ord("F"), len(p) + 1, hdr]) + p, 60 + 20 * i)
            return
        if uuid in (SSID, PASSWD, SECURITY):
            self.got[name] = value
            self.steps.append(name)
            self.world.report["received"][name] = value.decode("utf-8", "replace") if name != "SECURITY" \
                else ":".join(f"{b:02X}" for b in value[1:]) if len(value) == 7 and value[0] == 0 else value.hex()
            if name == "SECURITY" and (len(value) != 7 or value[0] != 0):
                self.violation(f"SECURITY payload must be 0x00 + 6 MAC bytes, got {value.hex()}")
            return
        if uuid == COMMAND and value in (b"0", b"4"):
            self.steps.append(f"COMMAND {value.decode()}")
            self.world.report["steps"] = self.steps
            expected = ["SSID", "PASSWD", "SECURITY", "COMMAND 0"] if value == b"0" \
                else ["SSID", "SECURITY", "COMMAND 4"]
            if self.steps != expected:
                self.violation(f"step order {self.steps}, expected {expected}")
                return
            self.connect_to_ap(value == b"0")
            return
        self.violation(f"unexpected {name} value {value!r}")

    def connect_to_ap(self, secured):
        ssid = self.got.get("SSID", b"").decode("utf-8", "replace")
        pw = self.got.get("PASSWD", b"").decode("utf-8", "replace") if secured else ""
        t = 100
        for code in "451":
            self.notify(code.encode(), t)
            t += 150
        if ssid != self.sc["network_ssid"]:
            self.notify(b"6", t)
        elif self.sc["network_password"] != pw:
            self.notify(b"3", t)
        elif self.sc.get("no_internet"):
            self.notify(b"A", t)
        else:
            self.notify(b"A", t)
            self.notify(b"B", t + 200)


class World:
    def __init__(self, sc, report_path):
        self.sc, self.report_path = sc, report_path
        self.bus = dbus.SessionBus()
        self.name = dbus.service.BusName("org.bluez", self.bus)
        self.objects: dict[str, Obj] = {}
        self.chars: dict[str, Characteristic] = {}
        self.report = {"log": [], "violations": [], "writes": [], "received": {}, "notified": [],
                       "audio_reconnects": 0, "connect_calls": 0}
        self.root = Root(self)
        self.adapter = Adapter(self)
        self.speaker = FakeM7(self, sc)

        # Paired, connected Bluetooth-audio identity (normal-mode LE beacon too).
        self.audio = Device(self, AUDIO_PATH, {
            "Address": "8C:2A:C1:0E:9F:35", "AddressType": "public", "Name": "Sound Suite1",
            "Alias": "Sound Suite1", "Paired": dbus.Boolean(True), "Trusted": dbus.Boolean(True),
            "Connected": dbus.Boolean(sc.get("audio_connected", True)),
            "UUIDs": dbus.Array([A2DP_SINK, FC79], signature="s"),
            "ManufacturerData": dbus.Dictionary({dbus.UInt16(0xC4): ay(bytes.fromhex("00000198002600"))},
                                                signature="qv"),
            "RSSI": dbus.Int16(-60)}, advertising=True, on_connect=self.audio_connect)

        # Setup-mode beacon with a random address and the long manufacturer payload.
        if sc.get("setup_mode", True):
            self.beacon = Device(self, BEACON_PATH, {
                "Address": "66:67:27:A7:BC:E1", "AddressType": "random", "Name": "Sound Suite1",
                "Alias": "Sound Suite1", "Paired": dbus.Boolean(False), "Connected": dbus.Boolean(False),
                "ServicesResolved": dbus.Boolean(False),
                "UUIDs": dbus.Array([FC79], signature="s"),
                "ManufacturerData": dbus.Dictionary(
                    {dbus.UInt16(0xC4): ay(bytes.fromhex("c498029f358e2ac10e9f340000"))}, signature="qv"),
                "RSSI": dbus.Int16(-62)}, advertising=True, on_connect=self.beacon_connect)
            svc_path = BEACON_PATH + "/service0028"
            svc = Obj(self, svc_path, SERVICE, {"UUID": FC79, "Primary": dbus.Boolean(True),
                                                "Device": dbus.ObjectPath(BEACON_PATH)})
            svc.hidden = True
            layout = [(SSID, ["read", "write"]), (PASSWD, ["write"]), (COMMAND, ["write"]),
                      (NOTIFY, ["notify"]), (LG_APP, ["write"]), (SECURITY, ["write"]),
                      (WIFI_MAC, ["read"])] + [(u, ["read"]) for u in EXTRA]
            for i, (uuid, flags) in enumerate(layout):
                ch = Characteristic(self, f"{svc_path}/char{0x29 + 2 * i:04x}", svc_path, uuid, flags)
                self.chars[uuid] = ch
            self.service = svc
        self.save()

    def log(self, *a):
        self.report["log"].append(" ".join(str(x) for x in a))
        self.save()

    def save(self):
        tmp = self.report_path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self.report, f, indent=1)
        os.replace(tmp, self.report_path)

    def audio_connect(self, dev):
        self.report["audio_reconnects"] += 1
        dev.set("Connected", dbus.Boolean(True))
        self.log("A2DP reconnected")

    def beacon_connect(self, dev):
        self.report["connect_calls"] += 1
        fails = self.sc.get("fail_connects", 0)
        if self.report["connect_calls"] <= fails:
            self.save()
            if self.sc.get("fail_kind") == "inprogress":
                # BlueZ is still finishing an earlier attempt, which then succeeds.
                GLib.timeout_add(500, lambda: (self._finish_connect(dev), False)[1])
                raise InProgress("simulated: earlier connect still in progress")
            raise Failed("simulated connect failure")
        self._finish_connect(dev)

    def _finish_connect(self, dev):
        if dev.props["Connected"]:
            return
        dev.set("Connected", dbus.Boolean(True))
        # Like the real M7: the setup connection knocks the A2DP link off.
        if self.audio.props["Connected"]:
            self.audio.set("Connected", dbus.Boolean(False))
            self.log("A2DP dropped (simulated M7 behaviour)")

        def resolve():
            self.service.hidden = False
            for ch in self.chars.values():
                ch.hidden = False
            dev.set("ServicesResolved", dbus.Boolean(True))
            return False
        GLib.timeout_add(200, resolve)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--report", required=True)
    p.add_argument("--scenario", default="{}")
    a = p.parse_args()
    sc = {"wifi_mac": "8c2ac10e9f34", "saved_ssid": "STARLINK", "network_ssid": "STARLINK",
          "network_password": "correct horse battery", **json.loads(a.scenario)}
    DBusGMainLoop(set_as_default=True)
    World(sc, a.report)
    print("READY", flush=True)
    GLib.MainLoop().run()


if __name__ == "__main__":
    sys.exit(main())
