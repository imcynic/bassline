"""Small BlueZ (D-Bus) client: just enough GATT to talk to a Sound Suite speaker.

Uses dbus-python + PyGObject (both ship with most desktop distros). All calls run on
the main thread; GLib's main context is pumped manually while waiting, so signals
(notifications, new devices) are delivered without threads.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import dbus
import dbus.bus
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib

from . import codec

BLUEZ = "org.bluez"
OM_IFACE = "org.freedesktop.DBus.ObjectManager"
PROPS_IFACE = "org.freedesktop.DBus.Properties"
ADAPTER_IFACE = "org.bluez.Adapter1"
DEVICE_IFACE = "org.bluez.Device1"
SERVICE_IFACE = "org.bluez.GattService1"
CHAR_IFACE = "org.bluez.GattCharacteristic1"


class BleError(RuntimeError):
    pass


def _short_dbus_error(e: dbus.DBusException) -> str:
    name = e.get_dbus_name() or "DBusException"
    msg = e.get_dbus_message() or ""
    return f"{name.rsplit('.', 1)[-1]}: {msg}".strip(": ")


@dataclass
class Speaker:
    path: str
    address: str
    name: str
    rssi: int | None
    address_type: str | None
    uuids: list[str] = field(default_factory=list)
    beacon: dict = field(default_factory=dict)

    @property
    def mode(self) -> str:
        return self.beacon.get("mode", "unknown")

    @property
    def label(self) -> str:
        wd = self.beacon.get("wifi_direct_mac")
        return f"{self.name} ({self.address}{', id ' + wd if wd else ''})"


class BlueZ:
    def __init__(self, adapter: str | None = None):
        DBusGMainLoop(set_as_default=True)
        # LGSUITE_DBUS_ADDRESS points the tool at a fake BlueZ (tests/fake_bluez.py) instead
        # of the real system bus, so the whole flow can be tested without touching hardware.
        test_bus = os.environ.get("LGSUITE_DBUS_ADDRESS")
        self.bus = dbus.bus.BusConnection(test_bus) if test_bus else dbus.SystemBus()
        self.ctx = GLib.MainContext.default()
        self.om = dbus.Interface(self.bus.get_object(BLUEZ, "/"), OM_IFACE)
        self.adapter_path = self._find_adapter(adapter)
        obj = self.bus.get_object(BLUEZ, self.adapter_path)
        self.adapter = dbus.Interface(obj, ADAPTER_IFACE)
        self.adapter_props = dbus.Interface(obj, PROPS_IFACE)

    # -- plumbing -----------------------------------------------------------
    def pump(self, seconds: float, until=None) -> bool:
        """Run the GLib loop for up to `seconds`; stop early when until() is truthy."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            while self.ctx.pending():
                self.ctx.iteration(False)
            if until is not None and until():
                return True
            time.sleep(0.02)
        return bool(until and until())

    def objects(self) -> dict:
        return self.om.GetManagedObjects()

    def _find_adapter(self, name: str | None) -> str:
        for path, ifaces in self.objects().items():
            if ADAPTER_IFACE in ifaces and (name is None or str(path).endswith("/" + name)):
                return str(path)
        raise BleError("No Bluetooth adapter found (is bluetoothd running and the adapter powered?)")

    def ensure_powered(self) -> None:
        if not bool(self.adapter_props.Get(ADAPTER_IFACE, "Powered")):
            self.adapter_props.Set(ADAPTER_IFACE, "Powered", dbus.Boolean(True))
            self.pump(1.0)

    # -- Bluetooth audio safety ---------------------------------------------------
    A2DP_SINK = "0000110b-0000-1000-8000-00805f9b34fb"

    def connected_audio_devices(self) -> list[str]:
        """Paths of paired devices currently connected as Bluetooth speakers (A2DP sink)."""
        out = []
        for path, ifaces in self.objects().items():
            dev = ifaces.get(DEVICE_IFACE)
            if dev and bool(dev.get("Connected")) and bool(dev.get("Paired")) \
                    and self.A2DP_SINK in [str(u).lower() for u in dev.get("UUIDs", [])]:
                out.append(str(path))
        return out

    def reconnect(self, paths: list[str], log=print) -> None:
        """Reconnect audio devices that dropped while we were busy (the M7 drops A2DP during setup)."""
        for path in paths:
            obj = self.bus.get_object(BLUEZ, path)
            props = dbus.Interface(obj, PROPS_IFACE)
            try:
                if bool(props.Get(DEVICE_IFACE, "Connected")):
                    continue
                name = str(props.Get(DEVICE_IFACE, "Alias"))
                log(f"Reconnecting Bluetooth audio to {name}…")
                dbus.Interface(obj, DEVICE_IFACE).Connect(timeout=30)
            except dbus.DBusException as e:
                log(f"  could not reconnect {path.rsplit('/', 1)[-1]}: {_short_dbus_error(e)} "
                    f"(run: bluetoothctl connect <address>)")

    # -- discovery ------------------------------------------------------------
    def scan(self, seconds: float = 8.0, stop_on_first: bool = False) -> list[Speaker]:
        """Find Sound Suite setup beacons over BLE."""
        self.ensure_powered()
        seen: set[str] = set()

        def on_added(path, ifaces):
            if DEVICE_IFACE in ifaces:
                seen.add(str(path))

        def on_props(iface, changed, invalidated, path=None):
            if iface == DEVICE_IFACE and ("RSSI" in changed or "ManufacturerData" in changed):
                seen.add(str(path))

        sig1 = self.bus.add_signal_receiver(on_added, "InterfacesAdded", OM_IFACE, BLUEZ)
        sig2 = self.bus.add_signal_receiver(on_props, "PropertiesChanged", PROPS_IFACE, BLUEZ,
                                            path_keyword="path")
        try:
            try:
                self.adapter.SetDiscoveryFilter(dbus.Dictionary({
                    "Transport": dbus.String("le"),
                    "DuplicateData": dbus.Boolean(True),
                }, signature="sv"))
            except dbus.DBusException:
                pass  # older BlueZ: scan unfiltered
            try:
                self.adapter.StartDiscovery()
            except dbus.DBusException as e:
                if "InProgress" not in (e.get_dbus_name() or ""):
                    raise BleError(f"Could not start scanning: {_short_dbus_error(e)}") from e
            if stop_on_first == "setup":
                until = lambda: any(s.mode == "setup" for s in self._speakers(seen))  # noqa: E731
            elif stop_on_first:
                until = lambda: bool(self._speakers(seen))  # noqa: E731
            else:
                until = None
            self.pump(seconds, until=until)
        finally:
            try:
                self.adapter.StopDiscovery()
            except dbus.DBusException:
                pass
            sig1.remove()
            sig2.remove()
        found = self._speakers(seen)
        found.sort(key=lambda s: -(s.rssi if s.rssi is not None else -999))
        return found

    def _speakers(self, seen: set[str]) -> list[Speaker]:
        result = []
        for path, ifaces in self.objects().items():
            path = str(path)
            dev = ifaces.get(DEVICE_IFACE)
            if not dev or not path.startswith(self.adapter_path + "/"):
                continue
            uuids = [str(u).lower() for u in dev.get("UUIDs", [])]
            mfr = {int(k): bytes(v) for k, v in dev.get("ManufacturerData", {}).items()}
            name = str(dev.get("Name", dev.get("Alias", "")))
            # The setup beacon advertises service 0xFC79. The speaker's paired classic-BT
            # identity also lists 0xFC79 in its cached UUIDs, so additionally require that
            # the device was actually heard advertising during this scan.
            if not any(u in codec.SERVICE_UUIDS for u in uuids):
                continue
            if path not in seen and "RSSI" not in dev:
                continue
            if str(dev.get("AddressType", "")) == "public" and bool(dev.get("Paired", False)) \
                    and "RSSI" not in dev:
                continue
            beacon = codec.parse_manufacturer_data(mfr[codec.LG_MANUFACTURER_ID]) \
                if codec.LG_MANUFACTURER_ID in mfr else {}
            result.append(Speaker(
                path=path, address=str(dev.get("Address", "?")), name=name or "?",
                rssi=int(dev["RSSI"]) if "RSSI" in dev else None,
                address_type=str(dev.get("AddressType", "")) or None,
                uuids=uuids, beacon=beacon,
            ))
        return result


class GattSession:
    """Connected GATT session to one speaker's provisioning service."""

    def __init__(self, bz: BlueZ, speaker: Speaker, log=print, verbose: bool = False):
        self.bz = bz
        self.speaker = speaker
        self.log = log
        self.verbose = verbose
        obj = bz.bus.get_object(BLUEZ, speaker.path)
        self.dev = dbus.Interface(obj, DEVICE_IFACE)
        self.dev_props = dbus.Interface(obj, PROPS_IFACE)
        self.chars: dict[str, str] = {}
        self.notifications: list[bytes] = []
        self._sig = None
        self._notifying: str | None = None

    # -- connection -------------------------------------------------------------
    def connect(self, attempts: int = 3, timeout: float = 25.0) -> None:
        last = None
        connected = False
        for attempt in range(1, attempts + 1):
            try:
                self.dev.Connect(timeout=timeout)
                connected = True
                break
            except dbus.DBusException as e:
                last = e
                name = e.get_dbus_name() or ""
                self.log(f"  connect attempt {attempt} failed: {_short_dbus_error(e)}")
                if "InProgress" in name:
                    # BlueZ is still working on an earlier attempt; wait for it instead of piling on.
                    if self.bz.pump(15.0, until=lambda: bool(self._prop("Connected"))):
                        connected = True
                        break
                # Cancel whatever BlueZ is still trying before the next attempt.
                try:
                    self.dev.Disconnect(timeout=5)
                except dbus.DBusException:
                    pass
                self.bz.pump(1.0 * attempt)
        if not connected:
            raise BleError(f"Could not connect to {self.speaker.label}: {_short_dbus_error(last)}. "
                           "Its BLE address rotates every few minutes; run the command again.")
        if not self.bz.pump(20.0, until=lambda: bool(self._prop("ServicesResolved"))):
            raise BleError("Connected, but the speaker's services never resolved")
        self._map_characteristics()

    def _prop(self, name: str):
        try:
            return self.dev_props.Get(DEVICE_IFACE, name)
        except dbus.DBusException:
            return None

    def _map_characteristics(self) -> None:
        objs = self.bz.objects()
        service_path = None
        for path, ifaces in objs.items():
            svc = ifaces.get(SERVICE_IFACE)
            if svc and str(path).startswith(self.speaker.path + "/") \
                    and str(svc.get("UUID", "")).lower() in codec.SERVICE_UUIDS:
                service_path = str(path)
                break
        if not service_path:
            raise BleError("Speaker does not expose the LG Wi-Fi setup service (0xFC79). "
                           "Is it in setup/pairing mode?")
        for path, ifaces in objs.items():
            ch = ifaces.get(CHAR_IFACE)
            if ch and str(ch.get("Service", "")) == service_path:
                self.chars[str(ch["UUID"]).lower()] = str(path)
        needed = [codec.CHAR_SSID, codec.CHAR_PASSWD, codec.CHAR_COMMAND, codec.CHAR_NOTIFY,
                  codec.CHAR_LG_APP, codec.CHAR_SECURITY]
        missing = [codec.CHAR_NAMES[u] for u in needed if u not in self.chars]
        if missing:
            raise BleError(f"Setup service is missing characteristics: {', '.join(missing)}")

    def _char(self, uuid: str):
        return dbus.Interface(self.bz.bus.get_object(BLUEZ, self.chars[uuid]), CHAR_IFACE)

    # -- GATT operations ----------------------------------------------------------
    def start_notify(self, uuid: str = codec.CHAR_NOTIFY) -> None:
        path = self.chars[uuid]

        def on_props(iface, changed, invalidated):
            if iface == CHAR_IFACE and "Value" in changed:
                data = bytes(changed["Value"])
                self.notifications.append(data)
                if self.verbose:
                    self.log(f"  <- NOTIFY {data.hex(' ')}")

        self._sig = self.bz.bus.add_signal_receiver(on_props, "PropertiesChanged", PROPS_IFACE,
                                                    BLUEZ, path=path)
        self._char(uuid).StartNotify()
        self._notifying = uuid
        self.bz.pump(0.3)

    def write(self, uuid: str, packets: list[bytes], redact: bool = False) -> None:
        ch = self._char(uuid)
        name = codec.CHAR_NAMES.get(uuid, uuid)
        for i, pkt in enumerate(packets):
            if self.verbose:
                shown = f"<{len(pkt)} bytes hidden>" if redact else pkt.hex(" ")
                self.log(f"  -> {name} [{i + 1}/{len(packets)}] {shown}")
            try:
                ch.WriteValue(dbus.Array([dbus.Byte(b) for b in pkt], signature="y"),
                              dbus.Dictionary({"type": dbus.String("request")}, signature="sv"),
                              timeout=10)
            except dbus.DBusException as e:
                raise BleError(f"Write to {name} failed: {_short_dbus_error(e)}") from e
            self.bz.pump(0.05)  # deliver any notifications between writes

    def read(self, uuid: str) -> bytes:
        try:
            value = bytes(self._char(uuid).ReadValue(dbus.Dictionary({}, signature="sv"), timeout=10))
        except dbus.DBusException as e:
            raise BleError(f"Read of {codec.CHAR_NAMES.get(uuid, uuid)} failed: {_short_dbus_error(e)}") from e
        if self.verbose:
            self.log(f"  <- {codec.CHAR_NAMES.get(uuid, uuid)} {value.hex(' ')}")
        return value

    def take_notifications(self) -> list[bytes]:
        out, self.notifications = self.notifications, []
        return out

    def close(self) -> None:
        if self._notifying:
            try:
                self._char(self._notifying).StopNotify()
            except dbus.DBusException:
                pass
            self._notifying = None
        if self._sig is not None:
            self._sig.remove()
            self._sig = None
        try:
            self.dev.Disconnect(timeout=10)
        except dbus.DBusException:
            pass
