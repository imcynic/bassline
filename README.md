# bassline

Linux tool that puts LG Sound Suite speakers (M5/M7) on Wi-Fi without the LG ThinQ app.

Talks to the speaker's Bluetooth LE setup service directly, using the protocol reverse-engineered
from the ThinQ Android app. After the speaker is on Wi-Fi you can play to it with AirPlay 2 /
Google Cast / Spotify Connect, or plain Bluetooth / USB-C audio.

## Requirements

Linux with BlueZ, Python 3.9+, `dbus-python` and PyGObject (most desktops already have them):

| Distro | Command |
|---|---|
| Arch / CachyOS | `sudo pacman -S --needed bluez python-dbus python-gobject` |
| Debian / Ubuntu | `sudo apt install bluez python3-dbus python3-gi` |
| Fedora | `sudo dnf install bluez python3-dbus python3-gobject` |

## Usage

Put the speaker in **setup/pairing mode** (the mode the ThinQ app looks for), then:

```sh
./lg-setup scan                    # list speakers; shows "setup mode" or "normal mode"
./lg-setup info                    # speaker's Wi-Fi MAC and the network it has saved
./lg-setup wifi --ssid MyNetwork   # send Wi-Fi settings; password is prompted, never echoed
./lg-setup encode --ssid MyNetwork # dry run: show the packets, no Bluetooth used
```

Useful options: `-v` (show every packet; password packets stay hidden), `--device` (pick one of
several speakers), `--bssid none` (let the speaker choose the access point on mesh networks),
`--open` (network without a password), `--password-stdin` (for scripts).

`wifi` prints the speaker's own status as it goes — scanning, found, connecting — and finishes with
success, or the speaker's reason for failing (wrong password, network not found, unsupported router
security…).

**Bluetooth audio:** the M7 drops its Bluetooth-audio connection while a setup session is open.
`lg-setup` notices and reconnects it when it's done.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

* `tests/test_codec.py` — wire-format tests with known answers worked out by hand from the app's code.
* `tests/test_e2e.py` — runs the real CLI against `tests/fake_bluez.py`, a fake BlueZ + fake speaker
  on a private, throwaway D-Bus (no real Bluetooth is touched). It checks write order, chunking,
  password handling, retries, error reporting and that Bluetooth audio gets reconnected.

## Protocol (short version)

BLE GATT service `0xFC79`. Characteristics `B02077Ex-13BE-11E5-BA08-0002A5D5C51B`:
`E1` SSID, `E2` password, `E5` command, `E6` status notifications, `E9` app hello, `EA` router BSSID,
`EC` speaker Wi-Fi MAC.

Values are UTF-8, split into 18-byte chunks, each prefixed with `(total << 4) | index`, and the
chunk XOR'd with the key `"musiC floW"`. Sequence: enable notifications on `E6` → `"C400"` to
`E9` → read `EC` → SSID → password → `0x00`+BSSID → `"0"` (or `"4"` for open networks) to `E5`.
Status codes arrive on `E6` as single ASCII characters (`B` = connected with internet, `3` = wrong
password, …); see `lgsuite/codec.py`.

## Status

`scan`/`info` are verified on a real M7; `wifi` is verified end-to-end against the fake speaker
but not yet on real hardware. Not affiliated with LG.
