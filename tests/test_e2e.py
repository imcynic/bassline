"""End-to-end tests: the real lg-setup CLI against a fake BlueZ + fake M7 on a private D-Bus.

Nothing here touches real Bluetooth: every test starts its own throwaway dbus-daemon and
points lg-setup at it with LGSUITE_DBUS_ADDRESS.
Run:  python3 -m unittest discover -s tests -v
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI = os.path.join(ROOT, "lg-setup")
FAKE = os.path.join(ROOT, "tests", "fake_bluez.py")
PW = "correct horse battery"


@unittest.skipUnless(shutil.which("dbus-daemon"), "dbus-daemon not installed")
class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="lgsuite-e2e-")
        self.daemon = subprocess.Popen(
            ["dbus-daemon", "--session", "--nofork", "--print-address=1"],
            stdout=subprocess.PIPE, text=True)
        self.address = self.daemon.stdout.readline().strip()
        self.assertTrue(self.address, "dbus-daemon gave no address")
        self.fake = None

    def tearDown(self):
        for proc in (self.fake, self.daemon):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(5)
                except subprocess.TimeoutExpired:
                    proc.kill()
        if self.daemon.stdout:
            self.daemon.stdout.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def start_fake(self, **scenario):
        self.report_path = os.path.join(self.tmp, "report.json")
        env = {**os.environ, "DBUS_SESSION_BUS_ADDRESS": self.address}
        self.fake = subprocess.Popen([sys.executable, FAKE, "--report", self.report_path,
                                      "--scenario", json.dumps(scenario)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        line = self.fake.stdout.readline().strip()
        if line != "READY":
            self.fail(f"fake BlueZ failed to start: {line} {self.fake.stderr.read()}")

    def run_cli(self, *args, stdin="", timeout=90):
        env = {**os.environ, "LGSUITE_DBUS_ADDRESS": self.address, "NO_COLOR": "1"}
        t0 = time.monotonic()
        r = subprocess.run([sys.executable, CLI, *args], input=stdin, capture_output=True,
                           text=True, env=env, timeout=timeout)
        r.elapsed = time.monotonic() - t0
        r.all = r.stdout + r.stderr
        return r

    def report(self):
        time.sleep(0.3)  # let the fake flush its last events
        with open(self.report_path) as f:
            return json.load(f)

    def wifi(self, *extra, password=PW, ssid="STARLINK"):
        args = ["wifi", "--ssid", ssid, "--bssid", "42:7B:8F:3E:04:76", "--no-lan-check",
                "--scan-time", "4", "--timeout", "20", *extra]
        if password is None:
            args.append("--open")
            stdin = ""
        else:
            args.append("--password-stdin")
            stdin = password + "\n"
        return self.run_cli(*args, stdin=stdin)

    def assert_clean(self, rep, r):
        self.assertEqual(rep["violations"], [], f"protocol violations; CLI output:\n{r.all}")

    # -- scenarios ------------------------------------------------------------------
    def test_scan_shows_both_identities(self):
        self.start_fake()
        r = self.run_cli("scan", "--scan-time", "2")
        self.assertEqual(r.returncode, 0, r.all)
        self.assertIn("66:67:27:A7:BC:E1", r.stdout)
        self.assertIn("setup mode", r.stdout)
        self.assertIn("8E:2A:C1:0E:9F:34", r.stdout)
        self.assertIn("normal mode", r.stdout)

    def test_info(self):
        self.start_fake(saved_ssid="My Home Wi-Fi")
        r = self.run_cli("info", "--scan-time", "4")
        self.assertEqual(r.returncode, 0, r.all)
        self.assertIn("Wi-Fi MAC        8C:2A:C1:0E:9F:34", r.stdout)
        self.assertIn("Current network  My Home Wi-Fi", r.stdout)
        rep = self.report()
        self.assert_clean(rep, r)
        self.assertEqual([w["char"] for w in rep["writes"]], ["LG_APP", "COMMAND"])

    def test_wifi_success_and_audio_restored(self):
        self.start_fake()
        r = self.wifi()
        self.assertEqual(r.returncode, 0, r.all)
        self.assertIn("Joined Wi-Fi with internet access", r.stdout)
        self.assertIn("Done: the speaker is on 'STARLINK'", r.stdout)
        self.assertNotIn(PW, r.all, "password leaked into output")
        rep = self.report()
        self.assert_clean(rep, r)
        self.assertEqual(rep["received"], {"SSID": "STARLINK", "PASSWD": PW, "SECURITY": "42:7B:8F:3E:04:76"})
        self.assertEqual(rep["steps"], ["SSID", "PASSWD", "SECURITY", "COMMAND 0"])
        # The fake dropped A2DP on connect, like the real M7; lg-setup must put it back.
        self.assertIn("A2DP dropped (simulated M7 behaviour)", rep["log"])
        self.assertEqual(rep["audio_reconnects"], 1, r.all)
        self.assertIn("Reconnecting Bluetooth audio", r.stdout)

    def test_wrong_password(self):
        self.start_fake()
        r = self.wifi(password="wrong password!")
        self.assertEqual(r.returncode, 1, r.all)
        self.assertIn("Wrong Wi-Fi password", r.stdout)
        self.assertIn("Check the password", r.stdout)
        rep = self.report()
        self.assert_clean(rep, r)
        self.assertEqual(rep["audio_reconnects"], 1, "audio must be restored on failure too")

    def test_network_not_found(self):
        self.start_fake()
        r = self.wifi(ssid="NoSuchNetwork")
        self.assertEqual(r.returncode, 1, r.all)
        self.assertIn("Network not found", r.stdout)

    def test_long_utf8_ssid_and_63_char_password_multichunk(self):
        ssid = "Café ☕ WiFi 2.4G — Upstairs"           # 32 bytes in UTF-8
        pw = "p" * 30 + "ä" + "q" * 32                 # 63 chars, 64 bytes
        self.assertEqual(len(ssid.encode()), 32)
        self.start_fake(network_ssid=ssid, network_password=pw)
        r = self.wifi(ssid=ssid, password=pw)
        self.assertEqual(r.returncode, 0, r.all)
        rep = self.report()
        self.assert_clean(rep, r)
        chunks = {w["char"]: w["chunks"] for w in rep["writes"]}
        self.assertEqual(chunks["SSID"], 2)
        self.assertEqual(chunks["PASSWD"], 4)
        self.assertEqual(rep["received"]["SSID"], ssid)
        self.assertEqual(rep["received"]["PASSWD"], pw)

    def test_open_network(self):
        self.start_fake(network_ssid="Guest", network_password="")
        r = self.wifi(ssid="Guest", password=None)
        self.assertEqual(r.returncode, 0, r.all)
        rep = self.report()
        self.assert_clean(rep, r)
        self.assertEqual(rep["steps"], ["SSID", "SECURITY", "COMMAND 4"])
        self.assertNotIn("PASSWD", [w["char"] for w in rep["writes"]])

    def test_joined_without_internet(self):
        self.start_fake(no_internet=True)
        r = self.wifi()
        self.assertEqual(r.returncode, 3, r.all)
        self.assertIn("no internet access", r.stdout)

    def test_not_in_setup_mode_never_connects(self):
        self.start_fake(setup_mode=False)
        r = self.wifi()
        self.assertEqual(r.returncode, 2, r.all)
        self.assertIn("not in setup mode", r.all)
        rep = self.report()
        self.assertEqual(rep["audio_reconnects"], 0)
        self.assertFalse(any(l.startswith("Connect") for l in rep["log"]), rep["log"])

    def test_connect_retry_after_failure(self):
        self.start_fake(fail_connects=1, fail_kind="failed")
        r = self.wifi()
        self.assertEqual(r.returncode, 0, r.all)
        self.assertIn("connect attempt 1 failed", r.stdout)
        self.assertEqual(self.report()["connect_calls"], 2)

    def test_connect_in_progress_waits_instead_of_piling_on(self):
        self.start_fake(fail_connects=1, fail_kind="inprogress")
        r = self.wifi()
        self.assertEqual(r.returncode, 0, r.all)
        self.assertEqual(self.report()["connect_calls"], 1, "should wait for the pending connect, not retry")

    def test_verbose_hides_password_packets(self):
        self.start_fake()
        r = self.wifi("-v")
        self.assertEqual(r.returncode, 0, r.all)
        self.assertIn("-> PASSWD [1/2] <", r.stdout)
        self.assertIn("bytes hidden>", r.stdout)
        self.assertIn("-> SSID [1/1] 7d 26 27 28 11 6c 2f 22 24", r.stdout)  # hand-checked vector


if __name__ == "__main__":
    unittest.main()
