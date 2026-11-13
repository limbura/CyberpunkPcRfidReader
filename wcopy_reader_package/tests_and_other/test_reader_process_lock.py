"""Cross-process reader lock regression tests; real Windows locks, no USB hardware."""
import os
from pathlib import Path
import subprocess
import sys
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import wcopy_reader as r


@unittest.skipUnless(os.name == "nt", "msvcrt file locks are Windows-only")
class WindowsReaderLockTests(unittest.TestCase):
    def setUp(self):
        self.device_path = ("fake-hid-" + uuid.uuid4().hex).encode("ascii")

    def tearDown(self):
        r.close_readers(path=self.device_path)

    def probe_in_another_process(self, device_path):
        # A separate Python process must see the actual OS byte-range lock.
        script = (
            "import sys, wcopy_reader as r\n"
            "try:\n"
            "    r._claim_reader_lock(bytes.fromhex(sys.argv[1]))\n"
            "except r.ReaderBusyError as exc:\n"
            "    print(exc)\n"
            "    sys.exit(13)\n"
            "sys.exit(0)\n"
        )
        env = dict(os.environ)
        env["PYTHONPATH"] = str(Path(r.__file__).resolve().parent) + os.pathsep + env.get("PYTHONPATH", "")
        return subprocess.run(
            [sys.executable, "-c", script, device_path.hex()],
            env=env, capture_output=True, text=True, timeout=15)

    def test_second_process_is_rejected_and_release_allows_retry(self):
        self.assertTrue(r._claim_reader_lock(self.device_path))
        self.assertFalse(r._claim_reader_lock(self.device_path))
        duplicate = self.probe_in_another_process(self.device_path)
        self.assertEqual(duplicate.returncode, 13, duplicate.stderr)
        self.assertIn("используется", duplicate.stdout)
        self.assertTrue(r.close_readers(path=self.device_path))
        accepted = self.probe_in_another_process(self.device_path)
        self.assertEqual(accepted.returncode, 0, accepted.stderr)

    def test_different_devices_do_not_interfere(self):
        self.assertTrue(r._claim_reader_lock(self.device_path))
        other_path = b"other-" + self.device_path
        self.assertEqual(self.probe_in_another_process(other_path).returncode, 0)

    def test_busy_reader_never_opens_hid_or_sends_commands(self):
        device = SimpleNamespace(open_path=lambda path: self.fail("USB must not be opened"))
        hid = SimpleNamespace(
            device=lambda: device,
            enumerate=lambda vid, pid: ([dict(path=self.device_path,
                vendor_id=vid, product_id=pid, interface_number=0)]
                if (vid, pid) == (r.VID, r.PID) else []))
        with patch.object(r, "_get_hid", return_value=hid), patch.object(
                r, "_claim_reader_lock",
                side_effect=r.ReaderBusyError("Занято другим процессом", stage="lock")):
            with self.assertRaises(r.ReaderBusyError) as exc:
                r.read_card(auto_feedback=False)
        self.assertEqual(exc.exception.code, "READER_BUSY")

    def test_failed_usb_open_releases_new_lock(self):
        device = SimpleNamespace(
            open_path=lambda path: (_ for _ in ()).throw(OSError("unplugged")),
            close=lambda: None)
        hid = SimpleNamespace(
            device=lambda: device,
            enumerate=lambda vid, pid: ([dict(path=self.device_path,
                vendor_id=vid, product_id=pid, interface_number=0)]
                if (vid, pid) == (r.VID, r.PID) else []))
        with patch.object(r, "_get_hid", return_value=hid):
            with self.assertRaises(r.ReaderOpenError):
                r.read_card(auto_feedback=False)
        self.assertNotIn(self.device_path, r._READER_LOCKS)
        self.assertEqual(self.probe_in_another_process(self.device_path).returncode, 0)


if __name__ == "__main__":
    unittest.main()
