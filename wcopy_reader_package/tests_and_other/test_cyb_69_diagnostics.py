"""Command 0x69 benchmark tests: synthetic HID, never a real reader."""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import cyb_69_diagnostics as d
from test_cyb_reader import Device, descriptor, frame

r = d.r


class Command69DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        r._PRESENCE.clear()
        r._OWNED_CYB.clear()
        self.addCleanup(r._OWNED_CYB.clear)

    def test_parse_inputs(self):
        self.assertEqual(d.parse_intervals("0,0.1,0.5"), [0, 0.1, 0.5])
        self.assertEqual(d.parse_modes("once,reassert"), ["once", "reassert"])
        for raw in ("", "-1", "inf", "nan", "abc", "0.1,"):
            with self.subTest(intervals=raw), self.assertRaises(ValueError):
                d.parse_intervals(raw)
        for raw in ("", "bad", "reopen,reopen"):
            with self.subTest(modes=raw), self.assertRaises(ValueError):
                d.parse_modes(raw)

    def run_fake(self, mode, device):
        rows = []
        fake = SimpleNamespace(
            device=lambda: device,
            enumerate=lambda vid, pid: [descriptor()] if (vid, pid) == (0x0483, 0x4300) else [])
        profiler = d.Profiler()
        with patch.object(r, "_get_hid", return_value=fake), \\
             patch.object(r, "_PERSISTENT_HOST_CONTROL", True), \\
             contextlib.redirect_stdout(io.StringIO()), profiler.instrument():
            d.run_series(profiler, b"cyb", mode=mode, condition="held",
                         interval=0, count=3, timeout_ms=5, save=rows.append)
            self.assertTrue(r.close_readers(path=b"cyb"))
        self.assertTrue(device.closed)
        return rows

    def test_modes_send_only_51_and_69_without_block_reads_or_feedback(self):
        for mode, takeover_count in (("reopen", 3), ("reassert", 3), ("once", 1)):
            with self.subTest(mode=mode):
                device = Device()
                rows = self.run_fake(mode, device)
                self.assertEqual([row["status"] for row in rows], ["card"] * 3)
                commands = [int.from_bytes(pkt[2:4], "big") for pkt in device.sent]
                self.assertEqual(commands.count(0x69), 3)
                self.assertEqual(commands.count(0x51), takeover_count + 1)  # cleanup release
                self.assertEqual(set(commands), {0x51, 0x69})
                self.assertEqual(device.reads, 0)
                for row in rows:
                    self.assertEqual(row["uid_length"], 4)
                    self.assertIsNotNone(row["poll_69_ms"])
                    self.assertIsNotNone(row["poll_usb_read_ms"])
                    self.assertNotIn("uid", row)
                    self.assertNotIn("number", row)

    def test_no_card_still_is_read_only(self):
        device = Device(failures={0x69: frame(0x69, bytes(19))})
        rows = self.run_fake("once", device)
        self.assertEqual([row["status"] for row in rows], ["no_card"] * 3)
        self.assertEqual(device.reads, 0)

    def test_timeout_does_not_repeat_the_command(self):
        device = Device(failures={0x69: None})
        rows = self.run_fake("once", device)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "error")
        self.assertEqual(rows[0]["error_stage"], "poll")
        self.assertEqual(sum(pkt[3] == 0x69 for pkt in device.sent), 1)
        self.assertEqual(d.summarize(rows)[0]["errors"], 1)

    def test_poll_breakdown_does_not_double_count_drain_read(self):
        events = [
            dict(name="usb_read", ms=2),
            dict(name="drain", ms=3),
            dict(name="usb_write", ms=1),
            dict(name="usb_read", ms=100),
            dict(name="poll_1", ms=108),
        ]
        parts = d.poll_breakdown(events)
        self.assertEqual(parts["poll_69_ms"], 108)
        self.assertEqual(parts["poll_drain_ms"], 3)
        self.assertEqual(parts["poll_usb_read_ms"], 100)
        self.assertEqual(parts["poll_usb_write_ms"], 1)
        self.assertEqual(parts["poll_other_ms"], 4)


if __name__ == "__main__":
    unittest.main()
