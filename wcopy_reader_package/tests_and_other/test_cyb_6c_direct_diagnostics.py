"""Check isolated direct-read experiment using synthetic Cyb HID frames."""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import cyb_6c_direct_diagnostics as d
from test_cyb_reader import Device, descriptor, frame

r = d.r


class Direct6CTests(unittest.TestCase):
    def setUp(self):
        r._PRESENCE.clear()
        r._OWNED_CYB.clear()
        self.addCleanup(r._OWNED_CYB.clear)

    def test_read_response_masks_and_anonymized_card_tags(self):
        secret = bytes(range(32))
        block = bytes(range(16))
        ok = d.decode_read_response(b"\x00\x00\x00\x01" + block, secret)
        self.assertEqual(ok["status"], "read_ok")
        self.assertEqual(ok["response_len"], 20)
        self.assertEqual(ok["block_tag"], d.private_tag(secret, block))
        self.assertEqual(len(ok["block_tag"]), 16)
        self.assertEqual(d.decode_read_response(b"\x00\x00\x00\x00", secret)["status"],
                         "read_failed")
        self.assertEqual(d.decode_read_response(b"\x00\x00\x00\x01", secret)["status"],
                         "invalid_response")
        self.assertEqual(d.decode_read_response(b"\x00", secret)["status"],
                         "invalid_response")

    def test_direct_read_is_sent_before_first_69_and_card_swap_has_no_extra_poll(self):
        device = Device()
        fake = SimpleNamespace(
            device=lambda: device,
            enumerate=lambda v, p: [descriptor()] if (v, p) == (0x0483, 0x4300) else [],
        )
        secret = b"T" * 32
        with (patch.object(r, "_get_hid", return_value=fake),
              patch.object(r, "_PERSISTENT_HOST_CONTROL", True)):
            profiler = d.Profiler()
            with profiler.instrument():
                with r._open_session(b"cyb", 5) as session:
                    session.initialize()
                    with contextlib.redirect_stdout(io.StringIO()):
                        a_pre = d.measure(profiler, lambda: d.direct_read(session, secret),
                                          phase="A_direct_first", sample=1, kind="direct")
                        a_ref = d.measure(profiler, lambda: d.reference_read(session, secret),
                                          phase="A_reference", sample=1, kind="reference")
                        # Simulate removing A and presenting a different card B.
                        device.uid = b"WXYZ"
                        device.block = bytes([77]) * 16
                        b_pre = d.measure(profiler, lambda: d.direct_read(session, secret),
                                          phase="B_direct_before_info", sample=1, kind="direct")
                        b_ref = d.measure(profiler, lambda: d.reference_read(session, secret),
                                          phase="B_reference", sample=1, kind="reference")
                self.assertTrue(r.close_readers(path=b"cyb"))
        cmds = [int.from_bytes(pkt[2:4], "big") for pkt in device.sent]
        self.assertEqual(cmds, [0x51, 0x6C, 0x69, 0x6C, 0x6C, 0x69, 0x6C, 0x51])
        self.assertEqual(a_pre["block_tag"], a_ref["block_tag"])
        self.assertEqual(b_pre["block_tag"], b_ref["block_tag"])
        self.assertNotEqual(a_pre["block_tag"], b_pre["block_tag"])
        self.assertNotIn("uid", a_pre)
        self.assertIsNotNone(a_pre["read_6c_ms"])
        self.assertIsNone(a_pre["poll_69_ms"])
        self.assertIsNotNone(a_ref["poll_69_ms"])
        self.assertTrue(device.closed)

    def test_cache_detection_and_absence_dont_assume_block_failure_is_no_card(self):
        key = b"S" * 32
        a = d.decode_read_response(b"\x00\x00\x00\x01" + bytes([10]) * 16, key)
        b = d.decode_read_response(b"\x00\x00\x00\x01" + bytes([20]) * 16, key)
        rows = [
            dict(phase="A_reference", uid_tag="A", read_6c_ms=20, **a),
            dict(phase="B_direct_before_info", read_6c_ms=20, **a),
            dict(phase="B_reference", uid_tag="B", read_6c_ms=20, **b),
            dict(phase="A_removed", read_6c_ms=20, **a),
        ]
        result = d.analyze(rows)
        self.assertTrue(any("НЕ ТОТ блок" in w for w in result["warnings"]))
        self.assertTrue(any("КРИТИЧНО" in w for w in result["warnings"]))
        self.assertEqual(result["by_phase"]["A_removed"]["ok"], 1)

    def test_only_three_whitelisted_commands_in_all_paths(self):
        # This experiment must never call write_block() or feedback commands.
        source = d.direct_read.__code__.co_names + d.reference_read.__code__.co_names
        self.assertNotIn("write_block", source)
        self.assertNotIn("write_card", source)
        self.assertNotIn("_send_feedback", source)


if __name__ == "__main__":
    unittest.main()
