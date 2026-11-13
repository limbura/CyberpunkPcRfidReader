"""Read-only manufacturer-block UID probe tests, no physical USB required."""
import unittest

import cyb_6c_uid_diagnostics as d


class FakeSession:
    def __init__(self):
        self.calls = []
        self.uid = bytes.fromhex("11223344")
        self.block0 = self.uid + bytes((0x44,)) + bytes(11)
        self.block1 = bytes(range(16))

    def exchange_cyb(self, command, payload, stage):
        self.calls.append((command, payload, stage))
        assert command == 0x6C
        assert stage == "read"
        start, count, mode = payload[:3]
        assert payload[3:] == b"\xff" * 12
        assert mode == 0
        block = {0: self.block0, 1: self.block1}
        return ((1 << count) - 1).to_bytes(4, "big") + b"".join(
            block[start + i] for i in range(count))

    def _poll(self):
        self.calls.append((0x69, b"", "poll"))
        return self.uid, bytes.fromhex("0004"), 8


class UID6CTests(unittest.TestCase):
    def test_permitted_read_parameters_only(self):
        self.assertEqual(d.parameters(0, 1), b"\x00\x01\x00" + b"\xff" * 12)
        self.assertEqual(d.parameters(0, 2), b"\x00\x02\x00" + b"\xff" * 12)
        self.assertEqual(d.parameters(1, 1), b"\x01\x01\x00" + b"\xff" * 12)
        for invalid in ((2, 1), (0, 3), (0, 0), (1, 2), (-1, 1)):
            with self.subTest(params=invalid), self.assertRaises(ValueError):
                d.parameters(*invalid)

    def test_read_block0_before_69_then_combined_blocks(self):
        session = FakeSession()
        key = b"secret"
        first = d.read(session, 0, 1)
        one = d.decode_read(first, 0, 1, key)
        self.assertEqual(one["status"], "read_ok")
        self.assertEqual(one["mask"], 1)
        self.assertIsNotNone(one["block0_tag"])
        self.assertIsNone(one["block1_tag"])
        uid, atqa, sak = session._poll()
        check = d.compare_uid(d.decode_block(first, 0, 1)[0], uid, key)
        self.assertEqual(check["uid_length"], 4)
        self.assertTrue(check["uid_match"])
        self.assertTrue(check["bcc4_ok"])
        paired = d.read(session, 0, 2)
        self.assertEqual(len(paired), 36)
        self.assertEqual(d.decode_read(paired, 0, 2, key)["mask"], 3)
        self.assertEqual(d.decode_block(paired, 0, 2), [session.block0, session.block1])
        second = d.read(session, 1, 1)
        self.assertEqual(d.decode_block(second, 1, 1), [session.block1])
        self.assertEqual(
            [cmd for cmd, _, _ in session.calls],
            [0x6C, 0x69, 0x6C, 0x6C],
        )

    def test_uid_mismatch_and_four_byte_bcc(self):
        block0 = bytes.fromhex("1122334455") + bytes(11)
        mismatch = d.compare_uid(block0, bytes.fromhex("11223345"), b"k")
        self.assertFalse(mismatch["uid_match"])
        self.assertFalse(mismatch["bcc4_ok"])
        match = d.compare_uid(block0, bytes.fromhex("11223344"), b"k")
        self.assertTrue(match["uid_match"])
        self.assertFalse(match["bcc4_ok"])

    def test_seven_byte_uid_comparison_without_assumed_bcc(self):
        uid = bytes.fromhex("01020304050607")
        result = d.compare_uid(uid + bytes(9), uid, b"k")
        self.assertEqual(result["uid_length"], 7)
        self.assertTrue(result["uid_match"])
        self.assertIsNone(result["bcc4_ok"])

    def test_negative_and_short_reply_is_not_success(self):
        key = b"k"
        self.assertEqual(d.decode_read(b"\0\0\0\0" + bytes(16),
                                       0, 1, key)["status"], "read_failed")
        self.assertEqual(d.decode_read(b"\0\0\0\1" + bytes(15),
                                       0, 1, key)["status"], "invalid_response")
        self.assertEqual(d.decode_read(b"\0\0\0\1" + bytes(32),
                                       0, 2, key)["status"], "partial_read")
        self.assertIsNone(d.decode_block(b"\0\0\0\0" + bytes(16), 0, 1))
        self.assertIsNone(d.decode_block(b"\0\0\0\3" + bytes(16), 0, 2))

    def test_anonymized_tags_are_consistent_but_run_specific(self):
        uid = bytes.fromhex("11223344")
        self.assertEqual(d.tag(b"key1", uid), d.tag(b"key1", uid))
        self.assertNotEqual(d.tag(b"key1", uid), d.tag(b"key2", uid))
        self.assertEqual(len(d.tag(b"key1", uid)), 16)


if __name__ == "__main__":
    unittest.main()
