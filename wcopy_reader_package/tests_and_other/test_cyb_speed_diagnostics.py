"""Validate diagnostic command sequences without physical hardware."""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import cyb_speed_diagnostics as d
from test_cyb_reader import Device, descriptor, frame
r = d.r


class SpeedTests(unittest.TestCase):
    def setUp(self):
        r._PRESENCE.clear()
        r._OWNED_CYB.clear()
        self.addCleanup(r._OWNED_CYB.clear)

    def run_mode(self, mode, device):
        rows = []
        fake = SimpleNamespace(device=lambda: device, enumerate=lambda v, p: [descriptor()] if (v, p) == (0x0483, 0x4300) else [])
        profiler = d.Profiler()
        with patch.object(r, '_get_hid', return_value=fake), \
             patch.object(r, '_PERSISTENT_HOST_CONTROL', True), \
             contextlib.redirect_stdout(io.StringIO()), profiler.instrument():
            d.run_mode(profiler, b'cyb', mode, 'held', 3, 5, 0, rows.append)
        self.assertTrue(device.closed)
        return rows

    def test_modes_use_one_fast_read_and_never_write_or_beep(self):
        for mode, initialize_count in zip(d.MODES, (3, 3, 1)):
            with self.subTest(mode=mode):
                device = Device()
                rows = self.run_mode(mode, device)
                cards = [row for row in rows if row['status'] == 'card']
                self.assertEqual(len(cards), 3)
                commands = [int.from_bytes(p[2:4], 'big') for p in device.sent]
                self.assertEqual(commands.count(0x51), initialize_count)
                self.assertEqual(commands.count(0x69), 0)
                self.assertEqual(commands.count(0x6C), 3)
                self.assertLessEqual(set(commands), {0x51, 0x6C})
                for row in cards:
                    self.assertIn('read', d.totals(row))
                    self.assertNotIn('poll_2', d.totals(row))

    def test_absent_card_does_not_read_block(self):
        device = Device(failures={0x6C: frame(0x6C, bytes(36))})
        rows = self.run_mode('open_once', device)
        self.assertEqual([x['status'] for x in rows], ['setup'] + ['no_card']*3)
        self.assertEqual(device.reads, 3)

    def test_timeout_stops_retained_session(self):
        device = Device(failures={0x6C: None})
        rows = self.run_mode('open_once', device)
        self.assertEqual([x['status'] for x in rows], ['setup', 'error'])
        self.assertEqual(rows[-1]['stage'], 'read')
        self.assertIn('read', d.totals(rows[-1]))
        self.assertEqual(d.summary(rows), [])


if __name__ == '__main__':
    unittest.main()
