"""Automatic signals and presentation tracking, without physical hardware."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import wcopy_reader as r
from test_cyb_reader import Device, descriptor, frame, UID, BLOCK


class AutoFeedbackTests(unittest.TestCase):
    def setUp(self):
        r._PRESENCE.clear()
        r._OWNED_CYB.clear()
        self.addCleanup(r._OWNED_CYB.clear)
        self.device = Device()
        self.descriptors = [descriptor()]
        fake = SimpleNamespace(device=lambda: self.device,
            enumerate=lambda v, p: [d for d in self.descriptors
                                     if (d['vendor_id'], d['product_id']) == (v, p)])
        self.enterContext(patch.object(r, '_get_hid', return_value=fake))

    def signals(self):
        return [x[6:-2] for x in self.device.sent if x[2:4] == b'\0\x55']

    def absent(self):
        self.device.failures[0x6C] = frame(0x6C, b'\0'*36)
        with self.assertRaises(r.NoCardError):
            r.read_card()

    def test_one_sound_per_placement_and_two_absences(self):
        first = r.read_card()
        held = r.read_card()
        self.assertTrue(first.is_new)
        self.assertFalse(held.is_new)
        self.assertEqual(first.presentation_id, held.presentation_id)
        self.absent()
        self.assertFalse(r.is_card_removed())
        self.absent()
        self.assertTrue(r.is_card_removed())
        self.device.failures.clear()
        again = r.read_card()
        self.assertTrue(again.is_new)
        self.assertNotEqual(first.presentation_id, again.presentation_id)
        self.assertEqual(self.signals(), [bytes.fromhex('01010100')]*2)

    def test_error_interrupts_absence_but_does_not_rearm_held_card(self):
        first = r.read_card()
        self.absent()
        with patch.object(r._CybSession, 'read', side_effect=r.USBError('lost', stage='read')):
            with self.assertRaises(r.USBError):
                r.read_card()
        self.absent()
        self.assertFalse(r.is_card_removed())
        self.device.failures.clear()
        held = r.read_card()
        self.assertEqual(first.presentation_id, held.presentation_id)
        self.assertEqual(len(self.signals()), 1)

    def test_changed_uid_and_separate_reader_paths(self):
        first = r.read_card()
        self.device.uid = b'abcd'
        second = r.read_card()
        self.assertNotEqual(first.presentation_id, second.presentation_id)
        self.descriptors = [descriptor(b'other')]
        third = r.read_card()
        self.assertTrue(third.is_new)
        self.assertNotEqual(second.presentation_id, third.presentation_id)
        self.assertEqual(len(self.signals()), 3)

    def test_write_only_double_signal_after_full_verification(self):
        self.assertEqual(r.write_card_number(555), 555)
        self.assertEqual(self.signals(), [bytes.fromhex('01010200')])
        commands = [int.from_bytes(x[2:4], 'big') for x in self.device.sent]
        self.assertEqual(commands.count(0x6c), 2)
        self.assertGreater(commands.index(0x55), max(i for i,c in enumerate(commands) if c == 0x6c))
        self.assertEqual(commands[-1], 0x55)  # Host control stays enabled.
        self.assertFalse(r.read_card().is_new)
        self.assertEqual(len(self.signals()), 1)

    def test_verification_failure_never_signals_success(self):
        self.device.failures[0x6c] = frame(0x6c, b'\0\0\0\1' + BLOCK)
        with self.assertRaises(r.VerificationError):
            r.write_card_number(555)
        self.assertEqual(self.signals(), [])

    def test_opt_out_keeps_tracking_and_manual_api(self):
        first = r.read_card(auto_feedback=False)
        self.assertTrue(first.is_new)
        self.assertFalse(r.read_card().is_new)
        r.write_card_number(555, auto_feedback=False)
        self.assertEqual(self.signals(), [])
        r.beep(count=2)
        self.assertEqual(self.signals(), [bytes.fromhex('01010200')])

    def test_signal_failure_does_not_change_read_or_write_result(self):
        with patch.object(r._CybSession, '_send_feedback', side_effect=r.USBError('lost', stage='feedback')):
            self.assertEqual(r.read_card().block, BLOCK)
            r._PRESENCE.clear()
            self.assertEqual(r.write_card_number(555), 555)
        self.assertFalse(any(x[2:4] == b'\0\x51' and x[6:-2] == b'\0'
                             for x in self.device.sent))

    def test_old_reader_updates_led_without_read_beep_and_write_ten(self):
        self.descriptors = [dict(path=b'old', vendor_id=r.VID, product_id=r.PID, interface_number=0)]
        card = r.CardData(UID, BLOCK, b'\0\4', 8)
        events = []
        with patch.object(r._Session, 'read', return_value=card), \
             patch.object(r._Session, 'set_led', side_effect=lambda c: events.append(('led', c))), \
             patch.object(r._Session, 'beep', side_effect=lambda **kw: events.append(('beep', kw))):
            r.read_card()
            r.read_card()
            self.assertEqual(events, [('led', 'green')]*2)
            with patch.object(r._Session, 'read', side_effect=r.NoCardError('none', stage='poll')):
                with self.assertRaises(r.NoCardError): r.read_card()
            self.assertEqual(events[-1], ('led', 'red'))
            with patch.object(r._Session, 'write_number', return_value=card):
                r.write_card_number(card.number)
            self.assertEqual(events[-2:], [('led', 'green'), ('beep', {'t': 10})])

    def test_old_feedback_failure_preserves_absence_and_data(self):
        self.descriptors = [dict(path=b'old', vendor_id=r.VID, product_id=r.PID, interface_number=0)]
        card = r.CardData(UID, BLOCK, b'\0\4', 8)
        with patch.object(r._Session, 'set_led', side_effect=r.FeedbackError('bad', stage='feedback')):
            with patch.object(r._Session, 'read', return_value=card):
                self.assertEqual(r.read_card(), card)
            with patch.object(r._Session, 'read', side_effect=r.NoCardError('none', stage='poll')):
                with self.assertRaises(r.NoCardError): r.read_card()

    def test_watch_sound_false_does_not_leak_to_later_reads(self):
        watcher = r.watch_cards(sound=False)
        event = next(watcher)
        self.assertIsInstance(event, r.CardPresented)
        watcher.close()
        self.assertEqual(self.signals(), [])
        self.device.uid = b'next'
        r.read_card()
        self.assertEqual(self.signals(), [bytes.fromhex('01010100')])

    def test_invalid_opt_out_never_touches_usb(self):
        with patch.object(r, '_get_hid') as hid:
            for fn in (lambda: r.read_card(auto_feedback=0),
                       lambda: r.read_card_number(auto_feedback=None),
                       lambda: r.write_card_number(1, auto_feedback='no')):
                with self.assertRaises(ValueError): fn()
            hid.assert_not_called()
