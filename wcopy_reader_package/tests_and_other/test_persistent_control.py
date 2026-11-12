"""Persistent device mode, explicit release and reconnect recovery."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import wcopy_reader as r
from test_cyb_reader import Device, descriptor, frame


class PersistentControlTests(unittest.TestCase):
    def setUp(self):
        r._PRESENCE.clear()
        r._OWNED_CYB.clear()
        self.addCleanup(r._OWNED_CYB.clear)
        self.enterContext(patch.object(r, '_PERSISTENT_HOST_CONTROL', True))
        self.device = Device()
        self.descriptors = [descriptor()]
        fake = SimpleNamespace(device=lambda: self.device,
            enumerate=lambda v,p: [d for d in self.descriptors
                                   if (d['vendor_id'], d['product_id']) == (v,p)])
        self.enterContext(patch.object(r, '_get_hid', return_value=fake))

    def controls(self):
        return [x[6:-2] for x in self.device.sent if x[2:4] == b'\0\x51']

    def test_two_reads_keep_mode_but_close_usb(self):
        r.read_card()
        self.assertTrue(self.device.closed)
        r.read_card()
        self.assertEqual(self.controls(), [b'\1', b'\1'])
        self.assertTrue(r.close_readers())
        self.assertEqual(self.controls(), [b'\1', b'\1', b'\0'])
        self.assertTrue(r.close_readers())
        self.assertEqual(len(self.controls()), 3)

    def test_absence_and_errors_do_not_release_or_repeat_write(self):
        self.device.failures[0x69] = frame(0x69, b'\0'*19)
        with self.assertRaises(r.NoCardError): r.read_card()
        self.assertEqual(self.controls(), [b'\1'])
        self.device.failures.clear()
        self.device.failures[0x6a] = None
        with self.assertRaises(r.ReaderTimeoutError): r.write_card_number(555)
        self.assertEqual(self.controls(), [b'\1', b'\1'])
        self.assertEqual(sum(x[2:4] == b'\0\x6a' for x in self.device.sent), 1)
        self.assertTrue(r.close_readers())

    def test_unplug_then_same_path_reconnect_reasserts_mode(self):
        r.read_card()
        self.descriptors = []
        with self.assertRaises(r.ReaderNotFoundError): r.read_card()
        self.assertFalse(r.close_readers())
        self.device = Device()  # Power reset, same path, no remembered firmware mode.
        self.descriptors = [descriptor()]
        r.read_card()
        self.assertEqual(self.controls(), [b'\1'])
        self.assertTrue(r.close_readers())
        self.assertEqual(self.controls(), [b'\1', b'\0'])

    def test_opt_out_releases_now_and_restores_legacy_operations(self):
        r.read_card(auto_feedback=False)
        self.assertTrue(r.set_persistent_host_control(False))
        r.read_card(auto_feedback=False)
        self.assertEqual(self.controls(), [b'\1', b'\0', b'\1', b'\0'])
        self.assertTrue(r.set_persistent_host_control(True))
        r.read_card(auto_feedback=False)
        self.assertEqual(self.controls()[-1], b'\1')
        r.close_readers()

    def test_failed_initialize_is_released_without_losing_original_error(self):
        self.device.failures[0x51] = frame(0x51, b'\2')
        with self.assertRaises(r.ReaderCommandError) as caught:
            r.read_card()
        self.assertEqual(caught.exception.stage, 'initialize')
        self.assertEqual(self.controls(), [b'\1', b'\0'])
        self.assertIn(b'cyb', r._OWNED_CYB)  # Cleanup not confirmed: retry on shutdown.
        self.device.failures.clear()
        self.assertTrue(r.close_readers())

    def test_release_failure_is_logged_and_retryable(self):
        r.read_card()
        with patch.object(self.device, 'write', side_effect=OSError('disconnect')):
            self.assertFalse(r.close_readers())
        self.assertIn(b'cyb', r._OWNED_CYB)
        self.assertTrue(r.close_readers())
        self.assertNotIn(b'cyb', r._OWNED_CYB)

    def test_release_only_owned_paths(self):
        r.read_card()
        self.descriptors.append(descriptor(b'other'))
        self.assertTrue(r.close_readers(path=b'other'))
        self.assertEqual(self.controls(), [b'\1'])
        self.assertTrue(r.close_readers(path=b'cyb'))
        self.assertEqual(self.device.path, b'cyb')

    def test_shutdown_waits_for_current_operation(self):
        entered = threading.Event()
        proceed = threading.Event()
        released = threading.Event()
        errors = []
        original = r._CybSession.read
        def slow(session):
            entered.set()
            proceed.wait(2)
            return original(session)
        def read():
            try: r.read_card()
            except Exception as exc: errors.append(exc)
        def close():
            r.close_readers()
            released.set()
        with patch.object(r._CybSession, 'read', slow):
            reader = threading.Thread(target=read)
            reader.start()
            self.assertTrue(entered.wait(1))
            closer = threading.Thread(target=close)
            closer.start()
            self.assertFalse(released.wait(0.02))
            proceed.set()
            reader.join(2)
            closer.join(2)
        self.assertFalse(errors)
        self.assertTrue(released.is_set())
        self.assertEqual(self.controls(), [b'\1', b'\0'])

    def test_unused_cleanup_and_manual_beep_do_not_take_over(self):
        self.assertTrue(r.close_readers())
        r.beep()
        self.assertEqual(self.controls(), [])
        self.assertTrue(r.close_readers())
