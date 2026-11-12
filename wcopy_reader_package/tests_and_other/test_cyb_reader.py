"""Protocol fixtures derived from EXE, NOT captures from physical hardware."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import wcopy_reader as r

UID = bytes.fromhex('c3d7c833')
BLOCK = bytes(range(8)) + (513).to_bytes(8, 'big')


def frame(command, body):
    # Independent fixture encoder for short responses.
    checksum = 0
    for b in body:
        checksum ^= b
    return b'\x55' + command.to_bytes(2, 'big') + len(body).to_bytes(2, 'big') + body + bytes([255 ^ checksum, checksum])


def info(uid=UID):
    return b'\x01\x00' + uid.ljust(10, b'\0') + bytes([len(uid)]) + b'\x04\x00\x08\x01\x10\x00'


def descriptor(path=b'cyb', pid=0x4300):
    return dict(path=path, vendor_id=0x0483, product_id=pid, interface_number=0,
                manufacturer_string='CYBDZKJ-BSJ', product_string='TCC-TSY-TBY', serial_number='BEGIN-2025-123')


class Device:
    def __init__(self, block=BLOCK, failures=None, fragmented=False):
        self.block = block
        self.uid = UID
        self.failures = failures or {}
        self.queue = []
        self.sent = []
        self.closed = False
        self.fragmented = fragmented
        self.reads = 0

    def open_path(self, path):
        self.path = path

    def close(self):
        self.closed = True

    def write(self, report):
        self.sent.append(report)
        assert report[0:2] == b'\0\x55'
        command = int.from_bytes(report[2:4], 'big')
        body = report[6:-2]
        assert report[1:] == frame(command, body)
        if command == 0x55:
            return len(report)
        if command == 0x51:
            result = body
        elif command == 0x69:
            result = info(self.uid)
        elif command in (0x6C, 0x6A):
            assert body[:15] == b'\x01\x01\x00' + b'\xff'*12
            if command == 0x6A:
                assert len(body) == 31
                self.block = body[15:]
                result = b'\0\0\0\1'
            else:
                assert len(body) == 15
                self.reads += 1
                result = b'\0\0\0\1' + self.block
        else:
            raise AssertionError(command)
        response = self.failures.get(command, frame(command, result))
        if response is not None:
            if self.fragmented:
                self.queue += [response[:3], response[3:9], response[9:]]
            else:
                self.queue.append(response)
        return len(report)

    def read(self, size, timeout):
        return self.queue.pop(0) if self.queue else b''


class CybTests(unittest.TestCase):
    def setUp(self):
        r._PRESENCE.clear()

    def run_device(self, device, callback=None, descriptors=None):
        devices = descriptors if descriptors is not None else [descriptor()]
        fake = SimpleNamespace(device=lambda: device,
            enumerate=lambda v, p: [d for d in devices if (d['vendor_id'], d['product_id']) == (v, p)])
        with patch.object(r, '_get_hid', return_value=fake):
            return (callback or r.read_card)()

    def test_reference_request_bytes(self):
        self.assertEqual(r._cyb_request(0x51, b'\1').hex(), '550051000101fe01')
        self.assertEqual(r._cyb_request(0x69, b'').hex(), '5500690000ff00')
        self.assertEqual(r._cyb_request(0x6C, b'\1\1\0' + b'\xff'*12).hex(),
                         '55006c000f010100ffffffffffffffffffffffffff00')

    def test_read_and_release(self):
        d = Device()
        card = self.run_device(d)
        self.assertEqual(card, r.CardData(UID, BLOCK, b'\0\4', 8))
        self.assertEqual(card.number, 513)
        self.assertEqual([int.from_bytes(x[2:4], 'big') for x in d.sent], [0x51,0x69,0x6c,0x69,0x55,0x51])
        self.assertEqual(d.sent[-1][6], 0)
        self.assertTrue(d.closed)

    def test_fragmentation(self):
        self.assertEqual(self.run_device(Device(fragmented=True)).number, 513)

    def test_padded_and_report_id(self):
        for n, prefix in [(64,b''), (64,b'\0')]:
            raw = prefix + frame(0x6C, b'\0\0\0\1' + BLOCK).ljust(n, b'\0')
            self.assertEqual(self.run_device(Device(failures={0x6C:raw})).number, 513)

    def test_unsolicited_frame(self):
        response = frame(0x1234,b'notification') + frame(0x6C,b'\0\0\0\1' + BLOCK)
        self.assertEqual(self.run_device(Device(failures={0x6C:response})).number, 513)

    def test_empty_reader(self):
        d = Device(failures={0x69:frame(0x69,b'\0'*19)})
        with self.assertRaises(r.NoCardError): self.run_device(d)
        self.assertTrue(d.closed)
        self.assertEqual(d.sent[-1][6], 0)

    def test_bad_read_replies(self):
        for reply, error in [
            (None,r.ReaderTimeoutError),
            (b'\x55',r.ProtocolError),
            (b'\x55\0\x6c\xff\xff',r.ProtocolError),
            (b'garbage',r.ProtocolError),
            (frame(0x6C,b'\0\0\0\1'+BLOCK)[:-1]+b'\xff',r.ProtocolError),
            (frame(0x6C,b'\0'*4+BLOCK),r.CardReadError),
            (frame(0x6C,b'\0\0\0\1'),r.ProtocolError),
        ]:
            with self.subTest(reply=reply):
                d=Device(failures={0x6C:reply})
                with self.assertRaises(error): self.run_device(d)
                self.assertTrue(d.closed)

    def test_write_preserves_prefix_and_verifies(self):
        d=Device()
        result=self.run_device(d,lambda:r.write_card_number(999,expected_uid=UID,expected_block=BLOCK))
        self.assertEqual(result,999)
        self.assertEqual(d.block,BLOCK[:8]+(999).to_bytes(8,'big'))
        self.assertEqual(d.reads,2)
        self.assertEqual(sum(x[3]==0x6A for x in d.sent),1)

    def test_format_zero_max_and_data_ending_9000(self):
        for value in (0, 2**64-1, 0x9000):
            self.assertEqual(self.run_device(Device(),lambda:r.write_card_number(value)),value)
        d=Device()
        self.assertEqual(self.run_device(d,lambda:r.write_card_number(257,offset=0,length=2,byteorder='little')),257)
        self.assertEqual(d.block[2:],BLOCK[2:])

    def test_prewrite_guards(self):
        for kwargs in [dict(expected_uid=b'1234'),dict(expected_block=b'\0'*16)]:
            d=Device()
            with self.assertRaises(r.VerificationError) as ctx:
                self.run_device(d,lambda:r.write_card_number(123,**kwargs))
            self.assertEqual(ctx.exception.stage,'prewrite')
            self.assertFalse(any(x[3]==0x6A for x in d.sent))

    def test_write_timeout_not_retried(self):
        d=Device(failures={0x6A:None})
        with self.assertRaises(r.ReaderTimeoutError):self.run_device(d,lambda:r.write_card_number(123))
        self.assertEqual(sum(x[3]==0x6A for x in d.sent),1)

    def test_verification_failure(self):
        d=Device(failures={0x6C:frame(0x6C,b'\0\0\0\1'+BLOCK)})
        with self.assertRaises(r.VerificationError) as ctx:self.run_device(d,lambda:r.write_card_number(123))
        self.assertEqual(ctx.exception.stage,'verify')

    def test_uid_change_during_read(self):
        d=Device()
        write=d.write
        def changed(report):
            ret=write(report)
            if report[3]==0x6C:d.uid=b'1234'
            return ret
        d.write=changed
        with self.assertRaises(r.VerificationError):self.run_device(d)

    def test_both_pids_and_descriptor_filter(self):
        for pid in (0x4300,0x4343):
            readers=self.run_device(Device(),r.list_readers,[descriptor(pid=pid)])
            self.assertEqual(readers[0].backend,'cyb')
        for field in ('manufacturer_string','product_string','serial_number'):
            bad=descriptor();bad[field]='Other device'
            self.assertEqual(self.run_device(Device(),r.list_readers,[bad]),())

    def test_multiple_and_explicit_path(self):
        readers=[descriptor(b'one'),descriptor(b'two',0x4343)]
        with self.assertRaises(r.MultipleReadersError):self.run_device(Device(),descriptors=readers)
        d=Device();self.run_device(d,lambda:r.read_card(path=b'two'),readers)
        self.assertEqual(d.path,b'two')

    def test_feedback_payloads(self):
        for call, payloads in (
            (r.beep, ['01010100']),
            (lambda: r.beep(t=6, count=3), ['01020300']),
            (lambda: r.beep(t=1), ['01010100']),
            (lambda: r.beep(t=255, count=999), ['01fbff00']),
            (lambda: r.set_led('red'), ['00010100']),
            (lambda: r.set_led('green'), ['00010100']),
            (lambda: r.set_led('off'), ['00000000']),
            (lambda: r.set_reader_feedback('green', beep=True, count=2),
             ['00010100', '01010200']),
        ):
            with self.subTest(payloads=payloads):
                d = Device()
                result = self.run_device(d, call)
                self.assertIn(result, (b'', (b'', b'')))
                self.assertEqual([x[6:-2].hex() for x in d.sent], payloads)
                self.assertTrue(all(x[2:4] == b'\0\x55' for x in d.sent))
                self.assertTrue(d.closed)

    def test_feedback_failures_do_not_escape(self):
        for method in ('write', 'open_path', 'close'):
            for call in (r.beep, lambda: r.set_led('green'),
                         lambda: r.set_reader_feedback('red', beep=True)):
                d = Device()
                with patch.object(d, method, side_effect=OSError('disconnected')):
                    self.assertIn(self.run_device(d, call), (b'', (), (b'', b'')))

    def test_feedback_initialization_failure_is_suppressed_and_released(self):
        d = Device(failures={0x51: frame(0x51, b'\x02')})
        self.assertEqual(self.run_device(d, lambda: r.beep(initialize=True)), b'')
        self.assertEqual([x[6:-2] for x in d.sent], [b'\1', b'\0'])
        self.assertTrue(d.closed)

    def test_feedback_count_validation(self):
        for count in (0, -1, True, 1.5):
            for call in (lambda: r.beep(count=count),
                         lambda: r.set_reader_feedback('red', count=count)):
                with self.assertRaises(ValueError):
                    call()

    def test_old_reader_ignores_count(self):
        session = r._Session(Device(), 2500)
        with patch.object(session, 'feedback_command', return_value=b'ok') as send:
            self.assertEqual(session.beep(5, count=3), b'ok')
            send.assert_called_once_with(bytes.fromhex('ff0040500405010101'))

    def test_mixed_readers_require_selection(self):
        old = dict(path=b'wcopy', vendor_id=r.VID, product_id=r.PID, interface_number=0)
        with self.assertRaises(r.MultipleReadersError):
            self.run_device(Device(), descriptors=[old, descriptor()])
        d = Device()
        self.assertEqual(self.run_device(d, lambda:r.read_card_number(path=b'cyb'),
                                        [old, descriptor()]), 513)

    def test_uid_seven_bytes_and_unsupported_card(self):
        d = Device(); d.uid = b'1234567'
        self.assertEqual(self.run_device(d).uid, d.uid)
        bad = bytearray(info()); bad[15] = 0
        with self.assertRaises(r.UnsupportedCardError):
            self.run_device(Device(failures={0x69:frame(0x69,bytes(bad))}))

    def test_write_rejected_and_malformed(self):
        for body, error in [(b'\0'*4, r.CardWriteError), (b'\1', r.ProtocolError)]:
            d = Device(failures={0x6A:frame(0x6A,body)})
            with self.assertRaises(error):self.run_device(d,lambda:r.write_card_number(123))
            self.assertEqual(sum(x[3]==0x6A for x in d.sent),1)

    def test_windows_padded_write_count(self):
        d = Device()
        write = d.write
        def windows_write(report):
            write(report)
            return 65  # hidapi/windows/hid.c returns padded OutputReportByteLength
        d.write = windows_write
        result = self.run_device(d, lambda:r.write_card_number(999))
        self.assertEqual(result, 999)
        self.assertEqual(sum(x[3] == 0x6A for x in d.sent), 1)
        self.assertEqual(d.sent[0][6], 1)
        self.assertEqual(d.sent[-1][6], 0)
        self.assertTrue(d.closed)

    def test_invalid_write_counts_are_not_accepted(self):
        for count in (-1, 0, 8, 10, 64, 66):
            with self.subTest(count=count):
                d = Device()
                d.write = lambda data: count
                with self.assertRaises(r.USBError) as ctx:
                    self.run_device(d)
                self.assertIn(str(count), str(ctx.exception))
                self.assertTrue(d.closed)

    def test_stale_frame_drained(self):
        d = Device(); d.queue = [frame(0x69,info(b'1234'))]
        self.assertEqual(self.run_device(d).uid, UID)

    def test_usb_short_write(self):
        d = Device(); d.write = lambda data: len(data)-1
        with self.assertRaises(r.USBError): self.run_device(d)
        self.assertTrue(d.closed)

    def test_watch_uses_same_events(self):
        d=Device()
        event=self.run_device(d,lambda:next(r.watch_cards()))
        self.assertIsInstance(event,r.CardPresented)
        self.assertEqual(event.number,513)

    def test_release_error_does_not_hide_primary_error(self):
        d=Device(failures={0x69:frame(0x69,b'\0'*19)})
        write=d.write
        def fail_release(report):
            if report[3]==0x51 and report[6]==0:raise OSError('unplugged')
            return write(report)
        d.write=fail_release
        with self.assertRaises(r.NoCardError) as ctx:self.run_device(d)
        self.assertTrue(ctx.exception.__notes__)
        self.assertTrue(d.closed)


if __name__=='__main__': unittest.main()
