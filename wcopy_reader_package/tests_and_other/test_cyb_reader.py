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
            if command == 0x6A:
                assert body[:15] == b'\x01\x01\x00' + b'\xff'*12
                assert len(body) == 31
                self.block = body[15:]
                result = b'\0\0\0\1'
            else:
                assert len(body) == 15 and body[3:] == b'\xff'*12
                self.reads += 1
                start, count, mode = body[:3]
                assert mode == 0
                if len(self.uid) == 4:
                    bcc = self.uid[0] ^ self.uid[1] ^ self.uid[2] ^ self.uid[3]
                    block0 = self.uid + bytes([bcc]) + b'\0'*11
                else:
                    block0 = self.uid.ljust(16, b'\0')
                if (start, count) == (0, 2):
                    result = b'\0\0\0\3' + block0 + self.block
                elif (start, count) == (1, 1):
                    result = b'\0\0\0\1' + self.block
                elif (start, count) == (0, 1):
                    result = b'\0\0\0\1' + block0
                else:
                    raise AssertionError((start, count))
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
        r._OWNED_CYB.clear()
        self.addCleanup(r._OWNED_CYB.clear)

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

    def test_read_keeps_host_mode_and_closes_usb(self):
        d = Device()
        card = self.run_device(d)
        self.assertEqual(card, r.CardData(UID, BLOCK, b'\0\0', 0))
        self.assertEqual(card.number, 513)
        self.assertEqual([int.from_bytes(x[2:4], 'big') for x in d.sent], [0x51,0x6c,0x55])
        reads = [p for p in d.sent if p[3] == 0x6C]
        self.assertEqual(len(reads), 1)
        self.assertEqual(reads[0][6:9], b'\x00\x02\x00')
        self.assertFalse(any(x[2:4] == b'\0\x51' and x[6:-2] == b'\0' for x in d.sent))
        self.assertTrue(d.closed)

    def test_fragmentation(self):
        self.assertEqual(self.run_device(Device(fragmented=True)).number, 513)

    def test_padded_and_report_id(self):
        for n, prefix in [(64,b''), (64,b'\0')]:
            bcc = UID[0] ^ UID[1] ^ UID[2] ^ UID[3]
            raw = prefix + frame(0x6C, b'\0\0\0\3' + UID + bytes([bcc]) +
                                 b'\0'*11 + BLOCK).ljust(n, b'\0')
            self.assertEqual(self.run_device(Device(failures={0x6C:raw})).number, 513)

    def test_unsolicited_frame(self):
        bcc = UID[0] ^ UID[1] ^ UID[2] ^ UID[3]
        response = (frame(0x1234,b'notification') +
                    frame(0x6C, b'\0\0\0\3' + UID + bytes([bcc]) + b'\0'*11 + BLOCK))
        self.assertEqual(self.run_device(Device(failures={0x6C:response})).number, 513)

    def test_empty_reader(self):
        d = Device(failures={0x6C:frame(0x6C,b'\0'*36)})
        with self.assertRaises(r.NoCardError): self.run_device(d)
        self.assertTrue(d.closed)
        self.assertFalse(any(x[2:4] == b'\0\x51' and x[6:-2] == b'\0' for x in d.sent))

    def test_bad_read_replies(self):
        for reply, error in [
            (None,r.ReaderTimeoutError),
            (b'\x55',r.ProtocolError),
            (b'\x55\0\x6c\xff\xff',r.ProtocolError),
            (b'garbage',r.ProtocolError),
            (frame(0x6C,b'\0\0\0\1'+BLOCK)[:-1]+b'\xff',r.ProtocolError),
            (frame(0x6C,b'\0'*4+BLOCK),r.NoCardError),
            (frame(0x6C,b'\0\0\0\1'),r.ProtocolError),
            (frame(0x6C,b'\0\0\0\1'+bytes(32)),r.CardReadError),
            (frame(0x6C,b'\0\0\0\3'+b'\0'*4+b'\x01'+bytes(27)),r.UnsupportedCardError),
        ]:
            with self.subTest(reply=reply):
                d=Device(failures={0x6C:reply})
                with self.assertRaises(error): self.run_device(d)
                self.assertTrue(d.closed)

    def test_partial_fast_read_recovers_after_one_or_two_retries(self):
        for masks in ((1, 3), (2, 1, 3)):
            with self.subTest(masks=masks):
                d = Device()
                actual_write = d.write
                sequence = iter(masks)
                bcc = UID[0] ^ UID[1] ^ UID[2] ^ UID[3]
                manufacturer = UID + bytes([bcc]) + b'\0'*11

                def write(report):
                    if int.from_bytes(report[2:4], 'big') == 0x6C:
                        mask = next(sequence)
                        d.failures[0x6C] = frame(
                            0x6C, mask.to_bytes(4, 'big') + manufacturer + BLOCK)
                    return actual_write(report)

                d.write = write
                with patch.object(r.time, 'sleep') as sleep:
                    card = self.run_device(d)
                self.assertEqual(card.number, 513)
                self.assertEqual(d.reads, len(masks))
                self.assertEqual(sleep.call_count, len(masks) - 1)
                sleep.assert_any_call(0.05)
                self.assertFalse(any(report[3] == 0x69 for report in d.sent))

    def test_partial_fast_read_exhausts_exactly_two_retries(self):
        for mask in (1, 2):
            with self.subTest(mask=mask):
                bcc = UID[0] ^ UID[1] ^ UID[2] ^ UID[3]
                manufacturer = UID + bytes([bcc]) + b'\0'*11
                d = Device(failures={0x6C: frame(
                    0x6C, mask.to_bytes(4, 'big') + manufacturer + BLOCK)})
                with patch.object(r.time, 'sleep') as sleep:
                    with self.assertRaises(r.CardReadError) as error:
                        self.run_device(d)
                self.assertEqual(error.exception.stage, 'read')
                self.assertEqual(error.exception.status, mask)
                self.assertEqual(d.reads, 3)
                self.assertEqual(sleep.call_count, 2)

    def test_fast_read_does_not_retry_no_card_or_invalid_mask(self):
        for mask, error_type in ((0, r.NoCardError), (4, r.CardReadError)):
            with self.subTest(mask=mask):
                d = Device(failures={0x6C: frame(
                    0x6C, mask.to_bytes(4, 'big') + bytes(32))})
                with patch.object(r.time, 'sleep') as sleep:
                    with self.assertRaises(error_type):
                        self.run_device(d)
                self.assertEqual(d.reads, 1)
                sleep.assert_not_called()

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

    def test_read_does_not_poll_uid_again(self):
        d=Device()
        write=d.write
        def changed(report):
            ret=write(report)
            if report[3]==0x6C:d.uid=b'1234'
            return ret
        d.write=changed
        card = self.run_device(d)
        self.assertEqual(card.uid, UID)
        self.assertEqual(card.block, BLOCK)
        self.assertEqual(sum(x[3] == 0x69 for x in d.sent), 0)
        self.assertEqual(sum(x[3] == 0x6C for x in d.sent), 1)

    def test_write_still_detects_changed_uid(self):
        d = Device()
        write = d.write
        def changed(report):
            result = write(report)
            if report[3] == 0x6A:
                d.uid = b'1234'
            return result
        d.write = changed
        with self.assertRaises(r.VerificationError) as ctx:
            self.run_device(d, lambda: r.write_card_number(999))
        self.assertEqual(ctx.exception.stage, 'verify')
        self.assertEqual(sum(x[3] == 0x69 for x in d.sent), 2)
        self.assertEqual(d.reads, 2)

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

    def test_fast_read_rejects_unverified_uid_but_write_keeps_7_byte_support(self):
        d = Device(); d.uid = b'1234567'
        with self.assertRaises(r.UnsupportedCardError):
            self.run_device(d)
        d = Device(); d.uid = b'1234567'
        self.assertEqual(self.run_device(
            d, lambda: r.write_card_number(123)).__class__, int)
        self.assertEqual([p[3] for p in d.sent].count(0x69), 2)
        bad = bytearray(info()); bad[15] = 0
        with self.assertRaises(r.UnsupportedCardError):
            self.run_device(
                Device(failures={0x69:frame(0x69,bytes(bad))}),
                lambda: r.write_card_number(123))

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
        self.assertFalse(any(x[2:4] == b'\0\x51' and x[6:-2] == b'\0' for x in d.sent))
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
        d=Device(failures={0x6C:frame(0x6C,b'\0'*36)})
        write=d.write
        def fail_release(report):
            if report[3]==0x51 and report[6]==0:raise OSError('unplugged')
            return write(report)
        d.write=fail_release
        with patch.object(r, "_PERSISTENT_HOST_CONTROL", False), self.assertRaises(r.NoCardError) as ctx:self.run_device(d)
        self.assertTrue(ctx.exception.__notes__)
        self.assertTrue(d.closed)


if __name__=='__main__': unittest.main()
