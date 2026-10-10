""" Автоматические тесты отдельных команд индикации set_led() и beep() """
import io
import threading
import unittest
from contextlib import contextmanager, redirect_stdout
from unittest.mock import patch

import wcopy_reader as r
import examples.write_example
import examples.watch_example

class IndicationAPITests(unittest.TestCase):
    def test_independent_public_commands(self):
        session = r._Session(None, 2500)
        @contextmanager
        def opened(*args):
            yield session
        with patch.object(r, '_open_session', opened), \
                patch.object(session, 'exchange', return_value=b'\x90\x01') as exchange:
            self.assertEqual(r.set_led('green'), b'\x90\x01')
            self.assertEqual([c.args[0] for c in exchange.call_args_list],
                             [bytes.fromhex('FF 00 40 0E 04 00 00 00 00')])
            exchange.reset_mock()
            self.assertEqual(r.beep(), b'\x90\x01')
            self.assertEqual([c.args[0] for c in exchange.call_args_list],
                             [bytes.fromhex('FF 00 40 50 04 01 01 01 01')])

    def test_state_reporting_does_not_send_indication(self):
        stop = threading.Event()
        card = r.CardData(b'aaaa', b'\0'*16, b'\0\x04', 8)
        absent = r.NoCardError('absent', stage='poll')
        sequence = iter([absent, card, card, absent, absent])
        def read(**kwargs):
            try:
                value = next(sequence)
            except StopIteration:
                stop.set()
                raise r.ReaderTimeoutError('end', stage='poll')
            if isinstance(value, Exception):
                raise value
            return value
        with patch.object(r, 'read_card', side_effect=read), \
                patch.object(r, 'set_reader_feedback') as feedback, \
                patch.object(r, 'set_led') as led, patch.object(r, 'beep') as beep:
            events = list(r.watch_cards(stop=stop, interval=0.00001, report_state=True))
        states = [e for e in events if isinstance(e, r.CardState)]
        self.assertEqual(states, [r.CardState(False), r.CardState(True, True),
                                 r.CardState(True), r.CardState(True), r.CardState(False)])
        self.assertEqual(len([e for e in events if isinstance(e, r.CardPresented)]), 1)
        feedback.assert_not_called()
        led.assert_not_called()
        beep.assert_not_called()

    def run_write(self, failure=None, beep_failure=None):
        order = []
        def write(number):
            order.append('verified_write')
            if failure:
                raise failure
            return number
        def beep():
            order.append('beep')
            if beep_failure:
                raise beep_failure
        with patch('sys.argv', ['write_example.py', '555']), patch('builtins.input', return_value=''), \
                patch.object(examples.write_example, 'write_card_number', side_effect=write), \
                patch.object(examples.write_example, 'beep', side_effect=beep), \
                patch.object(examples.write_example, 'set_led') as led, redirect_stdout(io.StringIO()) as output:
            status = examples.write_example.main()
        led.assert_not_called()  # запись по умолчанию использует только отдельный сигнал
        return status, order, output.getvalue()

    def test_write_success_beeps_after_verification(self):
        status, order, _ = self.run_write()
        self.assertEqual(status, 0)
        self.assertEqual(order, ['verified_write', 'beep'])

    def test_failed_verification_never_beeps(self):
        status, order, _ = self.run_write(failure=r.VerificationError('mismatch', stage='verify'))
        self.assertEqual(status, 1)
        self.assertEqual(order, ['verified_write'])

    def test_beep_failure_does_not_change_write_success(self):
        status, order, output = self.run_write(beep_failure=r.FeedbackError('unsupported', stage='feedback'))
        self.assertEqual(status, 0)
        self.assertEqual(order, ['verified_write', 'beep'])
        self.assertIn('Запись проверена, но', output)

    def test_watch_example_default_preserves_no_extra_beep(self):
        events = [r.CardState(False), r.CardState(True, True), r.CardState(True)]
        with patch('sys.argv', ['watch_example.py']), \
                patch.object(examples.watch_example, 'watch_cards', return_value=iter(events)) as watch, \
                patch.object(examples.watch_example, 'set_led') as led, \
                patch.object(examples.watch_example, 'beep') as beep, \
                patch.object(examples.watch_example.logging, 'basicConfig'), \
                patch.object(examples.watch_example.logging, 'shutdown'):
            examples.watch_example.main()
        watch.assert_called_once_with(report_state=True)
        self.assertEqual([c.args[0] for c in led.call_args_list], ['red', 'green', 'green'])
        beep.assert_not_called()


if __name__ == '__main__':
    unittest.main()
