import unittest
from types import SimpleNamespace
from unittest.mock import patch
import cyb_feedback_diagnostics as d
import wcopy_reader as r


class ProbeTests(unittest.TestCase):
    def session(self, written=65, replies=None):
        queue=list(replies or [])
        self.sent=[]
        def write(report):self.sent.append(report);return written
        device=SimpleNamespace(write=write,read=lambda *args:queue.pop(0) if queue else [])
        return SimpleNamespace(device=device,_drain=lambda stage:None)

    def test_original_packets_without_response_are_not_retried(self):
        for payload,expected in [
            (d.ORIGINAL[0][2],'00550055000401010200fd02'),
            (d.ORIGINAL[1][2],'00550055000400050100fb04'),
        ]:
            result=d.probe(self.session(),payload)
            self.assertEqual(self.sent,[bytes.fromhex(expected)])
            self.assertEqual(result['replies'],[])

    def test_captures_raw_response(self):
        result=d.probe(self.session(replies=[b'abc']),d.ORIGINAL[0][2])
        self.assertEqual(result['replies'],['61 62 63'])

    def test_invalid_payload_sends_nothing(self):
        s=self.session()
        with self.assertRaises(ValueError):d.probe(s,b'\xff'*4)
        self.assertEqual(self.sent,[])

    def test_short_write_not_retried(self):
        with self.assertRaises(r.USBError):d.probe(self.session(written=1),d.ORIGINAL[0][2])
        self.assertEqual(len(self.sent),1)


if __name__=='__main__':unittest.main()
