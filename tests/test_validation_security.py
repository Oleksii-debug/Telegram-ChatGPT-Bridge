from __future__ import annotations
import unittest
from datetime import datetime,timezone
from bridge.errors import BridgeError, HiddenNotFound
from bridge.models import decode_cursor, encode_cursor
from bridge.security import BearerGuard, FileSigner, RateLimitDecision
from bridge.validation import date_range, normalize_search_text, validate_file_ref

class ValidationSecurityTests(unittest.TestCase):
    def test_cursor_roundtrip(self): self.assertEqual(decode_cursor(encode_cursor({'v':1,'scope':'x','offset':2}))['offset'],2)
    def test_cursor_bad_chars(self):
        with self.assertRaises(BridgeError): decode_cursor('../x')
    def test_cursor_oversize(self):
        with self.assertRaises(BridgeError): decode_cursor('A'*1025)
    def test_unicode_casefold(self): self.assertEqual(normalize_search_text('ЇЖАК'),normalize_search_text('їжак'))
    def test_date_timezone_conversion(self): self.assertEqual(date_range('2026-01-01T02:00:00+02:00',None).start,datetime(2026,1,1,tzinfo=timezone.utc))
    def test_file_ref_rejects_path(self):
        with self.assertRaises(BridgeError): validate_file_ref('../etc/passwd')
    def test_bearer_constant_shape_missing(self):
        g=BearerGuard('x'*24)
        with self.assertRaises(HiddenNotFound): g.require({})
    def test_bearer_exact(self): BearerGuard('x'*24).require({'HTTP_AUTHORIZATION':'Bearer '+'x'*24})
    def test_signer_valid(self):
        s=FileSigner('x'*24,clock=lambda:100); url,exp=s.issue(base_url='https://e.invalid',route_prefix='/f',file_ref='A'*32,ttl_seconds=10); sig=url.split('sig=')[1]; self.assertTrue(s.verify('A'*32,str(exp),sig))
    def test_signer_expired(self):
        s=FileSigner('x'*24,clock=lambda:100); sig=s.signature('A'*32,99); self.assertFalse(s.verify('A'*32,'99',sig))
    def test_signer_file_swap_fails(self):
        s=FileSigner('x'*24,clock=lambda:100); sig=s.signature('A'*32,200); self.assertFalse(s.verify('B'*32,'200',sig))
    def test_signer_tamper_fails(self): self.assertFalse(FileSigner('x'*24,clock=lambda:100).verify('A'*32,'200','0'*64))
    def test_rate_limiter_interface_decision_shape(self):
        d=RateLimitDecision(True,remaining=3); self.assertTrue(d.allowed); self.assertEqual(d.remaining,3)
    def test_rate_limiter_retry_shape(self):
        d=RateLimitDecision(False,retry_after_seconds=9,remaining=0); self.assertFalse(d.allowed); self.assertEqual(d.retry_after_seconds,9)


if __name__=='__main__': unittest.main()
