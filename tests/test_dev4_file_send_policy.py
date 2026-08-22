import unittest
from ops.file_send_policy import (
    FileSendPolicyError, HttpsFetchPolicy, bridge_audit_metadata, dedupe_bridge_files,
    external_audit_metadata, make_bridge_reference, make_external_reference,
    safe_filename, validate_https_url, validate_redirect_chain, validate_resolved_ips,
    validate_voice_note,
)
H='a'*64; H2='b'*64

class PolicyBoundsTests(unittest.TestCase):
    def test_default_policy_bounded(self):
        p=HttpsFetchPolicy(); self.assertLessEqual(p.max_bytes,512*1024*1024); self.assertLessEqual(p.timeout_seconds,60); self.assertLessEqual(p.max_redirects,5)
    def test_invalid_size_policy(self):
        with self.assertRaises(ValueError): HttpsFetchPolicy(max_bytes=0)
    def test_invalid_timeout_policy(self):
        with self.assertRaises(ValueError): HttpsFetchPolicy(timeout_seconds=0)
    def test_invalid_redirect_policy(self):
        with self.assertRaises(ValueError): HttpsFetchPolicy(max_redirects=6)

class UrlSafetyTests(unittest.TestCase):
    def test_https_domain_allowed(self): self.assertEqual(validate_https_url('https://example.com/a#frag'),'https://example.com/a')
    def test_https_query_preserved(self): self.assertEqual(validate_https_url('https://example.com/a?q=1'),'https://example.com/a?q=1')
    def test_http_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'https_required'): validate_https_url('http://example.com/a')
    def test_ftp_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'https_required'): validate_https_url('ftp://example.com/a')
    def test_userinfo_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'url_credentials_forbidden'): validate_https_url('https://user:pass@example.com/a')
    def test_non443_port_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'external_port_forbidden'): validate_https_url('https://example.com:8443/a')
    def test_443_port_allowed(self): self.assertIn('example.com:443',validate_https_url('https://example.com:443/a'))
    def test_localhost_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_https_url('https://localhost/a')
    def test_dot_local_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_https_url('https://printer.local/a')
    def test_loopback_ipv4_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_https_url('https://127.0.0.1/a')
    def test_private_ipv4_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_https_url('https://10.0.0.1/a')
    def test_linklocal_ipv4_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_https_url('https://169.254.1.1/a')
    def test_public_ipv4_allowed(self): self.assertEqual(validate_https_url('https://1.1.1.1/a'),'https://1.1.1.1/a')
    def test_control_char_rejected(self):
        with self.assertRaises(FileSendPolicyError): validate_https_url('https://example.com/\n')
    def test_resolved_public_ip_allowed(self): self.assertEqual(validate_resolved_ips(['1.1.1.1','8.8.8.8']),('1.1.1.1','8.8.8.8'))
    def test_resolved_private_ip_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_resolved_ips(['10.1.2.3'])
    def test_mixed_dns_answer_fails_closed(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_resolved_ips(['1.1.1.1','127.0.0.1'])
    def test_empty_dns_answer_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'resolution_required'): validate_resolved_ips([])
    def test_invalid_dns_answer_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'resolution_invalid'): validate_resolved_ips(['not-ip'])
    def test_redirect_each_hop_revalidated(self):
        with self.assertRaisesRegex(FileSendPolicyError,'private_network'): validate_redirect_chain(['https://example.com/a','https://127.0.0.1/x'],policy=HttpsFetchPolicy())
    def test_redirect_cap(self):
        with self.assertRaisesRegex(FileSendPolicyError,'too_many_redirects'): validate_redirect_chain(['https://a.example/x','https://b.example/x'],policy=HttpsFetchPolicy(max_redirects=0))
    def test_redirect_empty_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'redirect_chain_empty'): validate_redirect_chain([],policy=HttpsFetchPolicy())

class FilenameTests(unittest.TestCase):
    def test_filename_allowed(self): self.assertEqual(safe_filename('voice-note.ogg'),'voice-note.ogg')
    def test_filename_unicode_allowed(self): self.assertEqual(safe_filename('документ.pdf'),'документ.pdf')
    def test_filename_slash_rejected(self):
        with self.assertRaises(FileSendPolicyError): safe_filename('../secret.txt')
    def test_filename_backslash_rejected(self):
        with self.assertRaises(FileSendPolicyError): safe_filename('..\\secret.txt')
    def test_filename_dot_rejected(self):
        with self.assertRaises(FileSendPolicyError): safe_filename('..')
    def test_filename_empty_rejected(self):
        with self.assertRaises(FileSendPolicyError): safe_filename(' ')
    def test_filename_control_rejected(self):
        with self.assertRaises(FileSendPolicyError): safe_filename('a\n.txt')

class ReferenceTests(unittest.TestCase):
    def test_external_ref_hash_bound(self):
        r=make_external_reference(url='https://example.com/a',name='a.pdf',declared_size=10,declared_mime='application/pdf'); self.assertEqual(len(r.url_sha256),64); self.assertEqual(r.safe_name,'a.pdf')
    def test_external_ref_size_cap(self):
        with self.assertRaisesRegex(FileSendPolicyError,'file_too_large'): make_external_reference(url='https://example.com/a',name='a',declared_size=101*1024*1024)
    def test_external_ref_negative_size(self):
        with self.assertRaisesRegex(FileSendPolicyError,'invalid_declared_size'): make_external_reference(url='https://example.com/a',name='a',declared_size=-1)
    def test_external_ref_invalid_mime(self):
        with self.assertRaisesRegex(FileSendPolicyError,'invalid_mime_type'): make_external_reference(url='https://example.com/a',name='a',declared_mime='bad')
    def test_bridge_ref_allowed(self): self.assertEqual(make_bridge_reference(file_id='opaque-1',sha256=H,size=10).file_id,'opaque-1')
    def test_bridge_ref_path_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'invalid_bridge_file_id'): make_bridge_reference(file_id='../x',sha256=H,size=10)
    def test_bridge_ref_bad_hash_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'invalid_file_hash'): make_bridge_reference(file_id='x',sha256='bad',size=10)
    def test_bridge_ref_zero_size_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'invalid_file_size'): make_bridge_reference(file_id='x',sha256=H,size=0)
    def test_bridge_ref_large_size_rejected(self):
        with self.assertRaisesRegex(FileSendPolicyError,'invalid_file_size'): make_bridge_reference(file_id='x',sha256=H,size=101*1024*1024)
    def test_bridge_ref_mime_lowercase(self): self.assertEqual(make_bridge_reference(file_id='x',sha256=H,size=1,mime_type='Audio/OGG').mime_type,'audio/ogg')
    def test_dedupe_same_ref(self):
        r=make_bridge_reference(file_id='x',sha256=H,size=1); self.assertEqual(len(dedupe_bridge_files([r,r])),1)
    def test_dedupe_count_cap(self):
        fs=[make_bridge_reference(file_id=f'x{i}',sha256=('%064x'%i)[-64:],size=1) for i in range(1,12)]
        with self.assertRaisesRegex(FileSendPolicyError,'file_count_exceeded'): dedupe_bridge_files(fs)
    def test_dedupe_total_cap(self):
        a=make_bridge_reference(file_id='a',sha256=H,size=100); b=make_bridge_reference(file_id='b',sha256=H2,size=100)
        with self.assertRaisesRegex(FileSendPolicyError,'files_total_too_large'): dedupe_bridge_files([a,b],max_total_bytes=150)
    def test_voice_note_ogg_allowed(self): validate_voice_note([make_bridge_reference(file_id='a',sha256=H,size=1,mime_type='audio/ogg')],voice_note=True)
    def test_voice_note_opus_allowed(self): validate_voice_note([make_bridge_reference(file_id='a',sha256=H,size=1,mime_type='audio/opus')],voice_note=True)
    def test_voice_note_multiple_rejected(self):
        a=make_bridge_reference(file_id='a',sha256=H,size=1,mime_type='audio/ogg'); b=make_bridge_reference(file_id='b',sha256=H2,size=1,mime_type='audio/ogg')
        with self.assertRaisesRegex(FileSendPolicyError,'single_file'): validate_voice_note([a,b],voice_note=True)
    def test_voice_note_wrong_mime_rejected(self):
        a=make_bridge_reference(file_id='a',sha256=H,size=1,mime_type='application/pdf')
        with self.assertRaisesRegex(FileSendPolicyError,'media_unsupported'): validate_voice_note([a],voice_note=True)
    def test_non_voice_skips_mime_rule(self): validate_voice_note([make_bridge_reference(file_id='a',sha256=H,size=1,mime_type='application/pdf')],voice_note=False)
    def test_external_audit_drops_url_host_filename(self):
        r=make_external_reference(url='https://private-label.example/a',name='Private Person.pdf',declared_size=10); blob=str(external_audit_metadata(r)); self.assertNotIn('private-label',blob); self.assertNotIn('Private Person',blob); self.assertIn(r.url_sha256,blob)
    def test_bridge_audit_drops_file_id(self):
        r=make_bridge_reference(file_id='private-person-file',sha256=H,size=10); blob=str(bridge_audit_metadata(r)); self.assertNotIn('private-person-file',blob); self.assertIn(H,blob)

if __name__=='__main__': unittest.main()
