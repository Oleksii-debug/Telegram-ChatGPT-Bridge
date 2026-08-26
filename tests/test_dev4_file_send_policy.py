import unittest
from ops.file_send_policy import (
    ExternalFileReference,
    FileSendPolicyError,
    HttpsFetchPolicy,
    bridge_audit_metadata,
    dedupe_bridge_files,
    external_audit_metadata,
    make_bridge_reference,
    make_external_reference,
    safe_filename,
    validate_https_url,
    validate_redirect_chain,
    validate_resolved_ips,
    validate_voice_note,
)
H='a'*64
H2='b'*64


class PolicyBoundsTests(unittest.TestCase):
    def test_default_policy_is_no_redirect(self):
        p=HttpsFetchPolicy()
        self.assertLessEqual(p.max_bytes,512*1024*1024)
        self.assertLessEqual(p.timeout_seconds,60)
        self.assertEqual(0,p.max_redirects)

    def test_invalid_size_policy(self):
        with self.assertRaises(ValueError): HttpsFetchPolicy(max_bytes=0)

    def test_invalid_timeout_policy(self):
        with self.assertRaises(ValueError): HttpsFetchPolicy(timeout_seconds=0)

    def test_any_redirect_policy_rejected(self):
        for count in (-1,1,3,6):
            with self.subTest(count=count), self.assertRaises(ValueError):
                HttpsFetchPolicy(max_redirects=count)


class ExternalUrlDisabledTests(unittest.TestCase):
    def assert_disabled(self, url):
        with self.assertRaisesRegex(FileSendPolicyError,'external_url_sources_disabled') as ctx:
            validate_https_url(url)
        self.assertEqual(403, ctx.exception.status)

    def test_all_external_url_shapes_fail_closed(self):
        urls = (
            'https://example.com/a',
            'https://EXAMPLE.com/a',
            'https://example.com./a',
            'https://xn--e1afmkfd.xn--p1ai/a',
            'https://1.1.1.1/a',
            'https://127.0.0.1/a',
            'https://10.0.0.1/a',
            'https://169.254.169.254/latest/meta-data/',
            'https://[::1]/a',
            'https://user:pass@example.com/a',
            'https://example.com:443/a',
            'https://example.com:8443/a',
            'https://example.com/a?q=1',
            'https://example.com/a#frag',
            'http://example.com/a',
            'file:///etc/passwd',
        )
        for url in urls:
            with self.subTest(url=url):
                self.assert_disabled(url)

    def test_resolve_then_connect_helper_is_not_a_security_boundary(self):
        for values in (['1.1.1.1'], ['8.8.8.8','1.1.1.1'], ['127.0.0.1'], []):
            with self.subTest(values=values), self.assertRaisesRegex(FileSendPolicyError,'external_url_sources_disabled'):
                validate_resolved_ips(values)

    def test_redirect_chain_disabled_even_same_origin(self):
        with self.assertRaisesRegex(FileSendPolicyError,'external_url_sources_disabled'):
            validate_redirect_chain(['https://example.com/a'],policy=HttpsFetchPolicy())
        with self.assertRaisesRegex(FileSendPolicyError,'external_url_sources_disabled'):
            validate_redirect_chain(['https://example.com/a','https://example.com/b'],policy=HttpsFetchPolicy())

    def test_external_reference_creation_disabled(self):
        with self.assertRaisesRegex(FileSendPolicyError,'external_url_sources_disabled'):
            make_external_reference(url='https://example.com/a',name='a.pdf',declared_size=10,declared_mime='application/pdf')

    def test_legacy_external_audit_object_cannot_leak_url_or_filename(self):
        ref = ExternalFileReference(
            url='https://private-label.example/a',
            url_sha256='c'*64,
            safe_name='Private Person.pdf',
            declared_size=10,
            declared_mime='application/pdf',
        )
        blob=str(external_audit_metadata(ref))
        self.assertNotIn('private-label',blob)
        self.assertNotIn('Private Person',blob)
        self.assertIn('HTTPS_DISABLED',blob)


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
    def test_bridge_audit_drops_file_id(self):
        r=make_bridge_reference(file_id='private-person-file',sha256=H,size=10); blob=str(bridge_audit_metadata(r)); self.assertNotIn('private-person-file',blob); self.assertIn(H,blob)


if __name__=='__main__': unittest.main()