from __future__ import annotations

import json
import tempfile
import unicodedata
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from bridge.archive import ArchiveBuilder, safe_archive_name, unique_name
from bridge.errors import BridgeError
from bridge.filenames import (
    PORTABLE_FILENAME_UTF8_BYTES,
    disambiguated_filename,
    filename_collision_key,
    safe_filename,
)
from bridge.models import MediaRecord, MessageRecord
from bridge.storage import FileRecordStore
from bridge.validation import bounded_text, normalize_search_text
from ops.file_send_policy import FileSendPolicyError, safe_filename as send_safe_filename


class Finalwave45FilenamePolicyTests(unittest.TestCase):
    def test_nfc_cyrillic_and_ordinary_emoji_are_preserved(self) -> None:
        raw = "Cafe\u0301 — файл 🦔.txt"
        result = safe_filename(raw)
        self.assertEqual(result, unicodedata.normalize("NFC", raw))
        self.assertIn("файл 🦔", result)

    def test_emoji_zwj_sequence_is_not_destroyed(self) -> None:
        raw = "family 👨‍👩‍👧‍👦.txt"
        self.assertEqual(safe_filename(raw), raw)

    def test_invalid_surrogate_is_neutralized_and_strict_utf8_encodable(self) -> None:
        result = safe_filename("bad\ud800name.txt")
        self.assertEqual(result, "bad_name.txt")
        self.assertEqual(result.encode("utf-8", "strict").decode("utf-8"), result)

    def test_c1_bidi_and_invisible_controls_are_neutralized(self) -> None:
        raw = "a\u0085b\u202ec\u200bd.txt"
        result = safe_filename(raw)
        self.assertNotIn("\u0085", result)
        self.assertNotIn("\u202e", result)
        self.assertNotIn("\u200b", result)
        self.assertEqual(result, "a_b_c_d.txt")

    def test_path_separator_confusables_are_neutralized(self) -> None:
        for separator in ("\u2044", "\u2215", "\u29f5", "\u29f8", "\ufe68", "\uff0f", "\uff3c"):
            with self.subTest(separator=hex(ord(separator))):
                result = safe_filename(f"safe{separator}evil.txt")
                self.assertEqual(result, "safe_evil.txt")
                self.assertNotIn(separator, result)

    def test_windows_reserved_compatibility_forms_are_neutralized(self) -> None:
        self.assertEqual(safe_filename("ＣＯＮ.txt"), "_ＣＯＮ.txt")
        self.assertEqual(safe_filename("COM¹.txt"), "_COM¹.txt")
        self.assertEqual(safe_filename("LPT¹"), "_LPT¹")
        self.assertEqual(safe_filename("NUL. "), "_NUL")

    def test_trailing_dot_and_space_are_removed(self) -> None:
        self.assertEqual(safe_filename("report.txt.   "), "report.txt")

    def test_utf8_byte_budget_preserves_suffix(self) -> None:
        result = safe_filename("🦔" * 100 + ".txt")
        self.assertLessEqual(len(result), 180)
        self.assertLessEqual(len(result.encode("utf-8")), PORTABLE_FILENAME_UTF8_BYTES)
        self.assertTrue(result.endswith(".txt"))

    def test_cyrillic_byte_budget_preserves_suffix(self) -> None:
        result = safe_filename("ф" * 180 + ".pdf")
        self.assertLessEqual(len(result.encode("utf-8")), PORTABLE_FILENAME_UTF8_BYTES)
        self.assertTrue(result.endswith(".pdf"))

    def test_collision_key_covers_case_nfc_nfd_and_compatibility_width(self) -> None:
        self.assertEqual(filename_collision_key("A.txt"), filename_collision_key("a.TXT"))
        self.assertEqual(filename_collision_key("é.txt"), filename_collision_key("e\u0301.txt"))
        self.assertEqual(filename_collision_key("Ａ.txt"), filename_collision_key("a.txt"))

    def test_collision_variant_keeps_marker_when_base_is_at_limit(self) -> None:
        base = "a" * 176 + ".txt"
        variant = disambiguated_filename(base, 2)
        self.assertNotEqual(filename_collision_key(base), filename_collision_key(variant))
        self.assertTrue(variant.endswith(" (2).txt"))
        self.assertLessEqual(len(variant), 180)
        self.assertLessEqual(len(variant.encode("utf-8")), PORTABLE_FILENAME_UTF8_BYTES)

    def test_unique_name_terminates_for_max_length_duplicates(self) -> None:
        base = "a" * 176 + ".txt"
        used: set[str] = set()
        names = [unique_name(base, used) for _ in range(200)]
        self.assertEqual(len(names), 200)
        self.assertEqual(len({filename_collision_key(name) for name in names}), 200)
        self.assertTrue(names[1].endswith(" (2).txt"))
        self.assertTrue(names[-1].endswith(" (200).txt"))
        self.assertTrue(all(len(name.encode("utf-8")) <= PORTABLE_FILENAME_UTF8_BYTES for name in names))

    def test_archive_name_uses_same_policy(self) -> None:
        self.assertEqual(safe_archive_name("ＣＯＮ.txt"), "_ＣＯＮ.txt")
        self.assertEqual(safe_archive_name("x\uff0fy.txt"), "x_y.txt")


class Finalwave45ArchiveIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.store = FileRecordStore(root / "state" / "files.sqlite3", root / "files")
        self.output = root / "tmp" / "archives"
        self.builder = ArchiveBuilder(files=self.store, output_dir=self.output)
        self._counter = 0

    def add(self, name: str, data: bytes = b"x"):
        self._counter += 1
        path = self.store.root / f"source-{self._counter}.bin"
        path.write_bytes(data)
        return self.store.add(path, name=name)

    def zip_names(self, record) -> list[str]:
        with zipfile.ZipFile(record.path) as zipped:
            self.assertIsNone(zipped.testzip())
            return zipped.namelist()

    def test_archive_handles_many_max_length_duplicate_names(self) -> None:
        base = "z" * 176 + ".txt"
        records = [self.add(base, str(index).encode("ascii")) for index in range(40)]
        archive = self.builder.build([record.file_ref for record in records])
        names = self.zip_names(archive)
        self.assertEqual(len(names), 40)
        self.assertEqual(len({filename_collision_key(name) for name in names}), 40)
        self.assertTrue(all(len(name.encode("utf-8")) <= PORTABLE_FILENAME_UTF8_BYTES for name in names))

    def test_archive_disambiguates_case_nfd_and_width_compatibility(self) -> None:
        records = [
            self.add("A.txt", b"1"),
            self.add("a.TXT", b"2"),
            self.add("Ａ.txt", b"3"),
            self.add("é.txt", b"4"),
            self.add("e\u0301.txt", b"5"),
        ]
        names = self.zip_names(self.builder.build([record.file_ref for record in records]))
        self.assertEqual(len(names), 5)
        self.assertEqual(len({filename_collision_key(name) for name in names}), 5)

    def test_archive_neutralizes_reserved_and_separator_lookalikes(self) -> None:
        records = [self.add("ＣＯＮ.txt"), self.add("parent\u2215child.txt")]
        names = self.zip_names(self.builder.build([record.file_ref for record in records]))
        self.assertIn("_ＣＯＮ.txt", names)
        self.assertIn("parent_child.txt", names)

    def test_duplicate_file_refs_still_produce_one_member(self) -> None:
        record = self.add("one.txt")
        names = self.zip_names(self.builder.build([record.file_ref, record.file_ref, record.file_ref]))
        self.assertEqual(names, ["one.txt"])

    def test_interrupted_archive_cleans_partial_output(self) -> None:
        record = self.add("one.txt")
        with patch.object(
            self.builder,
            "_write_record",
            side_effect=BridgeError("synthetic interruption", status=503, code="synthetic_interrupt"),
        ):
            with self.assertRaises(BridgeError):
                self.builder.build([record.file_ref])
        self.assertEqual(list(self.output.glob("archive_*.zip.part")), [])
        self.assertEqual(list(self.store.root.glob("*.zip")), [])

    def test_restart_reallocates_names_deterministically(self) -> None:
        base = "r" * 176 + ".txt"
        first_used: set[str] = set()
        second_used: set[str] = set()
        first = [unique_name(base, first_used) for _ in range(25)]
        second = [unique_name(base, second_used) for _ in range(25)]
        self.assertEqual(first, second)

    def test_parallel_archive_builds_do_not_share_collision_state(self) -> None:
        records = [self.add("same.txt", b"1"), self.add("SAME.TXT", b"2")]
        refs = [record.file_ref for record in records]

        def build_once() -> list[str]:
            builder = ArchiveBuilder(files=self.store, output_dir=self.output)
            return self.zip_names(builder.build(refs))

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: build_once(), range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(len({filename_collision_key(name) for name in results[0]}), 2)


class Finalwave45JsonMediaSearchTests(unittest.TestCase):
    def test_media_json_neutralizes_filename_but_message_text_is_unchanged(self) -> None:
        original_text = "Cafe\u0301 — Україна 👨‍👩‍👧‍👦"
        record = MessageRecord(
            id=7,
            chat_id="42",
            timestamp="2026-08-26T00:00:00Z",
            text=original_text,
            media=(MediaRecord(type="document", file_ref="tg_safe_ref", name="bad\ud800name.txt"),),
        )
        payload = record.to_dict(include_text=True)
        self.assertEqual(payload["text"], original_text)
        self.assertEqual(payload["media"][0]["name"], "bad_name.txt")
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8", "strict")
        self.assertIn(original_text.encode("utf-8"), encoded)

    def test_media_json_uses_windows_and_separator_neutralization(self) -> None:
        reserved = MediaRecord(type="document", file_ref="x", name="ＣＯＮ.txt").to_dict()
        deceptive = MediaRecord(type="document", file_ref="y", name="a\uff0fb.txt").to_dict()
        self.assertEqual(reserved["name"], "_ＣＯＮ.txt")
        self.assertEqual(deceptive["name"], "a_b.txt")

    def test_search_normalization_matches_canonical_and_compatibility_equivalents(self) -> None:
        self.assertEqual(normalize_search_text("CAFÉ"), normalize_search_text("cafe\u0301"))
        self.assertEqual(normalize_search_text("ＡＢＣ"), normalize_search_text("abc"))
        self.assertEqual(normalize_search_text("ПрИвІт"), normalize_search_text("привіт"))

    def test_invalid_surrogate_search_input_is_controlled_rejection(self) -> None:
        with self.assertRaises(BridgeError) as caught:
            bounded_text("bad\ud800query", field="text")
        self.assertEqual(caught.exception.code, "invalid_text")


class Finalwave45SendFileNameTests(unittest.TestCase):
    def test_external_send_name_uses_nfc(self) -> None:
        self.assertEqual(send_safe_filename("Cafe\u0301.pdf"), "Café.pdf")

    def test_external_send_name_neutralizes_windows_devices_and_lookalike_separator(self) -> None:
        self.assertEqual(send_safe_filename("ＣＯＮ.txt"), "_ＣＯＮ.txt")
        self.assertEqual(send_safe_filename("a\u2215b.txt"), "a_b.txt")

    def test_external_send_name_strips_trailing_dot(self) -> None:
        self.assertEqual(send_safe_filename("report.txt."), "report.txt")

    def test_external_send_name_rejects_real_path_and_surrogate(self) -> None:
        for raw in ("../secret.txt", "..\\secret.txt", "bad\ud800name.txt"):
            with self.subTest(raw=repr(raw)):
                with self.assertRaises(FileSendPolicyError):
                    send_safe_filename(raw)


if __name__ == "__main__":
    unittest.main()
