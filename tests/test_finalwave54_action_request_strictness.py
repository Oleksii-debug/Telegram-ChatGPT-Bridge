from __future__ import annotations

import unittest

from ops.dev06_runtime_conformance import validate_json_instance
import tests.test_finalwave54_action_wsgi_e2e as e2e


class ActionRequestStrictnessTests(unittest.TestCase):
    """Adversarial request cases where canonical runtime previously coerced schema-invalid JSON."""

    def setUp(self) -> None:
        # Reuse the real in-memory UnifiedBridgeApplication fixture without
        # inheriting its TestCase (which would duplicate the 17-op matrix).
        self.harness = e2e.ActionMockE2ETests(
            "test_private_setup_is_absent_from_action_schema_and_hidden_at_wsgi"
        )
        self.harness.setUp()

    def tearDown(self) -> None:
        self.harness.doCleanups()

    def _assert_schema_invalid_runtime_400(self, operation_id: str, body: dict[str, object]) -> None:
        schema_errors = validate_json_instance(
            body,
            self.harness._request_schema(operation_id),
        )
        self.assertTrue(schema_errors, (operation_id, body))
        before = len(self.harness.client.external_writes)
        result = self.harness._invoke(operation_id, body)
        self.assertEqual(result["status"], 400, (operation_id, result))
        self.harness._assert_response_matches_schema(operation_id, result)
        self.assertEqual(len(self.harness.client.external_writes), before)

    def test_write_previews_reject_schema_invalid_type_coercions(self) -> None:
        digest = "a" * 64
        file_ref = "abcdefghijklmnop"
        cases: tuple[tuple[str, dict[str, object]], ...] = (
            (
                "previewTelegramSend",
                {"chat": 123, "text": "synthetic"},
            ),
            (
                "previewTelegramReply",
                {
                    "chat": "@target_user",
                    "reply_to_message_id": "10",
                    "text": "synthetic",
                },
            ),
            (
                "previewTelegramForward",
                {
                    "from_chat": "@source_user",
                    "to_chat": "@target_user",
                    "message_ids": ["20"],
                },
            ),
            (
                "previewTelegramFiles",
                {
                    "chat": "@target_user",
                    "files": [{"file_ref": file_ref, "sha256": digest, "size": "3"}],
                },
            ),
            (
                "previewTelegramFiles",
                {
                    "chat": "@target_user",
                    "files": [{"file_ref": file_ref, "sha256": 123, "size": 3}],
                },
            ),
            (
                "previewTelegramFiles",
                {
                    "chat": "@target_user",
                    "files": [{"file_ref": file_ref, "sha256": digest, "size": 3}],
                    "voice_note": "false",
                },
            ),
            (
                "previewTelegramFiles",
                {
                    "chat": "@target_user",
                    "files": [{"file_ref": file_ref, "sha256": digest, "size": 3}],
                    "reply_to_message_id": "10",
                },
            ),
        )
        for operation_id, body in cases:
            with self.subTest(operation_id=operation_id, body=body):
                self._assert_schema_invalid_runtime_400(operation_id, body)

    def test_valid_write_types_remain_accepted_with_zero_preview_effect(self) -> None:
        digest = "a" * 64
        valid = {
            "chat": "@target_user",
            "files": [{"file_ref": "abcdefghijklmnop", "sha256": digest, "size": 3}],
            "caption": "synthetic",
            "reply_to_message_id": 10,
            "voice_note": True,
        }
        self.assertEqual(
            validate_json_instance(valid, self.harness._request_schema("previewTelegramFiles")),
            [],
        )
        before = len(self.harness.client.external_writes)
        result = self.harness._invoke("previewTelegramFiles", valid)
        self.assertEqual(result["status"], 200, result)
        self.harness._assert_response_matches_schema("previewTelegramFiles", result)
        self.assertEqual(len(self.harness.client.external_writes), before)

    def test_archive_duplicate_refs_are_rejected_like_uniqueitems_schema(self) -> None:
        single, _ = self.harness._seed_storage()
        body = {"file_refs": [single["file_ref"], single["file_ref"]]}
        schema_errors = validate_json_instance(
            body,
            self.harness._request_schema("createTelegramArchive"),
        )
        self.assertIn("ARRAY_NOT_UNIQUE:$.file_refs", schema_errors)
        before = len(self.harness.client.external_writes)
        result = self.harness._invoke("createTelegramArchive", body)
        self.assertEqual(result["status"], 400, result)
        self.assertEqual(result["json"]["error"]["code"], "invalid_list")
        self.harness._assert_response_matches_schema("createTelegramArchive", result)
        self.assertEqual(len(self.harness.client.external_writes), before)


if __name__ == "__main__":
    unittest.main()
