import copy
import json
import unittest

from ops.dev06_api_contracts import (
    AccessPolicy,
    ApiContractError,
    ApiExposure,
    ApiOperationClass,
    CANONICAL_ROUTES,
    build_chatgpt_action_openapi,
    canonical_action,
    canonical_route,
    canonical_runtime_operation,
    serialized_chatgpt_action_openapi,
    validate_canonical_registry,
    validate_chatgpt_action_schema,
    validate_runtime_parity,
)


BASE_URL = "https://tg-api.rukadopomogy.org.ua"


def operation(schema, operation_id):
    for path, item in schema["paths"].items():
        for method, candidate in item.items():
            if isinstance(candidate, dict) and candidate.get("operationId") == operation_id:
                return path, method, candidate
    raise AssertionError(operation_id)


class CanonicalRegistryTests(unittest.TestCase):
    def test_exact_route_and_action_counts(self):
        self.assertEqual(len(CANONICAL_ROUTES), 19)
        self.assertEqual(sum(r.exposure is ApiExposure.ACTION for r in CANONICAL_ROUTES), 17)
        self.assertEqual(validate_canonical_registry(), [])

    def test_only_health_is_public(self):
        public = [r for r in CANONICAL_ROUTES if r.access is AccessPolicy.PUBLIC]
        self.assertEqual([(r.method, r.path, r.runtime_operation_id) for r in public], [("GET", "/health", "health.get")])

    def test_raw_private_file_route_is_runtime_only(self):
        route = canonical_route("GET", "/api/v1/files/{file_ref}")
        self.assertIs(route.exposure, ApiExposure.RUNTIME_ONLY)
        self.assertIs(route.access, AccessPolicy.BEARER_OR_SIGNED)
        self.assertIs(route.operation_class, ApiOperationClass.FILE_CONTENT)
        self.assertIsNone(route.action_operation_id)

    def test_all_action_routes_are_bearer_post(self):
        for route in CANONICAL_ROUTES:
            if route.exposure is ApiExposure.ACTION:
                self.assertEqual(route.method, "POST")
                self.assertIs(route.access, AccessPolicy.BEARER)

    def test_unknown_route_fails_closed(self):
        with self.assertRaisesRegex(ApiContractError, "UNKNOWN_ROUTE_FAIL_CLOSED"):
            canonical_route("POST", "/api/v1/setup")

    def test_unknown_action_fails_closed(self):
        with self.assertRaisesRegex(ApiContractError, "UNKNOWN_ACTION_OPERATION_FAIL_CLOSED"):
            canonical_action("privateSetup")

    def test_unknown_runtime_operation_fails_closed(self):
        with self.assertRaisesRegex(ApiContractError, "UNKNOWN_RUNTIME_OPERATION_FAIL_CLOSED"):
            canonical_runtime_operation("setup.begin")

    def test_write_pairs_are_reciprocal_and_only_commits_consequential(self):
        writes = [r for r in CANONICAL_ROUTES if r.write_action]
        self.assertEqual(len(writes), 8)
        for route in writes:
            pair = canonical_action(route.pair_operation_id)
            self.assertEqual(pair.pair_operation_id, route.action_operation_id)
            self.assertEqual(pair.write_action, route.write_action)
            self.assertNotEqual(pair.operation_class, route.operation_class)
            self.assertEqual(route.consequential, route.operation_class is ApiOperationClass.WRITE_COMMIT)


class RuntimeParityTests(unittest.TestCase):
    def test_runtime_and_legacy_action_registries_match(self):
        self.assertEqual(validate_runtime_parity(), [])


class ActionSchemaPositiveTests(unittest.TestCase):
    def setUp(self):
        self.schema = build_chatgpt_action_openapi(BASE_URL)

    def test_schema_is_clean(self):
        self.assertEqual(validate_chatgpt_action_schema(self.schema), [])

    def test_exact_17_action_operations(self):
        ids = []
        for item in self.schema["paths"].values():
            for op in item.values():
                if isinstance(op, dict) and "operationId" in op:
                    ids.append(op["operationId"])
        self.assertEqual(len(ids), 17)
        self.assertEqual(len(set(ids)), 17)

    def test_health_and_raw_file_are_not_action_operations(self):
        self.assertNotIn("/health", self.schema["paths"])
        self.assertNotIn("/api/v1/files/{file_ref}", self.schema["paths"])

    def test_root_and_every_operation_require_bearer(self):
        self.assertEqual(self.schema["security"], [{"BearerAuth": []}])
        for item in self.schema["paths"].values():
            for op in item.values():
                if isinstance(op, dict) and "operationId" in op:
                    self.assertEqual(op["security"], [{"BearerAuth": []}])

    def test_preview_is_nonconsequential_commit_is_consequential(self):
        _, _, preview = operation(self.schema, "previewTelegramReply")
        _, _, commit = operation(self.schema, "commitTelegramReply")
        self.assertIs(preview["x-openai-isConsequential"], False)
        self.assertIs(commit["x-openai-isConsequential"], True)

    def test_commit_requires_all_three_explicit_gates(self):
        _, _, commit = operation(self.schema, "commitTelegramSend")
        body = commit["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(set(body["required"]), {"preview_token", "idempotency_key", "explicit_user_command"})
        self.assertIs(body["properties"]["explicit_user_command"]["const"], True)

    def test_success_envelope_matches_runtime(self):
        _, _, op = operation(self.schema, "listTelegramDialogs")
        success = op["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(set(success["required"]), {"ok", "request_id", "data"})
        self.assertIs(success["properties"]["ok"]["const"], True)
        data = success["properties"]["data"]
        self.assertEqual(set(data["required"]), {"items", "next_cursor", "scanned"})
        self.assertIs(data["additionalProperties"], False)

    def test_error_envelope_matches_runtime(self):
        _, _, op = operation(self.schema, "searchTelegramMessages")
        error = op["responses"]["400"]["content"]["application/json"]["schema"]
        self.assertEqual(set(error["required"]), {"ok", "request_id", "error"})
        self.assertIs(error["properties"]["ok"]["const"], False)
        detail = error["properties"]["error"]
        self.assertTrue({"code", "message"} <= set(detail["required"]))
        self.assertIs(detail["additionalProperties"], False)

    def test_retry_after_header_is_modeled_for_429(self):
        _, _, op = operation(self.schema, "downloadTelegramMediaBulk")
        retry = op["responses"]["429"]["headers"]["Retry-After"]
        self.assertIs(retry["required"], True)
        self.assertEqual(retry["schema"]["type"], "integer")
        self.assertEqual(retry["schema"]["minimum"], 1)
        self.assertEqual(retry["schema"]["maximum"], 600)

    def test_all_runtime_error_statuses_are_declared(self):
        expected = {"200", "400", "404", "409", "413", "415", "429", "500", "502", "503", "504"}
        for item in self.schema["paths"].values():
            for op in item.values():
                if isinstance(op, dict) and "operationId" in op:
                    self.assertEqual(set(op["responses"]), expected)

    def test_request_objects_are_fail_closed(self):
        for item in self.schema["paths"].values():
            for op in item.values():
                if not isinstance(op, dict) or "operationId" not in op:
                    continue
                body = op["requestBody"]["content"]["application/json"]["schema"]
                self.assertEqual(body["type"], "object")
                self.assertIs(body["additionalProperties"], False)

    def test_file_contract_bounds_are_preserved(self):
        _, _, bulk = operation(self.schema, "downloadTelegramMediaBulk")
        request = bulk["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(request["properties"]["items"]["maxItems"], 100)
        _, _, send_files = operation(self.schema, "previewTelegramFiles")
        request = send_files["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(request["properties"]["files"]["maxItems"], 10)
        file_item = request["properties"]["files"]["items"]
        self.assertEqual(file_item["properties"]["file_ref"]["maxLength"], 128)
        self.assertEqual(file_item["properties"]["size"]["maximum"], 104857600)

    def test_write_preview_response_contains_exact_binding_metadata(self):
        _, _, op = operation(self.schema, "previewTelegramForward")
        data = op["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["data"]
        self.assertTrue(
            {"preview_token", "preview_id", "action", "request_fingerprint", "expires_at", "preview"}
            <= set(data["required"])
        )

    def test_write_commit_response_exposes_replay_state_without_private_payload(self):
        _, _, op = operation(self.schema, "commitTelegramForward")
        data = op["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["data"]
        self.assertEqual(set(data["required"]), {"state", "idempotent_replay", "request_fingerprint", "result"})
        self.assertNotIn("preview_token", data["properties"])
        self.assertNotIn("idempotency_key", data["properties"])

    def test_serialization_is_deterministic_and_valid(self):
        first = serialized_chatgpt_action_openapi(BASE_URL)
        second = serialized_chatgpt_action_openapi(BASE_URL)
        self.assertEqual(first, second)
        parsed = json.loads(first)
        self.assertEqual(validate_chatgpt_action_schema(parsed), [])


class ActionSchemaAdversarialTests(unittest.TestCase):
    def setUp(self):
        self.schema = build_chatgpt_action_openapi(BASE_URL)

    def errors(self, schema):
        return "\n".join(validate_chatgpt_action_schema(schema))

    def test_extra_unknown_operation_fails_closed(self):
        bad = copy.deepcopy(self.schema)
        bad["paths"]["/api/v1/unknown"] = {"post": copy.deepcopy(operation(bad, "listTelegramDialogs")[2])}
        self.assertIn("UNKNOWN_ACTION_ROUTE", self.errors(bad))

    def test_missing_operation_fails_closed(self):
        bad = copy.deepcopy(self.schema)
        del bad["paths"]["/api/v1/dialogs/list"]
        self.assertIn("ACTION_ROUTE_MISSING", self.errors(bad))

    def test_operation_id_drift_detected(self):
        bad = copy.deepcopy(self.schema)
        operation(bad, "listTelegramDialogs")[2]["operationId"] = "differentId"
        self.assertIn("OPERATION_ID_DRIFT", self.errors(bad))

    def test_operation_bearer_removal_detected(self):
        bad = copy.deepcopy(self.schema)
        operation(bad, "readTelegramHistory")[2]["security"] = []
        self.assertIn("OPERATION_BEARER_REQUIRED", self.errors(bad))

    def test_root_bearer_removal_detected(self):
        bad = copy.deepcopy(self.schema)
        bad["security"] = []
        self.assertIn("ROOT_BEARER_SECURITY_REQUIRED", self.errors(bad))

    def test_preview_consequential_flip_detected(self):
        bad = copy.deepcopy(self.schema)
        operation(bad, "previewTelegramSend")[2]["x-openai-isConsequential"] = True
        self.assertIn("CONSEQUENTIAL_SEMANTICS_DRIFT", self.errors(bad))

    def test_commit_consequential_flip_detected(self):
        bad = copy.deepcopy(self.schema)
        operation(bad, "commitTelegramSend")[2]["x-openai-isConsequential"] = False
        self.assertIn("CONSEQUENTIAL_SEMANTICS_DRIFT", self.errors(bad))

    def test_request_additional_properties_open_detected(self):
        bad = copy.deepcopy(self.schema)
        body = operation(bad, "searchTelegramMessages")[2]["requestBody"]["content"]["application/json"]["schema"]
        body["additionalProperties"] = True
        self.assertIn("REQUEST_SCHEMA_NOT_FAIL_CLOSED", self.errors(bad))

    def test_commit_gate_removal_detected(self):
        bad = copy.deepcopy(self.schema)
        body = operation(bad, "commitTelegramReply")[2]["requestBody"]["content"]["application/json"]["schema"]
        body["required"].remove("idempotency_key")
        self.assertIn("COMMIT_GATES_MISSING", self.errors(bad))

    def test_explicit_commit_const_false_detected(self):
        bad = copy.deepcopy(self.schema)
        body = operation(bad, "commitTelegramReply")[2]["requestBody"]["content"]["application/json"]["schema"]
        body["properties"]["explicit_user_command"]["const"] = False
        self.assertIn("EXPLICIT_COMMIT_NOT_CONST_TRUE", self.errors(bad))

    def test_retry_after_header_removal_detected(self):
        bad = copy.deepcopy(self.schema)
        del operation(bad, "searchTelegramMessages")[2]["responses"]["429"]["headers"]["Retry-After"]
        self.assertIn("RETRY_AFTER_HEADER_MISSING", self.errors(bad))

    def test_retry_after_invalid_bound_detected(self):
        bad = copy.deepcopy(self.schema)
        retry = operation(bad, "searchTelegramMessages")[2]["responses"]["429"]["headers"]["Retry-After"]
        retry["schema"]["minimum"] = 0
        self.assertIn("RETRY_AFTER_HEADER_INVALID", self.errors(bad))

    def test_response_status_removal_detected(self):
        bad = copy.deepcopy(self.schema)
        del operation(bad, "listTelegramDialogs")[2]["responses"]["504"]
        self.assertIn("RESPONSE_STATUS_SET_DRIFT", self.errors(bad))

    def test_success_envelope_drift_detected(self):
        bad = copy.deepcopy(self.schema)
        success = operation(bad, "listTelegramDialogs")[2]["responses"]["200"]["content"]["application/json"]["schema"]
        success["required"].remove("data")
        self.assertIn("SUCCESS_ENVELOPE_DRIFT", self.errors(bad))

    def test_error_envelope_drift_detected(self):
        bad = copy.deepcopy(self.schema)
        error = operation(bad, "listTelegramDialogs")[2]["responses"]["400"]["content"]["application/json"]["schema"]
        error["required"].remove("error")
        self.assertIn("ERROR_ENVELOPE_DRIFT", self.errors(bad))

    def test_structured_error_detail_drift_detected(self):
        bad = copy.deepcopy(self.schema)
        detail = operation(bad, "listTelegramDialogs")[2]["responses"]["400"]["content"]["application/json"]["schema"]["properties"]["error"]
        detail["required"].remove("message")
        self.assertIn("STRUCTURED_ERROR_DRIFT", self.errors(bad))

    def test_private_setup_path_rejected(self):
        bad = copy.deepcopy(self.schema)
        bad["paths"]["/api/v1/setup/login"] = {"post": copy.deepcopy(operation(bad, "listTelegramDialogs")[2])}
        errors = self.errors(bad)
        self.assertIn("PRIVATE_ACTION_SURFACE", errors)
        self.assertIn("UNKNOWN_ACTION_ROUTE", errors)

    def test_secret_field_name_rejected_anywhere(self):
        bad = copy.deepcopy(self.schema)
        body = operation(bad, "listTelegramDialogs")[2]["requestBody"]["content"]["application/json"]["schema"]
        body["properties"]["session_string"] = {"type": "string"}
        self.assertIn("SECRET_FIELD_EXPOSED", self.errors(bad))

    def test_private_server_path_rejected(self):
        bad = copy.deepcopy(self.schema)
        bad["servers"] = [{"url": BASE_URL + "/setup/private"}]
        self.assertIn("SERVER_URL_INVALID", self.errors(bad))

    def test_duplicate_operation_id_detected(self):
        bad = copy.deepcopy(self.schema)
        _, _, first = operation(bad, "listTelegramDialogs")
        _, _, second = operation(bad, "readTelegramHistory")
        second["operationId"] = first["operationId"]
        errors = self.errors(bad)
        self.assertIn("OPERATION_ID_DRIFT", errors)
        self.assertIn("DUPLICATE_ACTION_OPERATION_ID", errors)


if __name__ == "__main__":
    unittest.main()
