import json
import unittest

from ops.openapi_registry import build_action_openapi
from ops.setup_surface_security import SetupSurfaceError, validate_action_schema_excludes_setup


class Finalwave25ActionSetupExclusionTests(unittest.TestCase):
    def test_serialized_chatgpt_action_contains_no_setup_login_2fa_or_session_surface(self):
        schema = build_action_openapi("https://tg-api.rukadopomogy.org.ua")
        validate_action_schema_excludes_setup(schema)
        serialized = json.dumps(schema, ensure_ascii=False, sort_keys=True).casefold()
        for forbidden in (
            "setup",
            "bootstrap",
            "login",
            "login_code",
            "2fa",
            "session",
            "session_string",
            "api_hash",
            "telegram_2fa_password",
            "setup_route",
            "setup_key",
        ):
            self.assertNotIn(forbidden, serialized, forbidden)

    def test_validator_fails_closed_if_a_future_action_adds_private_onboarding_field(self):
        schema = build_action_openapi("https://tg-api.rukadopomogy.org.ua")
        first_path = next(iter(schema["paths"].values()))
        first_operation = first_path["post"]
        first_operation["requestBody"] = {
            "required": True,
            "content": {
                "application/json": {
                    "schema": {
                        "type": "object",
                        "properties": {"session_string": {"type": "string"}},
                    }
                }
            },
        }
        with self.assertRaises(SetupSurfaceError):
            validate_action_schema_excludes_setup(schema)


if __name__ == "__main__":
    unittest.main()
