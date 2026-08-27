from __future__ import annotations

import asyncio
import unittest

from bridge.errors import BridgeError
from bridge.final5_search_failclosed import FailClosedTelethonReadBackend


class _RaisesInsideCall:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def iter_messages(
        self,
        entity: object,
        *,
        limit: int,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[object]:
        self.calls.append({"entity": entity, "limit": limit, "search": search, "offset_id": offset_id})
        raise TypeError("simulated TypeError inside client call")


class _NoSearchSupport:
    def __init__(self) -> None:
        self.calls = 0

    def iter_messages(self, entity: object, *, limit: int) -> list[object]:
        self.calls += 1
        return []


class _NoOffsetSupport:
    def __init__(self) -> None:
        self.calls = 0

    def iter_messages(self, entity: object, *, limit: int, search: str = "") -> list[object]:
        self.calls += 1
        return []


class _Supported:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def iter_messages(
        self,
        entity: object,
        *,
        limit: int,
        search: str = "",
        offset_id: int | None = None,
    ) -> list[object]:
        self.calls.append({"entity": entity, "limit": limit, "search": search, "offset_id": offset_id})
        return ["ok"]


class Final5Task3SearchFailClosedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = FailClosedTelethonReadBackend(client_factory=lambda: object())

    def test_internal_typeerror_does_not_retry_without_constraints(self) -> None:
        client = _RaisesInsideCall()
        with self.assertRaisesRegex(TypeError, "inside client call"):
            asyncio.run(
                self.backend._iter_messages(
                    client,
                    "peer",
                    25,
                    search="needle",
                    offset_id=77,
                )
            )
        self.assertEqual(
            client.calls,
            [{"entity": "peer", "limit": 25, "search": "needle", "offset_id": 77}],
        )

    def test_missing_search_parameter_fails_before_broad_call(self) -> None:
        client = _NoSearchSupport()
        with self.assertRaises(BridgeError) as caught:
            asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle"))
        self.assertEqual(caught.exception.code, "telegram_search_unsupported")
        self.assertEqual(client.calls, 0)

    def test_missing_offset_parameter_fails_before_rescan(self) -> None:
        client = _NoOffsetSupport()
        with self.assertRaises(BridgeError) as caught:
            asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle", offset_id=77))
        self.assertEqual(caught.exception.code, "telegram_search_continuation_unsupported")
        self.assertEqual(client.calls, 0)

    def test_supported_constraints_are_forwarded_exactly_once(self) -> None:
        client = _Supported()
        result = asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle", offset_id=77))
        self.assertEqual(result, ["ok"])
        self.assertEqual(
            client.calls,
            [{"entity": "peer", "limit": 25, "search": "needle", "offset_id": 77}],
        )


if __name__ == "__main__":
    unittest.main()
