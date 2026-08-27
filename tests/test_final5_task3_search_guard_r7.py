from __future__ import annotations

import asyncio
import unittest

from bridge.errors import BridgeError
from bridge.final5_search_guard_r7 import GuardedTelethonReadBackend
from bridge.validation import DateRange


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


class _NoSearchSupport:
    def __init__(self) -> None:
        self.calls = 0

    def iter_messages(self, entity: object, *, limit: int) -> list[object]:
        self.calls += 1
        return []


class Final5Task3SearchGuardR7Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = GuardedTelethonReadBackend(client_factory=lambda: object())

    def test_internal_typeerror_never_retries_without_constraints(self) -> None:
        client = _RaisesInsideCall()
        with self.assertRaisesRegex(TypeError, "inside client call"):
            asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle", offset_id=77))
        self.assertEqual(
            client.calls,
            [{"entity": "peer", "limit": 25, "search": "needle", "offset_id": 77}],
        )

    def test_supported_constraints_forward_exactly_once(self) -> None:
        client = _Supported()
        self.assertEqual(
            asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle", offset_id=77)),
            ["ok"],
        )
        self.assertEqual(
            client.calls,
            [{"entity": "peer", "limit": 25, "search": "needle", "offset_id": 77}],
        )

    def test_missing_search_support_fails_before_broad_call(self) -> None:
        client = _NoSearchSupport()
        with self.assertRaises(BridgeError) as caught:
            asyncio.run(self.backend._iter_messages(client, "peer", 25, search="needle"))
        self.assertEqual(caught.exception.code, "telegram_search_unsupported")
        self.assertEqual(client.calls, 0)

    def test_global_cursor_fails_closed_before_network_access(self) -> None:
        calls = 0

        def factory() -> object:
            nonlocal calls
            calls += 1
            return object()

        backend = GuardedTelethonReadBackend(client_factory=factory)
        with self.assertRaises(BridgeError) as caught:
            backend.search(
                chat=None,
                sender=None,
                text="needle",
                dates=DateRange(start=None, end=None),
                limit=20,
                cursor="synthetic-cursor",
                scan_limit=100,
            )
        self.assertEqual(caught.exception.code, "telegram_global_search_continuation_unsupported")
        self.assertEqual(caught.exception.status, 503)
        self.assertEqual(calls, 0)


if __name__ == "__main__":
    unittest.main()
