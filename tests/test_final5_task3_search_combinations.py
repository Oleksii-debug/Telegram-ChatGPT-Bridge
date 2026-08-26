from __future__ import annotations

import unittest
from datetime import datetime, timezone

from bridge.backend import TelethonReadConfig
from bridge.final5_search_backend import Final5TelethonReadBackend
from bridge.validation import DateRange


class User:
    def __init__(self, user_id: int, username: str) -> None:
        self.id = user_id
        self.username = username
        self.first_name = username
        self.last_name = ""


class Message:
    def __init__(self, message_id: int, chat_id: int, sender: User, text: str) -> None:
        self.id = message_id
        self.chat_id = chat_id
        self.sender_id = sender.id
        self.date = datetime(2026, 8, 26, 18, 0, tzinfo=timezone.utc)
        self.message = text
        self.out = False
        self.reply_to = None
        self.media = None
        self.file = None
        self._sender = sender

    async def get_sender(self) -> User:
        return self._sender


class StrictCombinedSearchClient:
    def __init__(self, wanted: User, messages: list[Message]) -> None:
        self.wanted = wanted
        self.messages = messages
        self.calls: list[dict[str, object]] = []

    async def connect(self) -> None:
        return None

    async def is_user_authorized(self) -> bool:
        return True

    async def disconnect(self) -> None:
        return None

    async def get_entity(self, target):  # type: ignore[no-untyped-def]
        if target == self.wanted.username:
            return self.wanted
        raise ValueError("not found")

    def iter_dialogs(self, limit: int):
        return []

    def iter_messages(
        self,
        entity,
        limit: int,
        *,
        search: str = "",
        filter=None,
        from_user=None,
        offset_id: int | None = None,
    ):  # type: ignore[no-untyped-def]
        self.calls.append(
            {
                "entity": entity,
                "limit": limit,
                "search": search,
                "filter": filter,
                "from_user": from_user,
                "offset_id": offset_id,
            }
        )
        rows = list(self.messages)
        if from_user is not None:
            rows = [row for row in rows if row.sender_id == from_user.id]
        if search:
            folded = search.casefold()
            rows = [row for row in rows if folded in row.message.casefold()]
        return rows[:limit]


class Final5Task3SearchCombinationTests(unittest.TestCase):
    def test_global_text_and_sender_are_both_constrained_before_scan_budget(self) -> None:
        wanted = User(42, "reader")
        other = User(7, "other")
        client = StrictCombinedSearchClient(
            wanted,
            [
                Message(12, 100, other, "needle"),
                Message(11, 101, other, "needle"),
                Message(10, 102, other, "needle"),
                Message(9, 103, wanted, "needle"),
            ],
        )
        backend = Final5TelethonReadBackend(
            client_factory=lambda: client,
            config=TelethonReadConfig(
                request_timeout_seconds=2,
                dialog_scan_limit=20,
                search_scan_limit=100,
                flood_wait_cap_seconds=10,
            ),
        )

        page = backend.search(
            chat=None,
            sender="@reader",
            text="needle",
            dates=DateRange(None, None),
            limit=1,
            cursor=None,
            scan_limit=3,
        )

        self.assertEqual([item.id for item in page.items], [9])
        self.assertEqual(client.calls[0]["search"], "needle")
        self.assertIs(client.calls[0]["from_user"], wanted)
        self.assertIsNone(client.calls[0]["filter"])


if __name__ == "__main__":
    unittest.main()
