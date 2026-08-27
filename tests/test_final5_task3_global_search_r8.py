from __future__ import annotations

import asyncio
import unittest
from contextlib import asynccontextmanager
from types import SimpleNamespace

from bridge.final5_global_search_r8 import GlobalContinuation, GlobalSearchR8Backend
from bridge.models import EntityRef, MessageRecord
from bridge.validation import DateRange


class Final5Task3GlobalSearchR8Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.backend = GlobalSearchR8Backend(client_factory=lambda: object())

    def test_cursor_roundtrip_is_scope_bound(self) -> None:
        state = GlobalContinuation(55, "channel", 777, 9)
        token = self.backend._encode_global_cursor("sig", state)
        self.assertEqual(self.backend._decode_global_cursor(token, "sig"), state)
        with self.assertRaises(Exception):
            self.backend._decode_global_cursor(token, "other")

    def test_peer_parts_cover_user_chat_channel(self) -> None:
        for kind, attr in (("user", "user_id"), ("chat", "chat_id"), ("channel", "channel_id")):
            msg = SimpleNamespace(peer_id=SimpleNamespace(**{attr: 42}))
            self.assertEqual(self.backend._peer_parts(msg), (kind, 42))

    def test_input_peer_restore_uses_session_entity_resolution(self) -> None:
        fake_types = SimpleNamespace(
            InputPeerEmpty=lambda: ("empty",),
            PeerUser=lambda x: ("user", x), PeerChat=lambda x: ("chat", x), PeerChannel=lambda x: ("channel", x),
        )
        state = GlobalContinuation(9, "channel", 123, 7)

        class Client:
            def get_input_entity(self, peer):
                return ("resolved", peer)

        self.assertEqual(asyncio.run(self.backend._input_peer(Client(), fake_types, state)), ("resolved", ("channel", 123)))

    def test_filtered_empty_page_keeps_cursor_and_reaches_older_match(self) -> None:
        other = EntityRef(id="1", kind="user", display_name="Other", username="other")
        target = EntityRef(id="2", kind="user", display_name="Target", username="target")
        first = SimpleNamespace(
            id=10,
            chat_id=100,
            peer_id=SimpleNamespace(user_id=100),
            record=MessageRecord(id=10, chat_id="100", timestamp="2026-08-27T05:00:00Z", text="first", sender=other),
        )
        second = SimpleNamespace(
            id=9,
            chat_id=200,
            peer_id=SimpleNamespace(channel_id=200),
            record=MessageRecord(id=9, chat_id="200", timestamp="2026-08-27T04:59:00Z", text="second", sender=target),
        )

        class FakeBackend(GlobalSearchR8Backend):
            @asynccontextmanager
            async def _client_session(self):
                yield object()

            async def _search_global_chunk(self, client, *, query, limit, state, max_date):
                self.assert_limit = limit
                if state is None:
                    return [first], GlobalContinuation(10, "user", 100, 7)
                if state.offset_id == 10:
                    return [second], GlobalContinuation(9, "channel", 200, 6)
                return [], None

            async def _message_record(self, msg, chat_id, *, require_sender_details=False):
                return msg.record

        backend = FakeBackend(client_factory=lambda: object())
        dates = DateRange(start=None, end=None)
        page1 = backend.search(chat=None, sender="target", text="", dates=dates, limit=1, cursor=None, scan_limit=1)
        self.assertEqual(page1.items, ())
        self.assertIsNotNone(page1.next_cursor, "bounded local filtering must not erase Telegram continuation state")

        page2 = backend.search(chat=None, sender="target", text="", dates=dates, limit=1, cursor=page1.next_cursor, scan_limit=1)
        self.assertEqual([item.id for item in page2.items], [9])
        self.assertEqual(page2.scanned, 1)


if __name__ == "__main__":
    unittest.main()
