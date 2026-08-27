from __future__ import annotations

import asyncio
import unittest
from types import SimpleNamespace

from bridge.final5_global_search_r8 import GlobalContinuation, GlobalSearchR8Backend


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


if __name__ == "__main__":
    unittest.main()
