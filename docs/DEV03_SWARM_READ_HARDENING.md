# DEV03 Swarm Read Hardening

This document records the non-live DEV03 read-side overlay restacked onto canonical DEV01/PR #9 head `999709f0ab2daee08fdb5c793419d1c45967238d` under AUTONOMOUS SWARM MODE V1. The prior DEV03 checkpoint was based on `d8969307...`; DEV03 independently compared all intervening canonical deltas before each restack. The large runtime delta did not modify DEV03 read implementation files. During this run DEV03 broad regression also exposed three stale DEV_B/DEV_C canonical tests; DEV01 then fixed exactly those tests in the canonical `cb058b74... -> 999709f0...` delta, without touching DEV03 read production paths. DEV03 therefore restacked again rather than carrying an exception allowlist.

## Scope

DEV03 owns Telegram user-client read semantics only: dialogs, history, message retrieval, sender identity, search, timezone/Unicode behavior, cursor safety, read lifecycle and privacy-safe Telegram errors. This slice does not implement media/download storage (DEV04), write/preview/commit (DEV05), OpenAPI ownership (DEV06), durable cross-namespace state/session serialization (DEV08), deployment/runtime (DEV02) or independent QA verdicts (DEV09/AUDIT roles).

## Cursor contract v2

Read cursors are opaque base64url JSON containing schema version 2, operation scope, a hash-only request signature and the last emitted stable ordering boundary. Dialog cursors bind normalized query + unread filter. History cursors bind the requested chat reference. Search cursors bind chat, normalized sender/text, canonical UTC date boundaries and scan limit.

Pagination uses keyset boundaries rather than offsets. Newer dialogs/messages inserted after page 1 do not shift subsequent pages. Old v1 offset cursors fail closed as `invalid_cursor`.

Message ordering is a total order over canonical UTC timestamp, message ID and chat ID. Internal `MessageRecord.timestamp` keeps the established `+00:00` UTC spelling for compatibility while API serialization and cursor/sort comparisons normalize independently.

## Long-history pagination correction

The first DEV03 keyset implementation still had a hidden history ceiling: every history page fetched at most `search_scan_limit` newest messages and only then applied the keyset boundary locally. Once the cursor moved beyond that fixed window, a long chat could terminate early even though older Telegram messages still existed.

The current overlay uses Telethon's explicit `offset_id` contract for scoped history. Production Telethon declares `offset_id` as an exclusive older-than boundary and returns history newest-to-oldest. DEV03 therefore fetches only `limit + 1` rows per real Telethon history page and passes the last emitted message ID as the next exclusive server boundary. This removes the fixed 5,000-message ceiling and reduces unnecessary GetHistory traffic/FloodWait exposure. A bounded local keyset filter remains as defense in depth.

A compatibility fallback is retained only for deterministic minimal fakes that do not explicitly declare `offset_id`; generic `**kwargs` acceptance is not treated as proof that a fake implements Telethon offset semantics.

## Unicode and person search

Search normalization uses Unicode NFKC plus casefold and preserves returned original text. The Telegram server-side text hint is now NFKC-normalized before dispatch, while local NFKC+casefold remains authoritative for returned rows.

Sender filtering accepts stable sender ID, username, display name and an optional leading `@` for usernames. Stable numeric identity remains separately returned.

Sender metadata failure semantics are query-sensitive. History/message reads may degrade to the stable sender ID if optional display metadata cannot be resolved. A sender name/username filter cannot truthfully convert `get_sender()` RPC/FloodWait failure into an empty result, so those searches propagate through the structured Telegram error mapper. Numeric stable-ID search remains usable without optional sender metadata.

## Telegram error boundary

Only known entity-not-found conditions plus local `ValueError` entity resolution failure map to `chat_not_found`. FloodWait propagates to the central Telegram error mapper and returns bounded retry metadata. Arbitrary exceptions that merely expose a `seconds` attribute are not classified as FloodWait. Raw Telegram/backend exception text is never copied to public structured errors.

## CI and integration provenance boundary

DEV03 has a dedicated read-side workflow pinned to the exact canonical parent and exact seven-path overlay. It runs both DEV03 adversarial suites, inherited read/request-security tests, the broad source regression suite, OpenAPI compatibility validation and both secret scans.

DEV01's canonical integration provenance gate intentionally rejects unregistered post-import mutation of DEV3-owned source. DEV03 does not weaken or rewrite that authority. The specialist workflow excludes exactly one DEV01 exact-candidate provenance unittest from its broad regression runner, independently verifies that canonical provenance remains fail-closed on the DEV3 backend mutation, and leaves semantic integration/provenance registration to DEV01.

## Remaining read-side finding

Telethon global search (`entity=None`) requires a non-empty search, filter or `from_user`. Current global sender-only semantics therefore need a separate bounded design for stable-ID/username/name queries rather than pretending a no-text global scan is proven. This remains explicit follow-up work; this overlay does not fabricate live/global-person correctness.

## Evidence boundary

All tests are deterministic synthetic/non-live tests with synthetic names/messages. They materially improve D2/D4/D5/C6/G3 source behavior but do not prove real Telegram D1-D6/K1-K2 product PASS, deployed ChatGPT Action behavior or production readiness.

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative. No Telegram phone/login code/2FA/session/API secret or private Telegram content is used by this slice.
