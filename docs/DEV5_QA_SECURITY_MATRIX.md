# DEV5 QA / security / accessibility matrix

This file records the deterministic DEV5 fan-out work boundary from audited anchor `3c315a29558b7996070fa2c109dc2ff98f6de04d`. It contains no real Telegram data, production credentials, private server routes or user content.

## Auditor findings targeted

| Finding | DEV5 engineering response | Evidence class |
| --- | --- | --- |
| M9 evidence metadata privacy | semantic environment/reference/enum allowlists; namespaced hash-only private identifiers; mutation/aggregate/exception regressions | synthetic prerequisite |
| M10 lifetime rate limiter | real fixed windows, rollover, actor isolation, boundaries and retry-after | synthetic prerequisite |
| M11 idempotency semantics | request fingerprint binding, conflict on mismatched reuse, committed retry after expiry, concurrency and restart-state validation | synthetic prerequisite |
| M12 accessibility overclaim | broader structural checks plus explicit reclassification of I1/I6 to REAL_SOURCE_REQUIRED | structural prerequisite only |
| M13 OpenAPI marker bypass | canonical route registry/protected-by-default policy, public allowlist, preview pairing, structured errors | synthetic prerequisite |
| L5 resume semantics | pending work is continued after interruption rather than only reporting completed items | synthetic prerequisite |

## Security matrices

The test suite includes deterministic matrices for bearer authorization, traversal encodings/confusables, malformed JSON/content length/ranges, rate-limit windows, Telegram failure states, ZIP collisions/caps/CRC, private-file signatures/expiry/tamper/path/file-ID/deletion/download caps, preview token invalid/expired/used states, request-bound idempotency, restart persistence and concurrency.

No real secret value or private Telegram content is required for any case.

## Accessibility evidence boundary

Static HTML analysis can establish only structural prerequisites. It checks labels, ARIA references, names, headings, focusability, positive tabindex, essential-control reachability, non-native keyboard semantics, pointer-only handlers, live regions and error associations. Rule evidence exposes rule IDs and counts, not control text.

Static analysis does not prove actual keyboard interaction or NVDA announcements. Therefore I1 and I6 remain REAL_SOURCE_REQUIRED and later require factual UI/runtime evidence. I2/I3/I4/I5/I7 may receive synthetic structural coverage without becoming product PASS.

## OpenAPI evidence boundary

Self-declared `x-*` flags are never sufficient proof of authorization or write safety. Operations not explicitly public are protected by default; write/commit routes require an authoritative preview pairing; schema/registry drift fails closed. H1 still requires generated schema versus factual application/deployed endpoint evidence.

## Acceptance drift gate

All 67 A1–K5 criteria are present exactly once. `SYNTHETIC_EXECUTABLE` entries must name concrete automated tests. K1–K5 are always LIVE_EXTERNAL_REQUIRED. Coverage classes never contain product PASS.

## Production boundary

This DEV5 branch does not merge or deploy. It does not perform a live Telegram write. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains the correct current flag until source/runtime/server setup makes human Telegram authorization the first real blocker.
