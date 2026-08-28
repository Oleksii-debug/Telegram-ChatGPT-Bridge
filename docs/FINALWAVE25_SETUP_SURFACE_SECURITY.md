# FINALWAVE-25 — one-time setup surface security

## Scope and evidence boundary

This slice started from live canonical PR #9 head `84691967e5363bc4b88dfae97371d7bf329c105d` and is intentionally credential-free. It does not authorize Telegram, deploy production, restart Passenger, touch HOSTiQ private configuration, or claim human NVDA PASS.

The current canonical tree had no production setup-route implementation to patch directly. Existing canonical evidence covered OpenAPI exclusion and structural readiness. DEV10 PR #40 contained useful accessibility/live-protocol planning, but not a durable one-time web gate. The recovered sanitized v0.4 source was inspected only as historical evidence, never as source of truth.

## Historical defects falsified/reproduced from the sanitized reference only

The old reference setup implementation used a process-local lock, mutable global setup state, no durable per-stage replay token with TTL, no persistent abuse quota, and completion ordering that could leave a setup route active until after private session persistence. It also derived a public base URL from request proxy/Host metadata and displayed sensitive completion material/manual cPanel restart guidance. None of those legacy implementation patterns is copied into this branch.

## Isolated repair

`ops/setup_surface_security.py` is a standard-library, credential-free security core intended for semantic integration by the canonical owner. Its public API accepts gate metadata only; no API hash, phone number, login code, 2FA password, Telegram session value, bearer token, or private message/media value is accepted by the durable store.

Implemented controls:

- Private state root must be owner-controlled mode `0700`; database must be a single-link owner-controlled regular file mode `0600`. Symlink, hardlink, broad-mode, wrong-owner and unsafe topology fail closed.
- The private setup route is possession-gated and stored only as a SHA-256 digest. The raw route value is never returned by status/audit APIs.
- Per-form challenge tokens are high-entropy, bounded, TTL-limited, single-use, rotated after failures and stored only as digests.
- Durable state uses SQLite `BEGIN IMMEDIATE`, so Passenger/multi-process contenders serialize. Same-token concurrent submissions have exactly one winner.
- Actor and global quotas are durable across process restart. Route opens are also rate-limited.
- A persisted clock high-water mark prevents wall-clock rollback from resetting fixed-window quotas; backwards time fails closed.
- Successful setup stages are explicit: START -> CODE -> optional PASSWORD -> SESSION_READY -> FINALIZING -> DISABLED.
- `FINALIZING` is deliberately web-inaccessible. The route digest and browser challenge are cleared before the external private session-persistence side effect. If the process crashes there, restart observes a closed web gate; a server-side completion call can mark DISABLED after private persistence succeeds. This removes the legacy crash window where authorization could succeed while the setup route remained reachable.
- Re-arming an initialized or completed setup gate is not an in-band web operation. Any legitimate recovery must be explicit out-of-band server administration under the audited deployment/support process.
- Error objects expose stable public codes/status only; exception detail/private Telegram content is not accepted into audit metadata.
- Setup audit records are positive-schema metadata only: allowlisted event/stage/status/generation.
- Setup responses prescribe `no-store`, `no-referrer`, frame denial, noindex, default-deny CSP with same-origin form action, MIME sniffing denial, permissions denial and cross-origin isolation headers.
- Public origin must be an explicitly configured HTTPS origin; it is not derived from request Host or forwarded-proto metadata.
- Setup markup is script-free and structural: one main landmark, ordered headings, explicit labels, native named buttons, natural keyboard order, no positive tabindex, text status/alert regions and no mouse-only handler surface. This is source-level readiness only, not human NVDA evidence.
- Completion markup displays no bearer token/API base and assigns Passenger restart/session-survival verification to support/automation rather than recurring user cPanel work.

## ChatGPT Action boundary

`validate_action_schema_excludes_setup()` fails closed if a ChatGPT Action path or request/header field exposes setup/bootstrap/login/2FA/session onboarding material. Canonical `ops/openapi_registry.py` was also tightened so the serialized Action no longer mentions a Telegram session in its generic 503 response description. Regression tests assert the serialized Action contains no setup/bootstrap/session/session-string/API-hash/setup-key onboarding surface.

The private browser setup flow is therefore a server-side bootstrap surface, never a ChatGPT Action operation.

## Exact later-auth live protocol

`later_auth_live_protocol(candidate_sha=...)` produces privacy-safe, non-executing steps bound to one candidate SHA. Every row has `execute_now=false`, `public_secret_value_allowed=false`, and `user_cpanel_required=false`.

The intended later order is:

1. Independent Auditor gate for the exact candidate SHA.
2. Verify exact live deployed SHA.
3. Verify actual Passenger Python 3.11 runtime.
4. Verify the private one-time setup route exists without publishing its value.
5. User opens only the private setup page.
6. Only then, if governance has changed to `USER_TELEGRAM_AUTH_REQUIRED`, user enters Telegram API/application data and phone on that private page.
7. User enters the one-time login code on the same private page.
8. User enters 2FA only if Telegram requires it.
9. Server closes/rotates the setup web gate before the private session persistence side effect.
10. Automation persists the Telegram session only in approved private server storage.
11. Automation marks setup DISABLED.
12. Support/automation restarts Passenger.
13. Auditor verifies the authorized session survives restart without exposing it.
14. Auditor verifies the ChatGPT Action still excludes setup/login/2FA/session onboarding.
15. Auditor performs only a harmless authenticated read smoke before any separately approved write scenario.

This protocol is preparation only. Current governance remains `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED`; this branch does not request or collect credentials.

## Verification coverage in this branch

`tests/test_finalwave25_setup_surface_security.py` covers positive/negative path protection, at-rest digest-only route/form tokens, expiry/replay, no-2FA and 2FA stages, FINALIZING crash/restart safety, durable actor quota, route-open quota, concurrent same-token serialization, backward-clock failure, one-time re-arm rejection, symlink/hardlink/mode failures, privacy-safe status, security headers, configured-origin policy, structural accessibility and the future live protocol.

`tests/test_finalwave25_action_setup_exclusion.py` covers exact serialized canonical Action exclusion plus adversarial schema mutation.

These tests prove source contracts only. They do not prove production routing, live rate-limiter behavior behind a proxy, Telegram authorization, session survival on HOSTiQ, human NVDA behavior, ChatGPT end-to-end behavior, deployment, rollback or K5.

## Integration recommendation

Canonical integrator should semantically integrate this security core and tests rather than copying the sanitized legacy `bridge/setup.py`. The live adapter still needs to bind private route dispatch, actor identity, Telethon calls and private session persistence to these contracts without logging/request-body leakage. Integration must preserve the exact ordering: close the web gate -> persist private session -> mark disabled -> audited Passenger restart -> restart-survival/read smoke.

No merge/deploy is authorized by this slice. Generic Recovery Guard may remain red at the inherited canonical recovery finding until the canonical owner fixes that separate domain; do not weaken provenance/recovery gates to make this isolated overlay green.
