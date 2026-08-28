# DEV10 Human / Live Evidence Binding

Status: source-only protocol. No deployment, Telegram authorization, ChatGPT Action live call, human NVDA PASS or Telegram write is authorized by this document.

This document is the authoritative DEV10 contract for **final human accessibility evidence**. It supersedes the older `candidate_sha` wording in the `Human evidence schema` section of `DEV10_ACCESSIBILITY_LIVE_E2E_PROTOCOL.md`. The older `validate_human_accessibility_evidence()` helper remains pre-live/source evidence only; it must not be used to claim final deployed human PASS. Final acceptance must use `validate_deployed_human_receipt()` from `ops/dev10_human_live_gate.py`.

## Why this layer exists

A green source candidate, a successful GitHub PR merge-ref run, and a successful non-live PREPARE are important release evidence, but none proves what is actually deployed and running on HOSTiQ. Human accessibility evidence has the same identity problem: a keyboard/NVDA PASS is meaningful only for the exact deployed release and the exact private setup surface that the human tested.

DEV10 therefore treats these identities separately:

1. exact source/release SHA;
2. exact deployed/running SHA;
3. exact SHA-256 of the private setup surface under test;
4. explicit human result for C1/I1/I4/I6.

A pull-request merge ref, PR number, short SHA, generic worktree HEAD, CI-green label or old human result is not a deployed-release identity.

## Source-green is not human/live green

`ops/dev10_human_live_gate.py` intentionally projects source readiness with:

- `source_release_ready` based on exact source SHA + Recovery Guard + non-live PREPARE;
- `human_nvda_pass=false`;
- `telegram_user_input_allowed=false`;
- `production_pass=false`;
- `live_execution_authorized=false`.

The current canonical source may become fully green while production remains blocked. No user Telegram input follows automatically from source CI.

## Every live prerequisite is exact-SHA-bound

A boolean such as `live_manifest_reconciled=true` or `passenger_application_process_verified=true` is not sufficient evidence by itself. Such a fact can become stale after a new release is deployed. DEV10 therefore validates one bounded `LivePrerequisiteBinding` before a human run can become ready.

The binding contains only privacy-safe fields:

- exact deployed SHA;
- exact SHA associated with the Independent Auditor release gate;
- exact SHA associated with live-manifest reconciliation;
- exact SHA associated with Passenger application-process proof;
- exact independently observed running SHA;
- SHA-256 of the private setup surface;
- boolean verification facts for those stages.

The release-gate SHA, live-manifest SHA, Passenger application SHA and running SHA must each equal the exact deployed SHA. The approved source SHA must also equal that same deployed SHA. A stale `true` boolean from an older release therefore cannot be mixed with a newer deployment.

Fail-closed identity states include:

- `BLOCKED_DEPLOYED_SHA_MISMATCH`;
- `BLOCKED_RELEASE_GATE_SHA_MISMATCH`;
- `BLOCKED_LIVE_MANIFEST_SHA_MISMATCH`;
- `BLOCKED_PASSENGER_SHA_MISMATCH`;
- `BLOCKED_RUNNING_SHA_MISMATCH`.

The binding schema has no field for server paths, private URLs, bearer tokens, Telegram identifiers, credentials, screenshots, transcripts, message text or session material. Unexpected fields are rejected rather than logged as evidence.

## Gate before requesting a human NVDA run

A human NVDA run becomes READY only when all of the following refer to the same exact release:

- exact source SHA is valid release identity, not a PR merge ref;
- source CI is green;
- exact non-live PREPARE is verified;
- Independent Auditor release gate exists and is bound to that exact deployed SHA;
- exact deployed SHA equals the approved source SHA;
- fresh live manifest reconciliation is complete and bound to that exact deployed SHA;
- Passenger application-process runtime is verified and bound to that exact deployed SHA;
- running SHA is independently verified and equals that exact deployed SHA;
- the private one-time setup surface is ready;
- the setup surface is bound by SHA-256.

Even then, readiness means only `READY_FOR_HUMAN_NVDA`. It is not a human PASS and it does not self-execute.

Telegram phone/code/2FA/session input remains separately controlled by the canonical Telegram authorization state. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` means zero Telegram credential/session input even if a nonsecret human accessibility run later becomes technically ready. Private Telegram input may be requested only after the authoritative state is `USER_TELEGRAM_AUTH_REQUIRED`.

## Human receipt schema

Final human evidence is intentionally bounded. A receipt contains only:

- criterion: C1, I1, I4 or I6;
- exact deployed SHA-40;
- private setup-surface SHA-256;
- PASS / FAIL / BLOCKED;
- bounded step and finding counts;
- keyboard-only verified boolean;
- spoken name/role/state verified boolean;
- focus order verified boolean;
- status announcement verified boolean;
- `no_private_content_recorded` boolean.

The schema rejects free-form details and therefore has no field for chat titles, people, Telegram IDs, phone numbers, messages, filenames, setup URLs, screenshots, transcripts, spoken private text, credentials or session material.

Criterion-specific PASS requirements remain fail-closed:

- C1: keyboard + spoken name/role/state + focus order + status announcement;
- I1: keyboard-only operation;
- I4: focus order;
- I6: status announcement.

`no_private_content_recorded` must be true for PASS.

## Staleness and invalidation

A previous human PASS is not portable across releases.

- deployed SHA changed -> `STALE_DEPLOYED_SHA`;
- setup-surface hash changed -> `STALE_SETUP_SURFACE`;
- either change invalidates prior human evidence and requires a fresh human run after the new deployment again satisfies the live prerequisites.

A previous live prerequisite proof is also not portable: its own recorded SHA must match the current deployed release before it contributes to readiness.

This prevents a PASS from an old release, an old private setup page, a stale runtime proof, or a GitHub merge ref from being silently reused for a different production state.

## Current project implication

The exact source/canonical gate may be green while these live facts remain absent. Until an Independent Auditor authorizes the release-to-live phase and exact HOSTiQ deployment/runtime identity is established, DEV10 keeps human NVDA evidence unexecuted and Telegram authorization input blocked.

K1-K5 remain separate live scenarios. K5 still requires independent write approval, safe destination, fresh explicit user commit and idempotency; this human-evidence layer does not authorize it.
