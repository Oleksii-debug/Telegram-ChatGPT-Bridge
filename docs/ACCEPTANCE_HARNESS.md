# Telegram Bridge — A–K acceptance harness

Source of truth: Drive `04_ACCEPTANCE_TESTS — Telegram Bridge`.

The repository contains all 67 criteria A1–K5 exactly once in `ops/acceptance_harness.py`. Planning/readiness states are not product verdicts.

## Evidence privacy — schema v2

Public/Drive evidence is a compact control-plane record, never a diagnostic transcript. Every result requires:

- exact 40-character Git SHA;
- a semantic environment class from a finite allowlist;
- PASS / FAIL / BLOCKED result state;
- a structured evidence reference;
- only criterion-appropriate typed facts.

Environment classes are semantic fixed values such as `github-ci`, `synthetic`, `reference-snapshot`, `hostiq-staging`, `hostiq-production` and `chatgpt-action-live`. Free-form labels are rejected.

Evidence references use reviewed provider forms only, for example `github:run:<numeric-id>`, `github:job:<numeric-id>`, `github:commit:<sha40>` or a `*:sha256:<sha256>` reference. Chat/person/file names and other uncontrolled labels are not evidence references. When a private identifier must be correlated, `hash_private_identifier()` emits a namespace-separated SHA-256 instead of returning the raw identifier.

Facts use positive per-key schemas:

- booleans;
- bounded integer/count/status values;
- exact SHA-40 / SHA-256 values;
- finite semantic enums;
- bounded reviewed enum/hash lists.

Unknown keys, arbitrary prose, Cyrillic or ASCII private labels in enum slots, nested fact dictionaries, bytes/custom objects, oversized lists/objects, excessive depth and unsupported types fail closed. Aggregate size is bounded.

`build_result()` validates the finalized object; `serialize_result()` independently revalidates a copy. Mutable list/tuple inputs are copied so later caller mutation cannot change a previously validated result without being caught at serialization.

Exception messages, chained exception text and subprocess stdout/stderr are intentionally discarded. Evidence retains only reviewed category/presence/status facts. Repository secret scanning remains a separate stronger gate; the evidence schema additionally rejects privacy-unsafe metadata that is not necessarily a repository-secret pattern.

## Telegram user-authorization gate

`evaluate_telegram_auth_gate()` accepts only boolean readiness facts and never credential values. `USER_TELEGRAM_AUTH_REQUIRED` occurs only when all real server/source/runtime prerequisites are ready, Telegram setup/session input is the first remaining human blocker and the work is not synthetic-only.

Current project state remains:

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED`

Synthetic QA must never cause a request for phone number, login code, 2FA password, API hash or session material.

## Coverage versus product evidence

`ops/acceptance_contracts.py` maintains a separate coverage layer:

- `SYNTHETIC_EXECUTABLE` means a deterministic prerequisite contract exists and maps to a concrete automated test;
- `REAL_SOURCE_REQUIRED` means sanitized factual application/UI source or real non-live integration is still needed;
- `LIVE_EXTERNAL_REQUIRED` means authorized deployed HOSTiQ/Telegram/ChatGPT evidence is required.

The coverage layer never emits product PASS. In particular:

- H1 generated schema matching deployed endpoints is not synthetically proven;
- I1 full keyboard operation is not proven by static HTML;
- I6 actual NVDA status/error announcement is not proven by static HTML;
- K1–K5 always require live external evidence; K5 additionally requires explicit write approval.

No live Telegram send is authorized by this harness.
