# DEV_C Release-to-Live Round 2 QA

Status: QA/source evidence only. This does not authorize merge, deployment, Passenger restart, Telegram authorization, ChatGPT Action connection, or a live Telegram write.

## Validation base

This DEV_C QA stack is rebased onto DEV_A `c4e90bd507ed054bf64167a1266a3325f1c32bf7`. DEV_C does not modify production application code.

## Independent gates

`ops/devc_release_qa.py` independently verifies the exact Passenger startup/evidence-hook sequence, exact Telethon 1.44.0 direct pin and four-package SHA-256-locked runtime closure, private-runtime exclusion, PREPARED_RELEASE metadata truth, non-executing H1-H5/K1-K5 protocols, and human-only keyboard/NVDA protocol.

`tests/test_devc_release_e2e.py` drives actual `UnifiedBridgeApplication` using deterministic synthetic adapters only: 17 Action operations, deterministic schema, continuous read/search/media/download/resume/ZIP/private-file/four-preview/blocked-commit/one-fake-commit/replay/restart path, audit privacy, and 18-way read/resume/duplicate-commit contention.

No real Telegram, HOSTiQ or deployed ChatGPT Action I/O is used.

## Current blockers on this base

DEV_A `c4e90...` Recovery Guard #177 passes package/OpenAPI/67x19/provenance/single-entrypoint, but full regression has two failures: stale runtime-entrypoint expectation (`bridge.integrated_app` versus the new `bridge.runtime_wsgi`) and stale hardcoded release-to-live path count (23 versus verified 26). Exact-head PREPARE is skipped because regression is red. Current-tree secret scan passes; full-history scan remains red on the previously identified historical secret-alias-shaped assignment in `bridge/runtime.py`. DEV_C does not weaken these gates.

DEV_A remains bound to accepted DEV_B `d45dd0b...`; live DEV_B has materially newer schema-v2 candidate/runtime binding work but its moving head is not blindly imported by DEV_C. Final authority requires DEV_A/DEV_B/Auditor reconciliation.

HOSTiQ live reconciliation/runtime/lifecycle, Telegram E2E, deployed Action, human NVDA and K5 remain external/human gates. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative. K5 is NOT EXECUTED.
