# DEV_C Release-to-Live Round 2 QA

Status of this document: QA/source evidence only. It does not authorize merge, deployment, Passenger restart, Telegram authorization, ChatGPT Action connection, or a live Telegram write.

## Validation base

The Round-2 DEV_C branch was created from exact DEV_A packaged candidate `237d74baa1522a2e31145104ccc181758c5a7f9c`. At branch creation the merge base was exact, ahead=0 and behind=0. DEV_C production application code is not modified.

## Independent package gates

`ops/devc_release_qa.py` independently verifies:

- exact six-statement Passenger startup contract: `Path`, `bridge.app.application`, `ops.passenger_evidence_hook.collect_if_armed`, `_here = Path(__file__).resolve()`, exact keyword-only one-shot evidence call, and `__all__ = ["application"]`;
- no embedded private/credential source markers in the WSGI shim;
- direct runtime dependency set is exactly Telethon 1.44.0;
- runtime lock closure is exactly Telethon 1.44.0, pyaes 1.6.1, rsa 4.9.1 and pyasn1 0.6.4, each SHA-256 hash locked;
- unsafe/floating/URL/editable/include requirements fail closed;
- public release tree contains no `.env`, private/session/credential class artifacts;
- PREPARED_RELEASE schema is exact, candidate SHA-bound, Python 3.11-bound, hash-bearing, shared-external-state and immutable-policy bound;
- H1-H5 and K1-K5 protocols are non-executing in source QA; K5 keeps Independent Auditor approval, safe destination and fresh explicit commit gates;
- keyboard/NVDA protocol is human-live evidence only and cannot be promoted by static tests.

## Integrated candidate QA

`tests/test_devc_release_e2e.py` drives the actual `UnifiedBridgeApplication` with deterministic synthetic backend/client adapters only. It checks:

1. all 17 Action operations resolve through actual unified runtime dispatch;
2. generated Action schema is deterministic; write commit schemas remain strict and consequential;
3. one continuous WSGI scenario covers dialogs, history, scoped/global search, media metadata, single download, bulk/resume, ZIP, private file retrieval, SEND/REPLY/FORWARD/SEND_FILES preview, explicit-command rejection, one approved synthetic commit and exact replay;
4. preview has zero Telegram effects;
5. public audit evidence excludes synthetic private chat/person/body/file labels, auth/signing placeholders and private filesystem root;
6. fresh application object preserves private file registry, completed download checkpoint and committed idempotency replay without another external effect;
7. 18-way cross-namespace contention runs read, completed-resume and duplicate commit concurrently; expected result is no redownload, no deadlock and exactly one synthetic external write.

No real Telegram, HOSTiQ or ChatGPT Action I/O is used.

## Current internal blockers observed before terminal rebase

DEV_C must not report `RELEASE_QA_GREEN` yet.

1. DEV_A exact head `237d74ba...` Recovery Guard #160 is red. Full regression/package/OpenAPI/provenance gates pass, but exact-head non-live PREPARE fails because direct execution of `tools/verify_release_prepare.py` cannot import `ops`; current-tree secret scan passes while full-history secret scan fails on a historical `bridge/runtime.py` secret-alias-shaped assignment. DEV_C does not weaken either gate.
2. DEV_A release provenance is bound to accepted DEV_B `d45dd0b...`, while live DEV_B PR #11 has advanced substantially. Current DEV_A imports legacy support-return schema v1. Newer DEV_B implements schema v2 with `candidate_package` + `runtime_binding` and explicitly makes v1 ineligible for strong Passenger runtime acceptance. DEV_C treats this as cross-lane release integration debt until DEV_A/DEV_B/Auditor resolve the authoritative final interface.
3. HOSTiQ live reconciliation/runtime/lifecycle, Telegram E2E, deployed ChatGPT Action, human keyboard/NVDA and K5 remain external/human gates and are not converted to source PASS.

## Truth boundary

`USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative. K5 is NOT EXECUTED. No production mutation is performed by DEV_C Round 2.
