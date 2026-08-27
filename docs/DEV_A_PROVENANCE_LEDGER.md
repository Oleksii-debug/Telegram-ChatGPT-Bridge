# DEV_A provenance and conflict-resolution ledger

## Exact predecessor inputs

| Lane | PR | Exact input SHA | Integration decision |
|---|---:|---|---|
| DEV1 | #2 | `26a2df12c350f670a703b236edc3648f339b64a9` | authoritative integration/deployment/security base; `ops/integration_interfaces.py` is later adapted by DEV_A for canonical cross-lane vocabulary |
| DEV3 | #4 | `4f2c162320c2cbd8e1b0fc2b91a62d2a50806653` | import all 20 changed paths; later adapt only `bridge/__init__.py` and `bridge/archive.py` |
| DEV4 | #7 | `fc409c7e0bd782148df5cb1a00f9f624b7008548` | import all 12 write/OpenAPI paths; later adapt only `ops/write_safety.py` for the proven same-key concurrent transition classification defect |
| DEV2 | #5 | `19910ec89c85aec6d9ddd31abca0f4cab4dac6cb` | semantic review of DEV1 overlaps, then import stronger compatible runtime/evidence surface; DEV1 deploy engine untouched |
| DEV5 | #3 | `82643ade0f1b5157d311e06a700223a1501ae062` | port five QA/oracle paths; reject seven production acceptance/evidence overlaps; later adapt only `tests/test_dev5_round2_fuzz.py` |

Release-to-Live Round 2 adds separately machine-accounted selective inputs rather than pretending they were part of the original five-lane assembly:

- DEV_B PR #11 accepted source checkpoint `d45dd0bbc81d9db2c764319d766db0d13141532a`, semantic merge `052e23e34bcafd9e2d3b569acb7065195689eb95`;
- DEV_B Round-2 synchronization checkpoint `6f943ee15f053acc5b4f15167c16d431023a35d1`, semantic merge `919d7d409564d7c21e46009e1d76cfa5d1fd602d`;
- DEV_C PR #16 QA checkpoint `5758bfdcd9ecee4011fc3caaa3c68eb46ee2af19`, semantic merge `df318aa089f754b7a14f624b7c27cca59758cbe8`.

A newer moving DEV_B or DEV_C head is not inherited by implication. Newer work must be explicitly reviewed and re-accounted before canonical import.

## Cross-PR overlap matrix

The original five-lane changed-path sets are machine-recomputed by `tools/verify_integration_provenance.py`.

| Pair | Direct changed-path overlap | Classification |
|---|---:|---|
| PR #2 × PR #3 | 7 | semantic/control overlap — DEV1 preserved |
| PR #2 × PR #4 | 0 | no direct overlap |
| PR #2 × PR #5 | 3 | semantic runtime/evidence overlap — reviewed and DEV2 stronger compatible versions selected |
| PR #2 × PR #7 | 0 | no direct overlap |
| PR #3 × PR #4 | 0 | no direct overlap |
| PR #3 × PR #5 | 0 | no direct overlap |
| PR #3 × PR #7 | 0 | no direct overlap |
| PR #4 × PR #5 | 0 | no direct overlap |
| PR #4 × PR #7 | 0 | no direct overlap |
| PR #5 × PR #7 | 0 | no direct overlap |

## DEV3 decision

DEV3 was imported through two-parent semantic merge `1cd732480e634e2cd6b45be98977c6cb2b2833b9`, whose parents are the exact DEV1 base and exact DEV3 head. All DEV3 paths remain byte-identical except the two explicit DEV_A overrides.

`bridge/__init__.py` preserves the recovered startup import contract while exporting the lazy unified application. `bridge/archive.py` uses Unicode NFC + casefold collision keys, deterministic disambiguation, and post-build normalized-name/CRC verification. The read/media behavior remains DEV3-owned.

## DEV4 decision and narrow concurrency override

DEV4 was imported through semantic merge `10bcc583beaf6aa6f06b15958bf92351cb7f048b`, with exact DEV4 head as second parent. The only declared DEV_A override is now `ops/write_safety.py`.

The override does not weaken preview/commit or ambiguity protection. It corrects one exact race:

1. two same-key commit calls can both observe an existing durable `RESERVED` transaction;
2. one wins `RESERVED -> CALLING`;
3. the other reaches `_transition_to_calling()` and sees `CALLING`.

On this path `CALLING` means another concurrent writer currently owns the external-effect boundary, so the loser returns fail-closed `409 write_in_progress`. It must not be mislabeled `write_outcome_unknown_reconciliation_required`. Only a durable `AMBIGUOUS` state retains reconciliation-required semantics. The winning external effect is still single, blind resend remains prohibited, and a subsequent same-key call after durable commit returns idempotent replay.

DEV4 `ops.openapi_registry.OPERATIONS` remains the canonical Action/private-API operation table; no second write-route table is introduced.

## DEV2 semantic overlaps

PR #5 overlaps DEV1 on exactly:

- `ops/baseline_reconcile.py`;
- `ops/runtime_evidence.py`;
- `tests/test_runtime_evidence.py`.

The stronger compatible DEV2 versions were selected after semantic review. No DEV2 copy of `ops/deploy_release.py`, deployment lock policy, acceptance privacy schema, or other DEV1 deploy control replaced DEV1 authority. The v0.4 reference material remains reference/provenance only and has no deployment authority.

## DEV5 rejected overlaps and adapted fuzz

These DEV5 paths remain explicitly rejected and byte-identical to DEV1 base:

- `docs/ACCEPTANCE_CONTRACTS.md`;
- `docs/ACCEPTANCE_HARNESS.md`;
- `ops/acceptance_contracts.py`;
- `ops/acceptance_harness.py`;
- `ops/evidence_privacy.py`;
- `tests/test_acceptance_contracts.py`;
- `tests/test_acceptance_harness.py`.

Selected portable DEV5 paths are the two QA docs, `ops/dev5_round2_oracles.py`, `tests/test_dev5_round2.py`, and `tests/test_dev5_round2_fuzz.py`. Only the fuzz test is adapted: it retains adversarial intent while executing against the actual integrated DEV1/DEV3/DEV4/DEV_A boundaries instead of restoring rejected DEV5 production helpers.

## DEV_B Release-to-Live accounting

`integration/release_to_live_v1.json` separately records DEV_B release/runtime/package paths. The canonical candidate does not follow the live tip of PR #11 automatically.

At the accepted Round-2 sync checkpoint, nine paths remain byte-exact to `6f943ee15f053acc5b4f15167c16d431023a35d1`. Three paths are explicit retained DEV_A adaptations:

- `ops/server_manifest.py`;
- `tests/test_devb_round2_release.py`;
- `tests/test_server_manifest.py`.

The strict-history suppression layer is explicitly not imported. Public provenance contains no private server values.

## DEV_C QA accounting

The selected DEV_C QA source is `5758bfdcd9ecee4011fc3caaa3c68eb46ee2af19` via semantic merge `df318aa089f754b7a14f624b7c27cca59758cbe8`.

Byte-exact DEV_C paths are now only:

- `docs/DEV_C_RELEASE_TO_LIVE_QA.md`;
- `ops/devc_release_qa.py`.

Explicit DEV_A-adapted DEV_C paths are:

- `tests/test_devc_release_qa.py`;
- `tests/test_devc_release_e2e.py`.

The E2E adaptation reflects the canonical concurrency contract: concurrent same-key losers may receive only `409 write_in_progress`; the scenario still proves one external effect and a later successful idempotent replay. This test is therefore not misrepresented as byte-identical to the source QA checkpoint.

A later DEV_C Round-2 overlay found the process-shared rate-limiter backward-clock issue. DEV_A fixed the production store with a persistent high-water mark; DEV_C subsequently showed that regression passing. Another DEV_C bulk-download `500` was traced to its mock reading `source_ref` while the canonical `ReadBackend.download_media` protocol passes `file_ref`; that fixture mismatch was reported back to DEV_C and was not used as justification to mutate correct production download code.

## Machine-verifiable invariants

`tools/verify_integration_provenance.py` fails if any of the following occurs:

1. a semantic merge loses or changes an exact recorded parent;
2. a predecessor path silently mutates unless that exact path is declared as an override/adaptation;
3. an override escapes its predecessor path set;
4. a rejected DEV5 overlap differs from DEV1 base;
5. a DEV_B path represented as exact differs from its fixed accepted checkpoint;
6. a DEV_C path represented as exact differs from its source checkpoint;
7. a DEV_C path represented as adapted silently reverts to the stale source blob;
8. a candidate path appears outside the declared allowlists;
9. a declared DEV_A or Release-to-Live path disappears from the candidate diff;
10. the no-merge/no-deploy/no-restart/no-live-write/NOT_YET_REQUIRED safety boundary changes.

The verifier emits only public Git identities, counts, and bounded status; it does not read or serialize private runtime, credential, Telegram-content, or HOSTiQ values.

## Safety boundary

No semantic adaptation in this ledger authorizes merge, production deploy, Passenger restart, Telegram credential collection, or live Telegram write. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
