# DEV_A provenance and conflict-resolution ledger

## Exact inputs

| Lane | PR | Exact input SHA | Integration decision |
|---|---:|---|---|
| DEV1 | #2 | `26a2df12c350f670a703b236edc3648f339b64a9` | authoritative integration/deployment/security base; only `ops/integration_interfaces.py` is later adapted by DEV_A to represent the canonical cross-lane vocabulary |
| DEV3 | #4 | `4f2c162320c2cbd8e1b0fc2b91a62d2a50806653` | import all 20 changed paths; DEV_A later adapts only `bridge/__init__.py` for unified lazy WSGI export and `bridge/archive.py` for NFC+casefold member-collision hardening |
| DEV4 | #7 | `fc409c7e0bd782148df5cb1a00f9f624b7008548` | import all 12 changed write/OpenAPI paths byte-identically |
| DEV2 | #5 | `19910ec89c85aec6d9ddd31abca0f4cab4dac6cb` | semantic review of DEV1 overlaps, then import stronger compatible 15-path runtime/evidence surface; DEV1 deploy engine untouched |
| DEV5 | #3 | `82643ade0f1b5157d311e06a700223a1501ae062` | port five QA/oracle paths; reject seven production acceptance/evidence overlaps; later adapt only `tests/test_dev5_round2_fuzz.py` to actual integrated APIs |

## Cross-PR overlap matrix

The changed-path sets were re-read live from GitHub before integration.

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

The matrix is represented in machine-checkable form by `integration/provenance_v1.json` and `tools/verify_integration_provenance.py`.

## DEV3 decision

DEV3 was imported through two-parent semantic merge commit `1cd732480e634e2cd6b45be98977c6cb2b2833b9`, whose parents are exact DEV1 base and exact DEV3 head. Only the 20 live PR #4 changed paths were placed in the resulting tree.

All DEV3 paths remain byte-identical to PR #4 except two explicit DEV_A overrides. `bridge/__init__.py` preserves the recovered HOSTiQ import target while exporting the lazy unified integration entry point. `bridge/archive.py` now normalizes ZIP member names to NFC, keys collisions by NFC+casefold, deterministically disambiguates equivalent names, and revalidates the emitted ZIP for duplicate normalized keys and CRC. The core read/media application remains DEV3-owned behavior.

## DEV4 decision

DEV4 was imported through semantic merge commit `10bcc583beaf6aa6f06b15958bf92351cb7f048b`, with exact DEV4 head as second parent. All 12 PR #7 changed paths remain byte-identical to that exact predecessor head.

DEV4 `ops.openapi_registry.OPERATIONS` is the canonical Action/private-API operation table. DEV_A does not create a second write-route table. The unified WSGI layer dispatches write operations directly from this registry and validates that its Action-visible READ paths equal DEV3 runtime read paths.

## DEV2 semantic overlaps

PR #5 overlaps DEV1 on exactly these paths:

- `ops/baseline_reconcile.py`;
- `ops/runtime_evidence.py`;
- `tests/test_runtime_evidence.py`.

`ops/baseline_reconcile.py`: DEV2 adds strict sanitized manifest schema/path/category/count handling while retaining fail-closed behavior. It was selected over the older DEV1 copy.

`ops/runtime_evidence.py`: DEV2 explicitly distinguishes private CLI Python 3.11 candidate context from Passenger application-process confirmation and emits only bounded/hash-only path identity. It was selected over the older DEV1 copy.

`tests/test_runtime_evidence.py`: selected together with the runtime schema so the stronger distinction remains enforced.

No PR #5 copy of `ops/deploy_release.py`, deployment lock policy, acceptance privacy schema or other DEV1 release control was introduced. DEV2's v0.4 material under `reference_candidate/hostiq_v0_4/` is metadata/provenance only; raw recovered snapshot source is not imported and receives no deployment authority.

## DEV5 rejected overlaps and adapted fuzz

These PR #3 paths were explicitly rejected to preserve DEV1 authority:

- `docs/ACCEPTANCE_CONTRACTS.md`;
- `docs/ACCEPTANCE_HARNESS.md`;
- `ops/acceptance_contracts.py`;
- `ops/acceptance_harness.py`;
- `ops/evidence_privacy.py`;
- `tests/test_acceptance_contracts.py`;
- `tests/test_acceptance_harness.py`.

The provenance verifier asserts their final Git blobs equal the DEV1 base blobs.

Selected portable DEV5 paths are:

- `docs/DEV5_QA_SECURITY_MATRIX.md`;
- `docs/DEV5_ROUND2_QA.md`;
- `ops/dev5_round2_oracles.py`;
- `tests/test_dev5_round2.py`;
- `tests/test_dev5_round2_fuzz.py`.

The first four remain byte-identical to exact PR #3 head. `tests/test_dev5_round2_fuzz.py` is an explicit DEV_A semantic adaptation because the original test called DEV5 helper APIs from the seven production files that were deliberately rejected. The adapted test retains adversarial intent but executes against authoritative integrated boundaries: DEV3 WSGI parsing/auth/path validation, DEV1 structured acceptance/evidence schemas, actual `bridge.archive`/private storage, the stable integration interface adapter, and the imported DEV5 crash/idempotency oracle. This is not a bypass and does not restore any rejected DEV5 production implementation.

## DEV_C compatibility reconciliation

DEV_C report/PR #10 identified four stale interface vocabulary defects against the earlier DEV_A checkpoint: `SEND_FILES` was not representable, dotted DEV3 operation IDs were rejected, camelCase DEV4 Action IDs were rejected, and `PROTECTED_OR_SIGNED` was absent. DEV_A resolves these in `ops/integration_interfaces.py` while retaining the invariant that every `PROTECTED_WRITE` RoutePolicy requires `preview_commit_required=True`. Invalid operation-ID grammar remains fail-closed.

DEV_C also reported absent write routes on the older DEV_A `c7dbcdb...` checkpoint. That finding is superseded in the current candidate by the later unified WSGI integration commit `d1a28da09d7c6d7d5a19a771ee6a2a342aad1324`; exact-head DEV_A integration tests exercise all preview/commit families without live Telegram effects. DEV_C still needs to independently revalidate the final DEV_A head after candidate CI is green.

## Machine-verifiable invariants

`tools/verify_integration_provenance.py` fails if any of the following occurs:

1. a semantic merge commit loses or changes an exact predecessor parent;
2. a predecessor path is silently mutated after import unless that exact path is declared in that predecessor's `dev_a_overrides` set;
3. an override names a path outside the predecessor's imported/ported path set;
4. a rejected DEV5 overlap differs from DEV1 base;
5. a candidate diff path appears outside the declared provenance allowlist;
6. a declared DEV_A path disappears from the candidate diff;
7. the no-merge/no-deploy/no-restart/no-live-write/NOT_YET_REQUIRED safety manifest changes.

The verifier emits only Git SHAs/counts/status and no private runtime or Telegram values.

## Safety boundary

No semantic adaptation in this ledger authorizes merge, production deploy, Passenger restart, Telegram credential collection or live Telegram write. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
