# DEV_A provenance and conflict-resolution ledger

## Exact inputs

| Lane | PR | Exact input SHA | Integration decision |
|---|---:|---|---|
| DEV1 | #2 | `26a2df12c350f670a703b236edc3648f339b64a9` | authoritative integration/deployment/security base |
| DEV3 | #4 | `4f2c162320c2cbd8e1b0fc2b91a62d2a50806653` | import all 20 changed paths, then adapt `bridge/__init__.py` only for unified lazy WSGI export |
| DEV4 | #7 | `fc409c7e0bd782148df5cb1a00f9f624b7008548` | import all 12 changed write/OpenAPI paths byte-identically |
| DEV2 | #5 | `19910ec89c85aec6d9ddd31abca0f4cab4dac6cb` | semantic review of DEV1 overlaps, then import stronger compatible 15-path runtime/evidence surface; DEV1 deploy engine untouched |
| DEV5 | #3 | `82643ade0f1b5157d311e06a700223a1501ae062` | port only five QA/oracle paths; reject seven production acceptance/evidence overlaps |

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

DEV3 was imported through a two-parent semantic merge commit `1cd732480e634e2cd6b45be98977c6cb2b2833b9`, whose parents are exact DEV1 base and exact DEV3 head. Only the 20 live PR #4 changed paths were placed in the resulting tree.

All DEV3 paths remain byte-identical to PR #4 except `bridge/__init__.py`. That one file is intentionally adapted by DEV_A so the recovered HOSTiQ import target `from bridge.app import application` resolves to the lazy unified integration entry point after normal package import. `bridge.app.BridgeApplication` itself remains the tested DEV3 read/media core.

## DEV4 decision

DEV4 was imported through semantic merge commit `10bcc583beaf6aa6f06b15958bf92351cb7f048b`, with exact DEV4 head as second parent. All 12 PR #7 changed paths remain byte-identical to that exact predecessor head.

DEV4 `ops/openapi_registry.OPERATIONS` is the canonical Action/private-API operation table. DEV_A does not create a second write-route table. The unified WSGI layer dispatches write operations directly from this registry and validates that its Action-visible READ paths equal DEV3 runtime read paths.

## DEV2 semantic overlaps

PR #5 overlaps DEV1 on exactly these paths:

- `ops/baseline_reconcile.py`;
- `ops/runtime_evidence.py`;
- `tests/test_runtime_evidence.py`.

`ops/baseline_reconcile.py`: DEV2 adds strict sanitized manifest schema/path/category/count handling while retaining fail-closed behavior. It was selected over the older DEV1 copy.

`ops/runtime_evidence.py`: DEV2 explicitly distinguishes private CLI Python 3.11 candidate context from Passenger application-process confirmation and emits only bounded/hash-only path identity. It was selected over the older DEV1 copy.

`tests/test_runtime_evidence.py`: selected together with the runtime schema so the stronger distinction remains enforced.

No PR #5 copy of `ops/deploy_release.py`, deployment lock policy, acceptance privacy schema or other DEV1 release control was introduced. DEV2's v0.4 material under `reference_candidate/hostiq_v0_4/` is metadata/provenance only; raw recovered snapshot source is not imported and receives no deployment authority.

## DEV5 rejected overlaps

These PR #3 paths were explicitly rejected to preserve DEV1 authority:

- `docs/ACCEPTANCE_CONTRACTS.md`;
- `docs/ACCEPTANCE_HARNESS.md`;
- `ops/acceptance_contracts.py`;
- `ops/acceptance_harness.py`;
- `ops/evidence_privacy.py`;
- `tests/test_acceptance_contracts.py`;
- `tests/test_acceptance_harness.py`.

The provenance verifier asserts their final Git blobs equal the DEV1 base blobs.

Only these portable DEV5 paths were selected, byte-identical to exact PR #3 head:

- `docs/DEV5_QA_SECURITY_MATRIX.md`;
- `docs/DEV5_ROUND2_QA.md`;
- `ops/dev5_round2_oracles.py`;
- `tests/test_dev5_round2.py`;
- `tests/test_dev5_round2_fuzz.py`.

## DEV_A-owned reconciliation

DEV_A adds only integration-specific surfaces:

- unified lazy WSGI composition;
- package-level recovered-import-target adapter;
- cross-lane integration/adversarial tests;
- explicit compile/OpenAPI/provenance CI gates;
- deterministic provenance manifest/verifier;
- integration/provenance documentation.

These changes do not authorize merge, production deploy, Passenger restart, Telegram credential collection or live Telegram write.

## Machine-verifiable invariants

`tools/verify_integration_provenance.py` fails if any of the following occurs:

1. a semantic merge commit loses or changes an exact predecessor parent;
2. a byte-identical predecessor path is silently mutated after import;
3. a rejected DEV5 overlap differs from DEV1 base;
4. a candidate diff path appears outside the declared provenance allowlist;
5. a declared DEV_A path disappears from the candidate diff;
6. the no-merge/no-deploy/no-restart/no-live-write/NOT_YET_REQUIRED safety manifest changes.

The verifier emits only Git SHAs/counts/status and no private runtime or Telegram values.
