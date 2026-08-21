# DEV2 analysis — HOSTiQ sanitized reference snapshot v0.4

Status: **REFERENCE_ONLY / NOT DEPLOY AUTHORITY**.

DEV2 inspected the ChatGPT Project archive `Telegram_Bridge_HOSTiQ_CURRENT_SANITIZED_v0.4.zip` only as analytical input. Nothing in this document upgrades it to live production authority or authorizes merge/deployment.

## Integrity facts proven from the package

- Archive SHA-256: `f6c639effd2be00ebba1afbacc082faacd4bfc397a4ac9d056e4ef0eac50c6bf`.
- ZIP file members: 44.
- `MANIFEST_SANITIZED_SHA256.txt` entries: 43.
- The manifest intentionally does not self-reference; the only unmanifested member is the manifest itself.
- Every manifest path and SHA-256 matched the corresponding package member in the inspected archive.
- No duplicate, case-colliding, path-traversal, symlink/special-member or non-NFC path was accepted by DEV2 validation.
- `passenger_wsgi.py` contains the expected startup import `from bridge.app import application`.
- `install_server.sh` is empty. No behavior is inferred from its filename.

## 44 package files versus 42 live-server files

Drive `SERVER_RECOVERY_EVIDENCE` records **42 live server files / 9 directories** from the first-hand recovery, with runtime/private/cache/temp material excluded from public/sanitized export. The package contains **44** files because it is a sanitized recovery package, not a byte-for-byte server filesystem image: it contains replacement/sanitized manifest and documentation/tooling artifacts used to make the recovery copy reviewable.

The count delta is therefore **+2 package members compared with the live-file count**, but DEV2 does **not** claim an exact 42→44 path bijection. The exact original non-secret 42-path manifest is not currently available in Drive/GitHub, so exact per-path accounting remains `BLOCKED_EXTERNAL` until first-hand private manifest evidence is supplied and validated.

## Source-import candidate

DEV2 selected 22 files as a local analysis candidate:

- 16 application-source/startup worker Python files (`bridge/*.py` plus `cron_worker.py`);
- `passenger_wsgi.py`;
- empty `install_server.sh`;
- server `requirements.txt`;
- `tests/test_core.py`;
- `tools/build_openapi.py`;
- `tools/server_selftest.py`.

Windows/Google Drive authorization helper files and their Windows-only dependency input are deliberately excluded from this server candidate. The candidate includes `CANDIDATE_PROVENANCE.json` with the source archive hash and per-file hashes.

The selected raw source is **not committed**. A focused pre-commit check found that the current public-repository secret scanner policy would flag source-level handling of a bearer variable even though no literal production secret was identified. Under the fail-closed rule, DEV2 rejected raw snapshot-derived source from public commit rather than weakening the scanner or altering the source and losing provenance.

Only `reference_candidate/hostiq_v0_4/CANDIDATE_PROVENANCE.json` plus a reference-only README are committed. They contain non-secret path/hash/size/category metadata and explicitly state that raw-source public commit is not authorized. Exact source import remains pending an Auditor-approved scanner/source reconciliation strategy.

## Evidence boundary

Drive evidence remains authoritative for the following server facts: 42 files / 9 dirs inventoried; 39 working files matched the old controlled manifest; `passenger_wsgi.py` is the known changed tracked startup file; `install_server.sh` is the empty extra; private backup exists only on HOSTiQ; old setup route was rotated/invalidated; setup page rendered; cron/temp jobs were zero; Telegram authorization remains incomplete.

This snapshot does not prove Passenger Python 3.11, current deployed SHA, live restart/smoke/rollback, Telegram E2E, or ChatGPT/OpenAPI E2E.
