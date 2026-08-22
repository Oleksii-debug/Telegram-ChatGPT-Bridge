# DEV_B -> DEV_A runtime integration guidance — Release-to-Live Round 2

Latest DEV_A DRAFT PR #9 head observed while writing this checkpoint: `9937d8c4c8335c7f58bc20e7057fbc2e14281499`.

This document is guidance/evidence only. DEV_B does not modify DEV_A branch and does not authorize deployment.

## What DEV_A has now solved

The original package blocker is materially reduced on current PR #9:

- root `passenger_wsgi.py` exists and canonically exports `from bridge.app import application`;
- root `requirements.txt` pins `Telethon==1.44.0`;
- root `requirements.lock` contains the reviewed exact Telethon/pyaes/rsa/pyasn1 closure with SHA-256 hashes;
- `ops/release_package.py` validates the public startup/dependency envelope;
- `tools/verify_release_prepare.py` invokes the actual `prepare_versioned_release()` pipeline for an exact Git SHA and verifies the prepared artifact/venv rather than trusting a drifting PR working checkout;
- canonical WSGI validation now whitelists only docstring + one `bridge.app.application` import + optional exact `__all__`, so executable startup calls fail closed;
- the release package still carries `deployment_authorized=false` and excludes private runtime material.

The earlier AST negative-test defect observed on `c25a597f...` / `8de1d7bb...` has been repaired in current `ops/release_package.py` by statement-level allowlisting; do not regress to direct `tree.body` `ast.Call` checks.

## Exact DEV_B provenance gap currently present

`integration/release_to_live_v1.json` on DEV_A head `9937...` explicitly records:

- `dev_b.sha = d45dd0bbc81d9db2c764319d766db0d13141532a`;
- old DEV_B runtime/readiness paths were imported/adapted from that Round-1 checkpoint.

Therefore DEV_A currently contains a traceable older DEV_B snapshot, not the current Release-to-Live Round-2 semantics from PR #11.

The current imported `ops/passenger_evidence_hook.py` still uses the obsolete **empty** owner-private marker, writes only one runtime report, and does not bind live evidence to an exact candidate SHA/expected WSGI hash. The current imported `ops/production_readiness.py` is correspondingly pre-v2 and cannot enforce the new exact candidate/runtime binding contract.

## Round-2 DEV_B semantics that must be consumed before HOSTiQ live gate

After exact-head DEV_B CI is green, semantically port the current equivalents of:

- `ops/candidate_runtime_preflight.py` — exact SHA-40 candidate envelope; canonical WSGI; exact pinned runtime direct deps; direct Telethon; fully SHA-256 hash-locked runtime lock; optional test input+lock pair; private/runtime artifact exclusion; hash/count/boolean-only result;
- `tools/validate_candidate_runtime_preflight.py` — one-command owner-private preflight evidence;
- `ops/passenger_evidence_hook.py` — marker schema binds exact candidate SHA + expected WSGI SHA-256; strong evidence requires actual WSGI hash equality; writes both runtime report and tamper-checked `passenger_runtime_binding.json`; marker consumed only after both reports are durable;
- `tools/arm_passenger_evidence.py` — derives marker from successful private candidate preflight and uses POSIX `O_NOFOLLOW|O_EXCL` no-clobber creation with owner/mode/inode checks + fsync;
- `ops/production_readiness.py` support-return **v2** — exact `candidate_package` + `runtime_binding`; top candidate SHA == binding SHA; candidate/runtime/expected/actual WSGI hashes equal; runtime payload hash equality; legacy v1 parseable but unable to satisfy strong Passenger gate;
- `ops/server_manifest.py` current dependency-input categories including runtime/test locks;
- current DEV_B tests and `docs/HOSTIQ_ONE_TIME_SUPPORT_PACKAGE.md`.

Do not blindly overwrite DEV_A-specific adaptations in `ops/hostiq_lifecycle.py`, `ops/release_package.py` or provenance files; port semantics and rerun integrated tests.

## Call-free WSGI-compatible Passenger evidence integration

DEV_A's strict canonical `passenger_wsgi.py` policy is compatible with DEV_B without adding calls to the WSGI file.

Keep `passenger_wsgi.py` as:

```python
from bridge.app import application
```

The preferred integration point is inside the actual exported application request path. Add the DEV_B helper import to `bridge/app.py` and invoke it at the beginning of `BridgeApplication.__call__`:

```python
from ops.passenger_evidence_hook import collect_if_armed_from_bridge_app

# at start of BridgeApplication.__call__(...):
collect_if_armed_from_bridge_app(__file__)
```

Properties:

- no WSGI startup call, so DEV_A's one-import/call-free bootstrap policy remains intact;
- no Telegram/network operation;
- inert when the owner-private exact candidate marker is absent;
- fail-isolated: helper never raises into request handling;
- derives actual app root and sibling `passenger_wsgi.py` from real `bridge/app.py` topology;
- executes only in the process actually serving a WSGI request, which is suitable Passenger application-process evidence;
- exact candidate SHA + expected/actual WSGI hash binding still applies before report/marker consumption.

This is preferable to weakening `validate_wsgi_contract()` to allow arbitrary startup calls.

## Existing runtime adapter invariants to preserve

- Meaningful health requires exact `ok`, `service`, `ready`, `components`; HTTP 200 alone is not PASS.
- `service == telegram-bridge`.
- components are auth/backend/storage/rate_limit with configured/unconfigured states; `ready` must agree.
- Explicit bootstrap-not-ready mode is distinct from production-ready health.
- Authenticated bootstrap probe is fixed to harmless read `POST /api/v1/dialogs/list`; structured `telegram_backend_unconfigured` is acceptable only in explicit bootstrap mode and without Telegram access.
- Private bearer/SHA/hook files use descriptor-safe owner-private reads/execution; no raw output/private values become public evidence.
- No deployment smoke invokes SEND/REPLY/FORWARD/SEND_FILES/K5.
- OpenAPI identity is not running release identity.

## Exact next gate

1. DEV_A exact-head CI must succeed, including **Real exact-head non-live release PREPARE** rather than skipping it after an earlier test failure.
2. The prepared exact SHA must install its lock with `pip --require-hashes` in clean Python 3.11 and prove the exact installed Telethon/pyaes/rsa/pyasn1 versions.
3. DEV_A must port the current DEV_B Round-2 exact-binding semantics and request-path Passenger adapter without weakening canonical WSGI safety.
4. Full integrated CI + DEV_B runtime/readiness tests + DEV_C QA must be green on one exact packaged SHA.
5. Only then may the Independent Auditor decide whether to arm the one-time HOSTiQ live evidence cycle.

No merge, production switch, Passenger restart, Telegram authorization request, live Telegram read/write, or K5 is authorized by this guidance. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains current.