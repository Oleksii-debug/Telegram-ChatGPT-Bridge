# DEV_B — one-time HOSTiQ release-to-live evidence package

Purpose: one bounded server-side path for factual source/runtime/lifecycle evidence without making the user a recurring cPanel operator.

Status: **PREPARED / NOT AUTHORIZED FOR LIVE SWITCH**. Execute production mutation only after the Independent Auditor approves one exact packaged DEV_A SHA. This package never asks for or returns Telegram credentials/session values, bearer values, setup-route values, private messages/media, environment dumps or raw private logs.

## 1. Preconditions and exact release identity

Support receives only non-secret release identifiers from the Auditor/release owner:

- exact approved Git SHA-40 and approved ref;
- exact candidate manifest/release identity hashes;
- exact `passenger_wsgi.py` SHA-256;
- exact `requirements.lock` SHA-256;
- application root `/home/rukadopo/telegram_bridge`;
- production host `tg-api.rukadopomogy.org.ua`.

The candidate is not eligible for this package until it contains root `passenger_wsgi.py`, `requirements.txt`, fully SHA-256 hash-locked `requirements.lock`, and any test dependency input only as an exact `requirements-test.txt` + `requirements-test.lock` pair.

## 2. Private control/evidence roots

Run as the application account:

```sh
umask 077
install -d -m 700 "$HOME/.telegram_bridge_private_control"
install -d -m 700 "$HOME/.telegram_bridge_private_evidence"
```

No secret is a command-line argument.

## 3. Exact candidate package preflight — before Passenger arming

Run against the exact exported/staged candidate, never an approximate source copy. The tool resolves its own repository root and does not depend on the caller's current directory or `PYTHONPATH`:

```sh
python tools/validate_candidate_runtime_preflight.py \
  --candidate-root /PATH/TO/EXACT/STAGED/CANDIDATE \
  --candidate-sha EXACT_APPROVED_SHA40 \
  --output "$HOME/.telegram_bridge_private_evidence/candidate_runtime_preflight.json"
```

Expected stdout is only `CANDIDATE_RUNTIME_PREFLIGHT_PASS` or `CANDIDATE_RUNTIME_PREFLIGHT_BLOCKED`.

The preflight fails closed unless:

- `passenger_wsgi.py` matches the exact reviewed startup contract in section 6; merely containing the recovered application import is insufficient;
- runtime direct dependencies are unconditional exact pins and directly include Telethon;
- every locked package is exact-pinned and has SHA-256 hashes only;
- direct runtime versions exactly match the lock;
- optional test requirements occur only as an exact input+lock pair and are hash locked;
- private/runtime/session/backup/.env/database/key material is absent from the code artifact;
- required control files are owner-owned regular single-link files;
- output remains hash/count/boolean-only and `promotion_authorized=false`.

This static preflight does **not** prove transitive dependency completeness. The real non-production `prepare_versioned_release()` must still create a clean Python 3.11 environment and make `pip --require-hashes` succeed; that execution proves the lock is actually installable and transitively complete.

## 4. First-hand live source manifest — no source text export

From the actual live application root/tooling context:

```sh
cd /home/rukadopo/telegram_bridge
python tools/collect_server_manifest.py
```

Expected stdout: `SERVER_MANIFEST_PRIVATE_REPORT_WRITTEN` or a bounded blocked code. The collector writes only path/hash/size/reviewed-category facts, skips known private/runtime directories and rejects unknown or unsafe topology. Shell `python3` used here is never Passenger proof.

`requirements.txt`, `requirements.lock`, `requirements-test.txt`, and `requirements-test.lock` are reviewed `dependency_input` classes when present. The exact live manifest must later reconcile to the exact approved candidate manifest; no reference snapshot can substitute.

## 5. Exact-candidate Passenger arming

The old empty marker is obsolete and intentionally rejected. Arming must derive from the successful owner-private candidate preflight so a different candidate or WSGI cannot reuse the evidence cycle. The tool also resolves imports from its own repository location and is safe to launch from a different working directory:

```sh
python tools/arm_passenger_evidence.py \
  --preflight "$HOME/.telegram_bridge_private_evidence/candidate_runtime_preflight.json"
```

Expected stdout is only `PASSENGER_EVIDENCE_ARMED_FOR_EXACT_CANDIDATE` or `PASSENGER_EVIDENCE_ARM_BLOCKED`.

The tool creates, with no-clobber POSIX semantics, one owner-private marker:

`$HOME/.telegram_bridge_private_control/collect_passenger_runtime_evidence.once`

The marker contains only schema version, exact candidate SHA and expected WSGI SHA-256. It is created descriptor-relative with `O_NOFOLLOW|O_EXCL`, owner/mode/inode checks and `fsync`; an existing/concurrent marker is never overwritten.

## 6. Passenger application-process proof — exact canonical WSGI contract

The current final-candidate interface is the exact audited direct-hook WSGI shape below. It is intentionally narrow: no arbitrary environment reads, extra imports, conditions, definitions or top-level calls are permitted.

```python
from pathlib import Path
from bridge.app import application
from ops.passenger_evidence_hook import collect_if_armed

_here = Path(__file__).resolve()
collect_if_armed(app_root=_here.parent, wsgi_file=_here)

__all__ = ["application"]
```

An optional module docstring is allowed; after it, the six statements above must match structurally. `ops.candidate_runtime_preflight` independently validates this AST shape before arming, so an unrelated side-effectful wrapper cannot obtain `startup_import_contract_ok=true` merely by importing the right application symbol.

This direct collector is safe only with the **Round 2 exact-binding implementation**. Public Git cannot arm it. Without the owner-private one-shot marker it is inert. When armed, the marker already binds the exact Auditor-approved candidate SHA and expected `passenger_wsgi.py` SHA-256. The collector itself does not contact Telegram or other network services, never authorizes deployment, suppresses exception detail from application output and is fail-isolated from application availability.

On the real Passenger process, strong evidence requires all of:

- actual Python major/minor 3.11;
- actual Passenger-context signal;
- successful `bridge.app.application` import;
- actual `passenger_wsgi.py` SHA-256 exactly equal to the armed candidate WSGI SHA-256.

Only then are both reports written owner-private:

- `$HOME/.telegram_bridge_private_evidence/passenger_runtime_evidence.json`;
- `$HOME/.telegram_bridge_private_evidence/passenger_runtime_binding.json`.

The binding report records only exact candidate SHA, expected/actual WSGI hashes, runtime payload hash, tamper hash and `private_values_copied=false`. The marker is consumed only after both private reports are written. Context mismatch or hash mismatch leaves the marker for diagnosis/retry and never degrades application availability.

`collect_if_armed_from_bridge_app()` remains available as an alternate adapter for a future audited call-free WSGI design, but it is **not** the current final-candidate contract and must not be mixed with the direct-hook shape. Any future switch to that adapter requires DEV_A/DEV_B to change the canonical WSGI contract deliberately and rerun package, preflight, provenance, CI and Auditor gates on the new exact SHA.

## 7. Real non-production PREPARE proof

Before any production switch, DEV_A/DEV_B/Auditor must have exact evidence that the final packaged SHA has passed the actual existing `prepare_versioned_release()` pipeline under approved Python 3.11:

1. exact approved ref resolves to exact candidate SHA;
2. Git export/stage is built from that SHA;
3. clean versioned Python 3.11 environment is created;
4. runtime and any test locks install with `pip --require-hashes`;
5. compile/import succeeds;
6. full tests succeed;
7. prepared payload manifest is produced;
8. immutable code tree is sealed/read-only except audited persistent bindings;
9. production/private paths are not mutated.

A green source CI alone is insufficient. Absence of both `requirements.txt` and `requirements.lock` is no longer acceptable release evidence even though the legacy PREPARE helper would otherwise have no dependency input to install.

## 8. Restart/rollback private hooks

Lifecycle tooling accepts only fixed logical names `restart` and `rollback`, mapped by HOSTiQ to the actual managed Python App mechanism under the owner-private control root. Hooks must be owner-private, single-link, non-symlink and executable. DEV_B opens/executes them descriptor-safely, suppresses stdout/stderr, applies a bounded timeout and returns only status codes.

Rollback restores the transaction-bound last-known-good release, triggers the managed restart and preserves private Telegram session/config/state. Never put credentials in hook arguments, filenames or output.

## 9. Auditor-authorized live lifecycle

Only after exact package PREPARE + exact Auditor approval:

1. verify/create fresh transaction-bound backup;
2. stage exact approved SHA/artifact;
3. install the exact hash-locked dependencies in the approved Python 3.11 environment;
4. validate staged startup/import;
5. switch immutable code while preserving private bindings;
6. invoke fixed private `restart` hook; the exact audited WSGI startup then attempts the privately armed, SHA/WSGI-bound Passenger evidence collection;
7. verify that both owner-private Passenger runtime and binding reports exist and validate; no CLI/shell Python result may substitute;
8. verify exact running candidate identity;
9. validate meaningful `GET /health`, not HTTP 200 alone;
10. verify an unauthenticated protected route rejects without leak;
11. run only the harmless authenticated read probe `/api/v1/dialogs/list` with a server-private bearer reference;
12. if Telegram remains intentionally unconfigured, bootstrap mode may accept only the exact structured `telegram_backend_unconfigured` response without contacting Telegram;
13. verify serving/resume and private-state survival;
14. verify rollback/rollback-health. Mandatory failure rolls back; unhealthy rollback is `CRITICAL_ROLLBACK_FAILED`.

No send/reply/forward/send-files/K5 operation belongs to deployment smoke.

## 10. Support-return v2 exact binding

Use support-return schema v2 for the release-to-live gate. Legacy v1 remains parseable for historical compatibility but **cannot** satisfy `exact_candidate_runtime_binding` or the strong Passenger prerequisite.

V2 adds bounded `candidate_package` and `runtime_binding` summaries. Validation requires:

- runtime-binding candidate SHA == top-level candidate SHA;
- candidate-package WSGI SHA == runtime WSGI SHA == binding expected WSGI SHA == binding actual WSGI SHA;
- binding runtime-payload SHA == runtime report payload SHA;
- candidate package preflight is positive;
- binding is positive;
- all privacy flags are false.

Validate the private support-return and public-safe projection with:

```sh
python -m tools.validate_hostiq_support_return \
  --input PRIVATE_SUPPORT_RETURN.json \
  --output PUBLIC_READINESS.json
```

Expected stdout: `HOSTIQ_SUPPORT_RETURN_READY_FOR_AUDITOR` or `HOSTIQ_SUPPORT_RETURN_BLOCKED`.

Even a complete v2 package forces `independent_auditor_gate=BLOCKED_EXTERNAL`, `production_switch=BLOCKED_EXTERNAL`, and `promotion_authorized=false`. Developer tooling cannot self-authorize production.

## 11. Support contact rule

Do not send a duplicate support request while no newer HOSTiQ reply/action is needed. The prior accepted recovery baseline remains authoritative until replaced by newer first-hand evidence: 42 live files / 9 directories, 39 old-manifest matches, known changed startup, empty `install_server.sh` extra, HOSTiQ-private backup, remediated setup gate and zero temporary recovery jobs.

When the Auditor authorizes the next one-time action, support should be asked for exactly the approved SHA-bound steps above. No recurring cPanel operation by the user is part of the target design.

## Safety boundary

This document does not authorize merge, deploy, Passenger restart, Telegram authorization, live Telegram read/write, or K5. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains in force until the Auditor changes it.
