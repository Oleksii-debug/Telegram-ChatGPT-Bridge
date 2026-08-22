# DEV_C Release-to-Live QA Gate

This document records the credential-free, non-deploying DEV_C gate for the Release-to-Live round. It does not authorize merge, production deployment, Passenger restart, Telegram authorization, or live Telegram writes.

## Current factual blocker

At the start of this round the live DEV_A PR #9 head was `30de1000672d18e2b17a4c4c91a0c583f7699071`. The repository root did not contain `passenger_wsgi.py`, `requirements.txt`, or `requirements.lock`. Therefore this exact source candidate is an `INTERNAL_RELEASE_BLOCKER` for packaged production preparation even though its source-level CI is green.

## Package gate

DEV_C requires all of the following before a candidate can be classified `READY_FOR_PREPARE`:

- root `passenger_wsgi.py` exists and is a minimal import-safe WSGI shim;
- the shim exposes `bridge.app.application` exactly and performs no top-level calls or private-path/secret embedding;
- root `requirements.txt` and `requirements.lock` both exist;
- the lock uses exact `==` pins and SHA-256 hashes for every locked requirement;
- every direct runtime input requirement is represented in the lock;
- Telethon is represented in both the application dependency input and lock;
- no private runtime file (`.env`, session/database/credential material, or private-state directory) is present in the release artifact.

The existing deployment helper uses `pip install --require-hashes` when a lock exists. DEV_C separately tests dependency-envelope completeness because absence of both input and lock must not be mistaken for a dependency-free production application.

## PREPARE truth gate

The prepared-release metadata must bind the exact candidate SHA, approved ref, Python 3.11 identity, source manifest hash, non-null application requirements-lock hash, payload manifest hash, `passenger_wsgi.py` in the runtime-entry accounting, shared-external persistent state, and the no-write-bits immutable payload policy. Stale SHA, missing hash, or unaccounted startup file is a pre-live failure.

## DEV_B evidence interface

DEV_C independently mirrors the semantic boundary of DEV_B's one-time HOSTiQ support-return contract. Test simulation/reference evidence cannot self-promote to live status. A strong Passenger claim requires `APPLICATION_PROCESS`, Python 3.11, successful application import, and a Passenger-context signal. Exact reconciliation requires zero unreviewed differences and accounted startup. Public evidence must state that no private values/raw responses were copied.

## Live protocols

Machine-readable protocols are prepared for H1-H5 and K1-K5. Every protocol has `execute_now=false`. K5 additionally requires Independent Auditor write approval, a privately confirmed safe destination, and a fresh explicit user commit. No live Telegram send is performed by this QA package.

Human accessibility remains a separate gate. The keyboard/NVDA protocol covers initial focus, labels/roles, forward/reverse Tab order, Enter/Space activation, validation-error announcement, asynchronous status announcement, and keyboard-only recovery/cancel/retry. Source/static checks do not replace the human I1/I4/I6 run.

## Terminal rule

DEV_C may report `RELEASE_QA_GREEN` only after DEV_A publishes the final packaged SHA, DEV_C is stacked on that exact SHA with `behind_by=0`, the real non-live PREPARE path succeeds under Python 3.11, full regression and both secret scans are green, and no internal BLOCKER/HIGH defect remains. Remaining HOSTiQ/Telegram/Action/NVDA/K gates must stay explicitly external; green source QA is never product PASS.
