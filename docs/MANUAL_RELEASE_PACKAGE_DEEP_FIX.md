# Supplemental manual release-package deep fix

Status: candidate-only support branch; **NO MERGE / NO DEPLOY** without the active DEV_A/Auditor workflow.

Base: accepted DEV_A integration candidate `30de1000672d18e2b17a4c4c91a0c583f7699071`.

This focused branch addresses the Auditor's active P1 packaging gap without modifying DEV_A, DEV_B, or DEV_C branches.

## Changes

- Adds the recovered HOSTiQ root startup contract `passenger_wsgi.py` with `from bridge.app import application`.
- Proves that normal package import resolves that target to the unified `bridge.integrated_app.application` surface.
- Keeps import/startup free of Telegram network activity and credential materialization.
- Adds `requirements.txt` with the direct Telegram runtime dependency pinned to Telethon 1.44.0.
- Adds `requirements.lock` with an exact hash-locked dependency closure for Telethon, pyaes, rsa, and pyasn1.
- Pins pyasn1 to 0.6.4 rather than vulnerable older 0.6.1/0.6.2 releases.
- Adds credential-free Passenger/dependency-envelope tests.
- Extends Recovery Guard to install the lock with `pip --require-hashes`, assert the unified Passenger target, compile the new envelope, and then run the existing full suite/security gates.

## Boundary discovered during review

The integrated code remains intentionally fail-closed unless production Telegram adapters and process-safe rate-limit/storage dependencies are injected. This branch does not fabricate Telegram authorization or live wiring evidence and does not enable a live write. Any further runtime factory/injection work must preserve private server-side credentials, the Telegram session lock, and the later Auditor live gate.

The sanitized HOSTiQ v0.4 package was consulted only as reference evidence for the historical `Telethon==1.44.0` dependency and Passenger import shape. Published package metadata/hashes were independently checked against PyPI before creating the lock.
