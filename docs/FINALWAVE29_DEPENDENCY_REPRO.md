# FINALWAVE-29 package/dependency reproducibility boundary

This note is non-authorizing public engineering evidence for the Telegram Bridge release lane. It does not authorize merge, deployment, Passenger restart, Telegram authorization, live Telegram access, or K5.

## Exact truth model

The reviewed release model is `hash-locked-inputs+sealed-prepared-instance-v1`.

It proves, when PREPARE succeeds on an exact approved SHA, that:

1. `requirements.txt` contains the reviewed direct runtime input (`Telethon==1.44.0`).
2. `requirements.lock` contains the exact four-package runtime closure with SHA-256 hashes.
3. Python 3.11 is required by the deployment engine.
4. pip hash checking rejects a different artifact for a locked entry.
5. the generated prepared release, including its `.venv`, is hashed and sealed before any production switch.

It does **not** claim that recreating the virtualenv on a different machine or with a different Python/pip/build toolchain will produce byte-identical files.

## Telethon closure

The exact runtime closure remains:

- Telethon 1.44.0
- pyaes 1.6.1
- rsa 4.9.1
- pyasn1 0.6.4

The optional Telethon `cryptg` accelerator is intentionally excluded because it is not required for correctness.

## pyaes source-distribution boundary

The selected `pyaes==1.6.1` SHA-256 is the public PyPI `pyaes-1.6.1.tar.gz` source distribution. There is no reviewed PyPI wheel in the selected closure. Consequently a clean installation includes a local source-build step and therefore depends on the available Python/pip/setuptools build toolchain.

This is not hidden as a bit-reproducible build claim. The safe boundary is instead: hash-verify source input, build before switch, verify imports/versions, hash every prepared payload byte, seal the prepared tree, and only then make it eligible for later independently gated deployment.

## New executable verification

`tools/verify_dependency_repro.py` performs a real Python 3.11 non-live check:

1. validates the canonical Passenger/startup and dependency contracts;
2. downloads only the four locked artifacts with `pip download --require-hashes --no-deps`;
3. verifies that the downloaded SHA-256 set equals the lock exactly and that the selected pyaes artifact is the expected source distribution;
4. creates a clean venv;
5. forces installation offline with `PIP_NO_INDEX=1`, `--no-index`, `--find-links`, `--require-hashes`, `--no-deps`, and `--no-build-isolation` so the pyaes build cannot silently fetch build requirements;
6. verifies exact installed versions and imports;
7. repeats installation with a one-nibble wrong hash and requires rejection.

The tool records only public package/toolchain metadata and booleans. It never reads server private config, Telegram content, sessions, bearer values, setup secrets, or production state.

## Network/offline interpretation

The canonical deployment PREPARE currently allows network access during its normal hash-locked pip installation. That remains safe with respect to artifact substitution because pip hash mode is enforced, but it is not an offline-availability guarantee. The new verifier proves that the currently selected public artifacts can be fetched first and then installed with the installation phase fully offline on the tested Python 3.11 CI toolchain.

A future production package may optionally retain an audited artifact cache/wheelhouse to remove PyPI availability from the PREPARE critical path. Such a cache must itself be exact-hash bound and must not weaken the existing lock or prepared-payload verification.

## Private-file exclusion

The existing release package validator remains fail-closed for `.env*`, `var/`, private/session directories, `*.session`, session journals, credentials/token JSON, cookies/browser profiles, absolute/traversal paths, and unsafe canonical startup/dependency files. The dependency verifier operates only on the public lock and temporary public package artifacts.

## Remaining boundary

This work establishes source/package reproducibility evidence only. It is not production PASS. Final release readiness still requires the canonical recovery regression to be closed on the integration branch, exact-head full CI/PREPARE, independent review, and later candidate-bound HOSTiQ live lifecycle evidence under the project gates.
