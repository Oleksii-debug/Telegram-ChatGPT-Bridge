# DEV1 contract hardening

This document covers synthetic/public control-plane contracts only. It is not product PASS and not live Telegram/HOSTiQ evidence.

## Public evidence threat model
Public evidence may contain reviewed provider IDs, numeric GitHub run/job IDs, reviewed suite IDs, exact Git/SHA-256 hashes, bounded counts, booleans and reviewed status enums. It must not contain raw Telegram text, chat/person/file names, filenames, paths, URLs/query strings, private notes, exception messages, subprocess text, credentials, setup routes, session material or private media content. External/private identifiers are hash-addressed.

Environment classes are a reviewed closed set. Evidence references are typed mappings; arbitrary prose references are rejected. Enum facts use reviewed semantic sets; unknown short ASCII labels and all Cyrillic/private-label-like public metadata fail closed.

## Rate limiting
`FixedWindowRateLimiter` is a deterministic, thread-safe **single-process synthetic model** with explicit duration, clock injection, rollover, backward-clock rejection, actor SHA-256 identifiers, safe retry-after metadata and bounded active actors. It is not process-safe and is not the production limiter; B8 stays `REAL_SOURCE_REQUIRED` until real shared/multi-process behavior is tested.

## Preview/idempotency
The synthetic store binds the hashed idempotency key to a SHA-256 fingerprint of preview key + action + target hash + payload hash. Mismatched reuse returns `IDEMPOTENCY_CONFLICT`. Committed retries are answered before preview expiry checks. Reservation is persisted before the simulated external write; restart while reserved returns `RECONCILE_REQUIRED`, preventing an automatic duplicate write. Exported state contains only hashed idempotency identifiers, hashes/status/timestamps and no payload body.

Detailed entries age into non-reusable hashed tombstones; pruning never re-enables the same idempotency key. This model is harness infrastructure only; real write adapters remain separately audited.

## Parallel integration
`tools/parallel_overlap_report.py` consumes already-discovered DEV2-DEV5 changed-path lists and produces deterministic overlap evidence without cherry-picking or mutating another lane. `ops/integration_interfaces.py` provides narrow read/media/write/runtime protocol boundaries to reduce cross-lane coupling.

## L4 lock-policy integration boundary

`ops/deployment_lock_policy.py` now supplies a fail-closed validator for pre-existing lock artifacts: exact `0600`, empty, single-link regular file, expected owner, no symlink/special type. The helper never chmod-normalizes an unexplained pre-existing file. DEV1 has not yet wired it into the large audited `ops/deploy_release.py` entrypoint in this checkpoint; therefore L4 is **advanced but not claimed closed** until the entrypoint calls the policy and the existing real contention/crash/100-cycle suite passes on that integrated code.

## Reference snapshot boundary

`docs/REFERENCE_SNAPSHOT_V04_ANALYSIS.md` records only safe archive/file-count/hash and selected path/hash facts for the project-provided v0.4 reference ZIP. It is non-authoritative analytical input and is not a deploy source.
