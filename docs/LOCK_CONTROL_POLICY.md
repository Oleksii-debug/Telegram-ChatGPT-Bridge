# Telegram Bridge — deployment lock control policy

The deployment transaction lock lives under the owner-controlled private control root and is protected with POSIX `O_NOFOLLOW`, regular-file/owner checks and `flock`. Current audited implementation normalizes an opened lock file to mode `0600` before the final permission check.

Independent audit Round 11 classifies pre-existing broad-mode normalization as LOW and non-production-blocking under the current private-control-root trust model. It is **not** claimed closed by the H8/M8 acceptance-harness changes.

Remaining L4 hardening work for the actual deployment entrypoint:

- define fail-closed behavior for a pre-existing broad-mode lock rather than silently normalizing an unexplained policy violation;
- reject pre-existing non-empty lock content;
- reject hardlinked lock topology (`st_nlink != 1`);
- preserve symlink/special-file/wrong-owner rejection;
- re-run real contention/crash-release and 100+ acquire/release tests after the implementation change.

Until that code-level hardening is applied and independently audited, the project should continue to report L4 as known LOW technical debt, not as closed evidence.
