# Telegram Bridge — deployment lock control policy

The deployment transaction lock lives under the owner-controlled private control root and is serialized with POSIX `flock`.

## DEV1 Round-2 closure candidate

The supported deployment entrypoint now treats a pre-existing lock as a control-plane artifact that must already satisfy policy. It no longer normalizes an unexplained lock with `fchmod(0600)`.

Before opening an existing lock, `ops/deploy_release.py` calls the side-effect-free policy validator and requires:

- regular file only; no symlink or special file;
- expected owner;
- exact mode `0600`;
- zero length;
- exactly one hard link (`st_nlink == 1`).

The entrypoint then opens with `O_NOFOLLOW` where supported and verifies the opened descriptor again. For a pre-existing file it also compares device/inode identity with the preflight object, so replacement between validation and open fails closed. No permission normalization or content truncation occurs on a rejected lock.

When no lock exists, creation uses `O_CREAT | O_EXCL` with requested mode `0600`. A race that inserts another object before creation therefore fails rather than accepting/repairing it.

After descriptor validation, the process acquires `LOCK_EX | LOCK_NB`; contention remains fail-closed. Unlock/close remains best-effort in the context-manager cleanup path.

## Regression requirements

DEV1 Round 2 adds direct supported-entrypoint tests for:

- valid empty private lock reuse for 128 acquire/release cycles;
- broad-mode rejection while proving mode is not normalized;
- non-empty rejection while proving content is not truncated;
- hardlink, symlink and FIFO rejection;
- inode replacement between preflight and open;
- existing real subprocess contention/crash-release regression retained from prior audit rounds.

This is a **Developer closure candidate**, not an independent PASS. The independent Auditor must re-run the exact-head suite and inspect the actual `ops/deploy_release.py` implementation before L4 can be marked closed.
