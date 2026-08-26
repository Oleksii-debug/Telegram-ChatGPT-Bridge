# FINALWAVE-49 private-filesystem findings

Status: isolated specialist evidence. No merge/deploy authority.

Base audited: canonical PR #9 exact head `84691967e5363bc4b88dfae97371d7bf329c105d`.

## Fixed in this overlay

1. Deployment transaction lock acquisition no longer validates a private root and then opens `DEPLOYMENT_TRANSACTION.lock` through a later full pathname. The exact FINALWAVE-31 descriptor-bound lock repair is imported: no-follow ancestor walk, root/leaf inode binding, regular/current-owner/single-link/0600/empty policy, nonblocking special-file defense, post-flock rebinding, contention/SIGKILL/cycle tests.
2. Telegram session lock parent and leaf opens are descriptor-bound across every path component. The held lock exposes `assert_intact()` and revalidates public parent/leaf bindings after flock and before release.
3. Audit persistence no longer trusts a full parent pathname. The parent is walked descriptor-relatively, its inode is retained, the audit leaf is opened nonblocking/no-follow and validated on the actual fd, and leaf/parent bindings are rechecked after the append+fsync.
4. Reusable `ops.posix_fs` + `tests.posix_attack_harness` cover no-follow ancestor walking, regular-leaf validation, random descriptor-relative atomic replacement, inode rebinding, and descriptor-relative recursive cleanup that never follows symlinks.
5. Executable adversarial coverage includes symlink, hardlink, FIFO, UNIX socket, character device, wrong-owner model, broad mode, parent replacement, leaf replacement, rename race, lock contention/crash recovery inherited from FINALWAVE-31, and special-leaf cleanup.

## Proven/rejected during development

- A first generic descriptor read helper was rejected after adversarial FIFO testing showed that opening a FIFO before regular-file validation could block. The helper was removed; generic regular-leaf opens now force `O_NONBLOCK` before `fstat` type validation.
- Existing symlink/hardlink/special-file names can be atomically replaced through a bound parent without opening/following the old object; victim targets/peers remain unchanged in the synthetic tests.
- Recursive cleanup unlinks a symlink/special leaf rather than descending through it.

## Remaining HIGH integration findings

### H49-1 — mutable deployment JSON writer still uses a predictable pathname temp

`ops.release_guard.write_json_atomic()` still uses `<target>.tmp` via pathname `write_text()` followed by pathname `chmod()`/`replace()`. A same-UID actor with write authority in that directory can pre-position or race the temp leaf. The safe model is a random `O_EXCL|O_NOFOLLOW|O_NONBLOCK` temp opened relative to a bound parent fd, exact-fd write+fsync, target race policy, descriptor-relative rename, directory fsync, and parent/leaf rebinding. FINALWAVE-32 contains a useful standalone `ops.atomic_private_state` implementation/tests, but its exact head does not wire that primitive into the canonical deployment journal/status writer, so this overlay does not claim H49-1 closed.

### H49-2 — file registry/checkpoint SQLite pathname lifetime is not descriptor-bound

`bridge.storage.FileRecordStore` and `CheckpointStore` resolve database paths during construction but later call `sqlite3.connect(str(db_path))` repeatedly by pathname. Same-UID parent/db replacement after construction can redirect later connections. SQLite sidecar/WAL semantics mean this should not be papered over with a naive fd reopen. Canonical integration needs either a verified stable operator-owned database namespace outside application rename authority or a designed SQLite URI/fd strategy whose WAL/locking behavior is tested under Passenger concurrency and crash/restart.

### H49-3 — registry file add/get/delete still contain multi-open pathname windows

`FileRecordStore.add()` performs path topology validation, then separate pathname `stat()` and hash opens; `get()` performs separate resolve/lstat/hash operations; `delete()` deletes the DB row and later unlinks by pathname. These should be converted to descriptor-bound root/leaf opens with one verified inode for size/hash/registration and inode-aware deletion/reconciliation. Private serving is stronger because `bridge.file_access.open_verified_file()` reopens and hashes a descriptor before streaming, but registry mutation itself is not yet fully TOCTOU-closed.

### H49-4 — archive/download materialization and recovery remain mixed pathname/descriptor code

ZIP/download staging/final leaves still have pathname creation/cleanup/recovery seams. Random names reduce collision probability but are not an authorization boundary. FINALWAVE-32 adds useful process-loss and upload-snapshot work, but its archive lock and several cleanup decisions still use full pathnames and therefore are not imported as a blanket filesystem-security fix. Canonical integration should open ZIP/output leaves with `O_EXCL|O_NOFOLLOW|O_NONBLOCK` relative to stable directory fds, pass the opened file object to `zipfile`, verify inode identity before registration/rename, and perform cleanup via no-follow directory descriptors.

### H49-5 — post-entry same-UID root replacement needs a stable external lock namespace

A held fd remains bound to the displaced inode, but if an attacker with the same Unix UID can rename the entire public control/session root after the first process enters a critical section, a later independent process can discover a replacement pathname namespace. Rechecking detects the change at explicit boundaries but cannot make two independently discovered namespaces identical. Production therefore needs one operator-stable lock anchor outside application rename authority (or an equivalent supervisor-held fd boundary). This hosting property is not yet live-proven.

## Not a production PASS

This overlay is source/synthetic evidence only. It does not prove HOSTiQ Passenger Python identity, ownership/mount semantics, live deployed SHA, restart behavior, private session survival, rollback, Telegram behavior, or ChatGPT Action E2E. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
