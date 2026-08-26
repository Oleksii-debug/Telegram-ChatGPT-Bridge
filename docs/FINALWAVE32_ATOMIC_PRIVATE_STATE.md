# FINALWAVE-32 — atomic private-state filesystem survey

This document describes an isolated source/synthetic hardening candidate only. It does not authorize merge, HOSTiQ deployment, Passenger restart, Telegram authorization, live Telegram read/write, K5, or product PASS.

## Exact starting point

- Canonical source at branch creation: PR #9 `work3/integration-release-candidate` @ `84691967e5363bc4b88dfae97371d7bf329c105d`.
- Specialist branch: `finalwave26/32-atomic-private-writers`.
- Specialist PR: #84, base `work3/integration-release-candidate`.
- `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.

## Shared primitive added

`ops/atomic_private_state.py` provides two narrow POSIX primitives for small owner-private JSON state under an already existing private directory:

1. `atomic_replace_json()` — random exclusive temp, descriptor-walked parent, no symlink following, owner/mode/link/type validation of any existing target, temp file fsync, compare-and-rebind before descriptor-relative rename, directory fsync, post-rename inode/size/mode check, and final public-parent rebinding.
2. `atomic_create_json_once()` — the same safe temp construction followed by descriptor-relative no-clobber hard-link publication, directory fsync, temp unlink + second directory fsync, and exact final inode validation. It never replaces an existing one-shot marker.

A successful return means the file data and containing-directory metadata were fsynced on the same POSIX host/filesystem. It is not a claim of cross-host, storage-controller, or hardware power-loss durability.

The primitive is intentionally not wired blindly into every older writer in this isolated lane. Its own adversarial tests first establish the filesystem contract; canonical integration must then compose it with the transaction semantics owned by the relevant lane.

## Survey / disposition

### Deployment transaction lock — selected repair

Selected from FINALWAVE-31 PR #82 after exact-base review. The lock now binds the absolute private `control_root` through descriptor-relative ancestor walking, opens the lock leaf relative to that bound root, rejects symlink/hardlink/FIFO/socket/broad-mode/non-empty/wrong-owner topology, rebinds root+leaf after `flock`, and retains the supported single deployment entrypoint.

### Telegram session lock — selected stronger repair

Selected from FINALWAVE-24 PR #72. The session lock walks every ancestor with `O_DIRECTORY|O_NOFOLLOW`, requires an owner-private final parent, opens the leaf descriptor-relative, validates regular/current-owner/single-link/empty/exact-0600 topology, rebinds parent+leaf after `flock`, retains parent+lock descriptors for the held lifetime, and exposes continuity validation. Synthetic runtime tests cover read/write ownership across connect/effect/disconnect plus process-death recovery.

### Download checkpoint / private file registry / archive / upload snapshot — selected repair

Selected exact filesystem/media blobs from DEV04 PR #50 after confirming the PR #50-to-canonical divergence did not modify the four selected `bridge/` files. This adds deterministic stale-origin recovery, narrowed cleanup, post-move/registry integrity checks, descriptor-bound immutable upload snapshots, and ZIP process-loss recovery using a private pending marker + process lock.

### Immutable private evidence writer — existing incumbent retained

`ops/private_control.py` already uses descriptor-relative private-directory access, `O_NOFOLLOW|O_EXCL` random staging, fsync, no-clobber publication, parent fsync, and final owner/mode/link/inode validation. FINALWAVE-32 does not duplicate it.

### Audit append sink — existing incumbent retained, no new closure claim

The canonical audit sink is descriptor-bound and fsyncs each append. Audit retention/lifetime continuity is a separate specialist concern; FINALWAVE-32 does not claim to close that entire policy surface.

## Remaining same-domain HIGH items

1. **Deployment journal/status writer wiring.** Canonical `ops.release_guard.write_json_atomic()` still uses a predictable `*.tmp`, pathname `write_text/chmod/replace`, and no file/directory fsync. Deployment journal and best-effort status call this helper. The new shared primitive proves a candidate filesystem contract but is not yet transaction-semantics wiring.
2. **External approval consumption durability/topology.** Canonical one-shot consumption uses pathname parent creation/open and does not fsync the marker or directory. `atomic_create_json_once()` is the candidate primitive, but canonical consumption must be integrated deliberately with approval semantics and existing replay behavior.
3. **Active release symlink switching.** Canonical `atomic_switch_link()` / `restore_link()` use fixed `.next` / `.rollback` pathname temps and do not fsync the containing directory. Deployment recovery ownership must compose a safe descriptor-bound link publication primitive with transaction journal ordering; this lane does not independently rewrite that state machine.
4. **A01-11 recovery ordering.** The exact canonical failure loads current runtime-manifest state before reconciling an already-active transaction, so malformed/missing/currently changed manifest data can prevent durable ambiguity terminalization. FINALWAVE-26-01 PR #66 owns this recovery-semantic repair; it must be composed with FINALWAVE-31 lock hardening rather than overwritten.
5. **Final canonical provenance.** All selected specialist bytes remain non-authoritative until the canonical integrator explicitly provenance-accounts them and one stable resulting SHA passes the full same-SHA Recovery Guard, exact-ref PREPARE, both secret scans, and independent audit.

## Security boundary

No secret values, private Telegram content, production runtime state, credential collection, deployment, restart, or live Telegram operation is part of this specialist overlay.
