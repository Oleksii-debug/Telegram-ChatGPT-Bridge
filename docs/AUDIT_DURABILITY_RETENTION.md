# Audit durability and retention contract

This document defines the non-secret, POSIX-host durability boundary for the metadata-only `AuditLog` sink.

## Security boundary

The audit parent must be an owner-controlled directory with exact mode `0700`. The current leaf, its process-shared lock, and every rotated archive must be regular files owned by the current UID, single-linked, and exact mode `0600`. Opens are descriptor-relative and use `O_NOFOLLOW`. The parent device/inode is bound for the lifetime of an `AuditLog` instance.

Audit records are metadata only. Unknown fields are dropped. Event names and string-valued allowlisted fields must be short identifier-like ASCII values; prose, message bodies, filenames, private Telegram content, credentials, bearer values, setup routes and arbitrary exception text are not audit-record inputs. Integer and boolean metadata remain bounded.

## Append and concurrency

File-backed audit logging requires POSIX `flock`. All processes using the same audit path serialize through a private sibling lock file. The lock inode is bound for each `AuditLog` instance and revalidated after lock acquisition. The current audit leaf device/inode is also bound after first observation. A direct same-owner replacement of the current leaf or lock is rejected rather than silently adopted.

Each record is appended through a verified descriptor, followed by `fsync`, then path/descriptor continuity is revalidated. A partial write, `fsync` error, disk-full error, or topology change attempts to truncate the descriptor back to the pre-record size and `fsync` that rollback. If rollback cannot be proven, the sink raises a stronger durability error rather than claiming the record was absent or committed.

## Rotation and retention

Rotation is serialized under the same process-shared lock. Before rotation the current segment is `fsync`ed. The current leaf is then renamed descriptor-relatively to a monotonically numbered archive, and the parent directory is `fsync`ed before a new current leaf is created with `O_EXCL|O_NOFOLLOW`, mode `0600`, then `fsync`ed together with the parent.

If new-current creation fails after the rename, the prior evidence remains in the durable rotated archive. A later retry in the same process, or a clean restart, can recreate the current leaf. The triggering record is not claimed committed unless its append and `fsync` complete.

Retention removes only the oldest validated rotated archives and never the current segment. Pruning occurs only after the new current record is durable. If archive enumeration/topology or deletion is uncertain, cleanup degrades to retention hold: extra old evidence may remain, but uncertain evidence is not deleted to satisfy a quota.

Defaults are an 8 MiB current segment, 16 retained rotated segments, and a 2,048-event in-memory observation cache. The hard bounds are 1 GiB per current segment, 64 rotated segments, and 100,000 in-memory events. Passing `max_file_bytes=None` disables disk rotation for explicit test/compatibility use; production integration should use a bounded value.

## Proven scope and non-claims

The executable FINALWAVE-23 regressions cover 100,000 in-memory events; 5,000 disk events across restart and rotation; concurrent multi-process append; direct same-owner leaf and lock replacement; symlink archive namespace attacks; partial `ENOSPC`; `fsync` failure; leaf replacement during append; rotation-create failure; and bounded archive pruning.

This is same-host/POSIX-filesystem durability, not a claim of power-loss guarantees beyond the filesystem semantics of successful `fsync` calls. It is also not cryptographic tamper evidence against a malicious actor that already has arbitrary write authority as the same Unix UID while all bridge processes are stopped. That threat requires a separate append-only/remote/WORM or keyed integrity design and is not implied by Unix ownership and mode checks.
