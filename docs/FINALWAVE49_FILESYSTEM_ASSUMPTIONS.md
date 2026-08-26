# FINALWAVE-49 POSIX filesystem threat model

This document records the filesystem assumptions and fail-closed boundaries for the FINALWAVE-49 specialist overlay. It is engineering evidence only and does not authorize merge or deployment.

## Required platform primitives

The hardened private-state paths require a POSIX runtime with `O_DIRECTORY`, `O_NOFOLLOW`, descriptor-relative `open/stat/unlink/rmdir/replace`, `fstat`, and `flock` where locking is used. Security-sensitive helpers fail closed when the required primitives are unavailable. HOSTiQ production must therefore be verified on the actual Python 3.11 Passenger application process before this overlay can be treated as deployable evidence.

## Ownership and permissions

Private control/session/audit directories are expected to be owned by the application account and not group/world accessible. Existing broad-mode or wrong-owner lock/audit leaves are rejected rather than normalized. Lock files must be regular, owner-only, single-link, and empty. Private audit leaves must be regular, owner-only, and single-link.

## Descriptor binding

Security decisions are made from the descriptor that is actually used. Ancestor directories are walked from `/` without following symlink components. Parent and leaf pathname bindings are rechecked at security boundaries so rename/replacement does not silently redirect writes or create an accepted lock on a different inode.

For atomic replacement helpers, a random `O_EXCL|O_NOFOLLOW` temporary leaf is created relative to an already-open parent descriptor, the exact temporary descriptor is written and fsynced, rename occurs descriptor-relatively, and the public parent binding is checked again. No predictable `.tmp` pathname is trusted.

## Special files and hardlinks

Security-sensitive leaf opens add `O_NONBLOCK` before type validation so a FIFO cannot hang the process. Symlink, FIFO, socket, device, and other non-regular lock/audit leaves fail closed. Hardlinked lock/audit leaves fail closed. Descriptor-relative cleanup treats symlinks and special leaves as leaf directory entries and never follows them recursively.

## Cleanup

Recursive cleanup must be descriptor-relative and no-follow. A directory entry is opened as a directory only after `lstat`-equivalent no-follow metadata and `O_DIRECTORY|O_NOFOLLOW`; its public name is rechecked against the opened inode before `rmdir`. A symlink is unlinked as a symlink, never traversed into its target.

## Same-UID rename authority limitation

A process that has the same Unix UID and unrestricted rename authority over every ancestor of the application control tree can create a new pathname namespace after another process has already entered a critical section. A descriptor keeps the first process bound to the original inode, but POSIX alone cannot force a later independent process to rediscover that displaced inode through the replaced public pathname.

Therefore production must provide at least one stable lock namespace outside application-controlled rename authority (for example an operator-owned stable parent/control anchor), or deployment/session callers must prove an equivalent supervisor-held descriptor boundary. Until that hosting property is independently verified, adversarial same-UID post-entry root replacement remains a HIGH integration concern rather than a claimed closed production threat.

## Durability

The project deployment contract remains process-loss recovery on the same POSIX host/filesystem unless a narrower helper explicitly fsyncs the file and containing directory. No code in this overlay claims cross-host or storage-hardware power-loss durability.

## Production boundary

Synthetic/source tests cannot prove HOSTiQ ownership, mount semantics, actual Passenger Python runtime, deployed SHA, private session preservation, or live restart/rollback behavior. These remain independent deployment evidence requirements. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged by this filesystem work.
