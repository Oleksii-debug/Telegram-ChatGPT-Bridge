# DEV07 Security / Privacy / Secrets / Evidence hardening

Status: isolated SWARM security candidate. This document is non-secret evidence only. It does not authorize merge, deployment, Passenger restart, Telegram authorization, or live Telegram write.

## Threat model addressed in this slice

The repository is public, so tracked source, commit history, pull requests, Actions logs, and workflow behavior are treated as public attack surfaces. Security checks must fail closed when the scanner cannot prove that it inspected the bytes Git actually tracks or when a workflow can unexpectedly gain privileges or fetch mutable executable content.

This slice hardens two boundaries that were previously implicit:

1. **Git object / filesystem boundary for secret scanning.** A tracked path must not cause the scanner to follow a working-tree symlink, hardlink, special file, submodule/gitlink, unresolved index entry, or external Git LFS object. Normal tracked files are opened with `O_NOFOLLOW`, checked as single-link regular files owned by the current process owner, and bound to the same inode/device during the read. Git LFS pointers fail closed because scanning the pointer does not prove scanning the external object bytes.
2. **GitHub Actions supply-chain / privilege boundary.** Public-repository workflows are checked for immutable third-party action SHAs, read-only token permissions, safe checkout settings, full-history checkout when history scanning is claimed, absence of `pull_request_target`, absence of PR-triggered repository-secret use, absence of network pipe-to-interpreter commands, and absence of artifact upload/download without a separate privacy design review.

## Secret scanner behavior

`tools/secret_scan.py` retains the existing recursive ZIP/TAR inspection, nested archive limits, extension/signature mismatch detection, unsupported compressed/container fail-closed behavior, traversal/special-member rejection, current-tree scanning, full Git-history blob scanning, commit-message scanning, redacted finding output, and reviewed path+SHA-256 binary allowlist.

Additional credential aliases include common Telegram/Telethon environment naming variants. Findings report the alias/type and path, never the matched value.

Current-tree scanning now reads staged Git modes from `git ls-files --stage`:

- regular tracked files (`100644`/`100755`) are read through a no-follow file descriptor;
- tracked symlinks (`120000`) fail closed without dereferencing their targets;
- gitlinks/submodules (`160000`) fail closed rather than assuming external repository content was scanned;
- unresolved/non-zero Git index stages fail closed;
- unfamiliar Git modes fail closed.

A standard Git LFS pointer is rejected in both current-tree and history scans. The scanner deliberately does not print the pointer object identifier in its finding.

## Workflow security guard

`tools/workflow_security.py` is intentionally narrow and conservative. It does not attempt to become a general YAML policy engine. It validates the security properties required by this repository and rejects constructs outside the reviewed trust model when they affect privilege, mutable executable dependencies, secret exposure, or artifact movement.

The Recovery Guard executes this policy as an always-run security step and compiles the guard and its adversarial tests.

## Adversarial regression coverage

`tests/test_dev07_security.py` covers, without real credentials or private Telegram content:

- unpinned third-party Actions;
- write-capable workflow permissions;
- `pull_request_target`;
- PR workflow secret-context references with redacted findings;
- checkout credential persistence;
- shallow checkout while claiming full-history scanning;
- artifact transfer;
- network pipe-to-interpreter commands;
- local repository Actions as the permitted local exception;
- tracked symlink rejection without dereferencing an outside target;
- gitlink/submodule rejection;
- Git LFS current-tree rejection;
- Git LFS historical rejection after the pointer is removed from the current tree.

The pre-existing `tests/test_secret_scan.py` archive/polyglot/history matrix remains authoritative regression coverage and must stay green.

## Security truth boundary

A green scanner proves only the material and trust boundaries it actually inspected. It does **not** prove that an external Git LFS object, private HOSTiQ filesystem, private production backup, Telegram session, or live runtime contains no secret. Those surfaces require their own private, privacy-safe evidence path and must never be copied into this public repository merely to make scanning easier.

No production credential, private setup route, Telegram message/media content, private backup content, or user secret is introduced by this security slice.

## Remaining DEV07 work

The next security slices should continue from current canonical interfaces rather than duplicating feature owners. Highest-value pending review areas include descriptor-bound private-file verification across validation/use (TOCTOU resistance), SSRF/DNS-rebinding-safe URL policy if any outbound URL fetch surface becomes reachable, systematic log/error metadata redaction across all routes, and cross-process private-control/session lock topology regression.
