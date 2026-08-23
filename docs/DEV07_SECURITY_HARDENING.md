# DEV07 Security / Privacy / Secrets / Evidence hardening

Status: isolated SWARM security candidate. This document is non-secret evidence only. It does not authorize merge, deployment, Passenger restart, Telegram authorization, or live Telegram write.

## Threat model addressed

The repository is public, so tracked source, commit history, pull requests, Actions logs, workflow behavior and cross-run CI state are public attack surfaces. Private runtime state must remain outside those surfaces. Security checks fail closed when they cannot prove which bytes, inode, error metadata or privilege boundary they inspected.

This DEV07 line hardens six boundaries:

1. **Git object / filesystem boundary for secret scanning.** Tracked symlinks, gitlinks, unresolved index entries, Git LFS pointers, unsafe topology and read-time inode races fail closed.
2. **GitHub Actions supply-chain / privilege boundary.** Public CI is constrained to immutable dependencies, read-only token authority, reviewed checkout semantics and no unreviewed secret/artifact/cache/self-hosted/environment channels.
3. **Private audit-log filesystem boundary.** The audit destination is descriptor-bound and rejects symlink/hardlink/FIFO/permission/parent-replacement attacks.
4. **Telegram session-lock filesystem boundary.** The private session lock is opened relative to a no-symlink directory-descriptor walk and parent/leaf identity is rebound after flock acquisition.
5. **Public write-error metadata boundary.** Unknown exceptions may not export arbitrary `.code`, `.status`, retry metadata or exception text. Only exact reviewed Telegram contract errors cross the public boundary.
6. **Truthful outbound-network boundary.** The current Passenger evidence probe is reviewed as a narrowly constrained exact-host HTTPS probe, not mislabeled as a general DNS-pinning/SSRF subsystem.

## Secret scanner behavior

`tools/secret_scan.py` retains recursive ZIP/TAR inspection, nested archive limits, extension/signature mismatch detection, unsupported compressed/container fail-closed behavior, traversal/special-member rejection, current-tree scanning, full Git-history blob scanning, commit-message scanning, value-redacted findings and reviewed path+SHA-256 binary allowlisting.

Current-tree scanning reads staged Git modes from `git ls-files --stage`:

- regular tracked files (`100644`/`100755`) are read through a no-follow descriptor and topology/inode checks;
- tracked symlinks (`120000`) fail closed without dereferencing targets;
- gitlinks/submodules (`160000`) fail closed rather than assuming external repository content was scanned;
- unresolved/non-zero index stages and unfamiliar Git modes fail closed;
- Git LFS pointers fail closed in current and historical objects because the external object bytes were not proven inspected.

Additional credential aliases cover common Telegram/Telethon environment naming variants. Findings report only bounded type/path evidence, never matched secret values or Git LFS object identifiers.

## Workflow security policy v2

`tools/workflow_security.py` is intentionally a conservative policy guard for this public repository. Tracked CI must satisfy all of the following:

- exactly one explicit top-level permissions stanza whose only grant is `contents: read`;
- no job-level or compact-map permission override;
- no `pull_request_target`, `workflow_run`, `repository_dispatch`, `issue_comment` or `workflow_call` trigger without separate review;
- no `self-hosted` runner or GitHub `environment:` binding;
- no `${{ secrets.* }}` context and no explicit `${{ github.token }}` exposure;
- third-party Actions pinned to immutable 40-hex commits and Docker actions to immutable SHA-256 digests;
- checkout explicitly uses `persist-credentials: false`, `clean: true`, `lfs: false`, `submodules: false`, and `fetch-depth: 0` whenever full-history scanning is claimed;
- checkout may not override `ref`, `repository`, `path`, `token`, `ssh-key` or `ssh-known-hosts`;
- artifact and cache channels require separate privacy/cache-poisoning review;
- network pipe-to-interpreter installation commands fail closed.

Workflow directory/files are also checked for ownership, topology and permissions. Workflow files are read with `O_NOFOLLOW`, single-link/ownership checks and pre/post descriptor identity/size/time binding.

The Recovery Guard executes the DEV07 policy and adversarial suite before canonical provenance. This is deliberate: an isolated specialist PR can be correctly rejected by DEV01 provenance while still producing bounded security evidence.

## Descriptor-bound private audit sink

`bridge.audit.AuditLog` accepts only bounded metadata fields and drops message bodies, server paths and unknown/private fields. The filesystem sink additionally requires:

- owner-controlled real parent with exact mode `0700`;
- captured/revalidated parent device+inode identity;
- relative leaf open through the verified parent descriptor;
- `O_NOFOLLOW` and `O_NONBLOCK`;
- single-link regular file, current UID, exact mode `0600`;
- descriptor write + `fsync` before the event is accepted in memory.

Symlink, hardlink, FIFO, broad-mode leaf, unsafe parent and parent-replacement attacks fail closed before audit bytes are written.

## Descriptor-bound Telegram session lock

The previous canonical lock validated `lock_path.parent` by pathname and then reopened the leaf through the full pathname. `O_NOFOLLOW` on the final leaf does not protect parent/ancestor components.

The DEV07 candidate now:

- requires POSIX `O_DIRECTORY` and `O_NOFOLLOW` primitives;
- uses a lexical absolute path without resolving away symlink evidence;
- walks every parent component descriptor-relatively from `/`, rejects symlink/non-directory components and binds observed/opened directory inode identity;
- creates only the missing final private parent, not arbitrary missing ancestor trees;
- requires the final parent to be current-EUID owned, owner-private, owner-writable and owner-searchable;
- opens the lock leaf with `dir_fd` + `O_NOFOLLOW`;
- preserves regular/current-owner/single-link/empty/exact-`0600` leaf checks and bounded flock timeout;
- after obtaining flock, re-walks the public parent name and requires the same device/inode, then requires the named leaf inside the bound directory to still match the locked descriptor inode.

This closes parent redirection between validation and leaf open and detects deterministic parent/leaf replacement around acquisition. It does not claim protection against a malicious same-UID process that can continuously mutate the private runtime after all checks; production still relies on the owner-private account boundary.

## Public write-error privacy

`structured_write_error()` previously accepted any exception carrying string `.code` and integer `.status` attributes. That was a metadata exfiltration channel: a foreign/faulty adapter could place private material in `.code`, which would then be returned through the API and written into bounded audit metadata.

The DEV07 candidate removes generic attribute trust:

- `EndpointPolicyError` and `WriteSafetyError` remain trusted internal contracts;
- `TelegramContractError` is accepted only when its code is in an exact reviewed allowlist and its status matches the exact expected status;
- only reviewed `telegram_flood_wait` may expose bounded retry metadata;
- unknown exception types, forged Telegram codes, mismatched statuses and arbitrary retry fields collapse to `internal_bridge_error` / HTTP 500 without reflecting the supplied value;
- an AST regression requires every `TelegramContractError` code emitted by the adapter to remain a literal reviewed contract and to match the public allowlist exactly.

## Adversarial regression coverage

DEV07 specialist tests, inherited scanner tests and selected canonical application/write tests cover without real credentials or private Telegram content:

- mutable/unpinned Actions, permission expansion and high-risk workflow triggers;
- secret/github-token contexts with value-redacted findings;
- self-hosted runners, environments, unsafe checkout settings, artifact/cache channels and pipe-to-interpreter commands;
- workflow topology/permission failures;
- tracked symlink/gitlink/Git LFS and nested archive/polyglot/history/commit-message secret scanning;
- audit symlink/hardlink/FIFO/broad-mode/unsafe-parent/parent-replacement failures;
- session-lock direct symlink parent, symlink ancestor, parent replacement, leaf replacement, mutual exclusion and inherited DEV4 session-lock behavior;
- foreign exception metadata suppression, safe-code spoof rejection, forged Telegram contract rejection, status binding and bounded FloodWait metadata;
- exact adapter public-error allowlist parity;
- inherited read/auth/error/privacy and unified write safety regressions.

## Outbound URL / SSRF / DNS-rebinding review

Current canonical `ops/passenger_probe.py` is a narrow outbound request surface:

- `https` only;
- hostname exactly `tg-api.rukadopomogy.org.ua`;
- absent or 443 port only;
- path exactly `/health`;
- query, fragment, username and password forbidden;
- redirects disabled and redirect statuses fail closed;
- challenge material is sent only on that initial exact request and excluded from public result evidence.

This substantially constrains classic user-controlled SSRF and redirect credential forwarding. It is **not** a DNS-pinning claim. Address-class/DNS-rebinding controls must be revisited if the endpoint becomes configurable, arbitrary URLs/hosts become reachable, redirects are enabled, or the transport trust model changes.

## DEV04 private-file integration review

Canonical `0809e2cf075ec2b2201b8638b1fdfad928d00de9` integrates DEV04 media/private-serving hardening. `bridge/file_access.py` now opens a registered private file through owner-private directory descriptors with no-follow flags, hashes/revalidates the exact opened descriptor, and returns that pinned handle. The WSGI file route streams from that already-verified descriptor and closes it on normal completion or `start_response` failure.

DEV04 tests cover leaf replacement after descriptor acquisition, symlink leaf, hardlink topology, broad root/nested directories and WSGI descriptor streaming. DEV07 therefore does not recreate the media subsystem or the already-integrated validation/use binding.

Live HOSTiQ ownership/mode evidence remains a separate production evidence question; source tests do not prove the private production directory has the expected topology.

## Cross-lane deployment-lock finding

Canonical deployment code validates a pre-existing lock, captures its inode and then uses `os.open(path, O_NOFOLLOW)` through the full pathname. Canonical topology helpers reject existing symlink/alias roots, and the leaf inode is checked after open, but a directory replacement race between root validation and the full-path open remains a class worth hardening descriptor-relatively.

Because `ops/deploy_release.py` is DEV02 release-engine ownership, DEV07 does not create a competing deploy implementation in this slice. This is retained as a cross-lane security finding/oracle for DEV02/DEV01 semantic integration.

## Security truth boundary

A green public scanner proves only the material and trust boundaries it actually inspected. It does **not** prove that an external Git LFS object, private HOSTiQ filesystem, private production backup, Telegram session or live runtime contains no secret. Those require separate privacy-safe private evidence paths and must never be copied into this public repository merely to make scanning easier.

No production credential, private setup route, Telegram message/media content, private backup content or user secret is introduced by this security line.

## Remaining DEV07 work

Highest-value pending review after this slice:

- give DEV02/DEV01 a minimal deployment-lock directory-descriptor oracle/finding without taking release-engine ownership;
- inspect remaining private-control/state writers for path-based replacement windows not already covered by `ops.private_control` descriptor primitives;
- re-check public error/privacy contracts whenever new adapter/route error classes appear;
- re-check outbound URL/DNS/address policy if any configurable/general fetch surface appears;
- revalidate security gates on each exact canonical parent without weakening canonical provenance.
