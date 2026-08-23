# DEV07 Security / Privacy / Secrets / Evidence hardening

Status: isolated SWARM security candidate. This document is non-secret evidence only. It does not authorize merge, deployment, Passenger restart, Telegram authorization, or live Telegram write.

## Threat model addressed

The repository is public, so tracked source, commit history, pull requests, Actions logs, workflow behavior and any cross-run CI state are treated as public attack surfaces. Security checks must fail closed when they cannot prove which bytes or privilege boundary they inspected.

This DEV07 line hardens three boundaries:

1. **Git object / filesystem boundary for secret scanning.** A tracked path must not make the scanner follow a working-tree symlink, hardlink, special file, submodule/gitlink, unresolved index entry, external Git LFS object or path that changes while it is inspected.
2. **GitHub Actions supply-chain / privilege boundary.** Public tracked CI must use immutable executable dependencies, minimum token authority, an exact checkout of the reviewed repository state and no unreviewed secret/artifact/cache/self-hosted/environment channels.
3. **Truthful outbound-network boundary.** A network client is not labeled a general SSRF control merely because it uses HTTPS. The current Passenger evidence probe was inspected separately and its presently reachable endpoint policy is recorded below.

## Secret scanner behavior

`tools/secret_scan.py` retains recursive ZIP/TAR inspection, nested archive limits, extension/signature mismatch detection, unsupported compressed/container fail-closed behavior, traversal/special-member rejection, current-tree scanning, full Git-history blob scanning, commit-message scanning, redacted finding output and reviewed path+SHA-256 binary allowlisting.

Additional credential aliases cover common Telegram/Telethon environment naming variants. Findings report only the alias/type and path, never the matched value.

Current-tree scanning reads staged Git modes from `git ls-files --stage`:

- regular tracked files (`100644`/`100755`) are read through a no-follow descriptor and topology/inode checks;
- tracked symlinks (`120000`) fail closed without dereferencing targets;
- gitlinks/submodules (`160000`) fail closed rather than assuming external repository content was scanned;
- unresolved/non-zero index stages fail closed;
- unfamiliar Git modes fail closed;
- Git LFS pointers fail closed in current and historical objects because the external object bytes were not proven inspected.

The scanner deliberately does not print secret values or Git LFS object identifiers in findings.

## Workflow security policy v2

`tools/workflow_security.py` is intentionally a narrow, conservative policy guard for this public repository rather than a general YAML policy engine.

Tracked CI must satisfy all of the following:

- exactly one explicit top-level permissions stanza whose only grant is `contents: read`;
- no job-level or compact-map permission override;
- no `pull_request_target`, `workflow_run`, `repository_dispatch`, `issue_comment` or `workflow_call` trigger without a separate security design review;
- no `self-hosted` runner;
- no GitHub `environment:` binding;
- no `${{ secrets.* }}` context and no explicit `${{ github.token }}` exposure in tracked public CI;
- third-party Actions pinned to an immutable 40-hex commit; Docker actions pinned to an immutable SHA-256 digest;
- checkout explicitly sets `persist-credentials: false`, `clean: true`, `lfs: false`, `submodules: false`, plus `fetch-depth: 0` whenever full-history scanning is claimed;
- checkout may not override `ref`, `repository`, `path`, `token`, `ssh-key` or `ssh-known-hosts`;
- artifact upload/download requires a separate privacy design review;
- cache restore/save requires a separate cache-poisoning review;
- network pipe-to-interpreter installation commands fail closed.

The workflow directory and workflow files themselves are also checked as owner-controlled, non-symlink, non-group/world-writable objects. Workflow files are opened with `O_NOFOLLOW`, single-link/ownership checks, and pre/post descriptor identity, size, mtime and ctime binding so a concurrent replacement/modification is not silently accepted as the inspected file.

The Recovery Guard executes this policy and the DEV07 adversarial suite before canonical provenance. That ordering is deliberate: an isolated specialist PR may be rejected by DEV01's exact provenance allowlist, but its security checks must still execute and publish bounded evidence.

## Adversarial regression coverage

`tests/test_dev07_security.py`, together with the inherited secret-scanner matrix, covers without real credentials or private Telegram content:

- mutable/unpinned Actions;
- write/inline/job-level token permission expansion;
- high-risk event triggers;
- secret and explicit GitHub-token contexts with redacted findings;
- self-hosted runners and environment bindings;
- checkout credential persistence, shallow history, dirty checkout, LFS/submodule enablement and ref/repository/token overrides;
- artifact and cache channels;
- network pipe-to-interpreter commands;
- workflow-file permission and directory-symlink topology failures;
- tracked symlink and gitlink/submodule rejection;
- Git LFS current-tree and historical rejection;
- inherited archive/polyglot/history/commit-message secret scanning.

## Outbound URL / SSRF / DNS-rebinding review

Fresh inspection of current canonical `ops/passenger_probe.py` found a narrowly constrained outbound request surface rather than a general user-controlled URL fetcher:

- endpoint validation requires `https`;
- hostname is exactly `tg-api.rukadopomogy.org.ua`;
- port is absent or 443;
- path is exactly `/health`;
- query, fragment, username and password are forbidden;
- redirects are disabled and 301/302/303/307/308 fail closed;
- challenge material is only placed on that single initial request and is not included in public result evidence.

Under the current source contract this substantially constrains classic user-controlled SSRF and redirect-based credential forwarding. This is **not** a claim of DNS pinning: standard name resolution still occurs in the HTTP stack. DNS rebinding/address-class controls must be revisited if the endpoint ever becomes configurable, if requests can target arbitrary URLs/hosts, if redirects are re-enabled, or if the transport trust model changes. DEV07 therefore records the current exact-host surface as reviewed rather than inventing a broader SSRF implementation that the product does not presently need.

## Cross-lane TOCTOU boundary

DEV04 now owns substantial media/download/storage/ZIP descriptor and crash-window hardening in its specialist line. DEV07 does not duplicate that implementation. Security review still tracks the final file-serving path as a cross-lane boundary because validation of a registered private file and later HTTP streaming must remain bound across validation/use. Any concrete remaining race is to be supplied as an isolated security finding/oracle for DEV04/DEV01 rather than a competing media subsystem.

## Security truth boundary

A green public scanner proves only material and trust boundaries it actually inspected. It does **not** prove that an external Git LFS object, private HOSTiQ filesystem, private production backup, Telegram session or live runtime contains no secret. Those require separate private, privacy-safe evidence paths and must never be copied into this public repository merely to make scanning easier.

No production credential, private setup route, Telegram message/media content, private backup content or user secret is introduced by this security line.

## Remaining DEV07 work

Highest-value pending security review after this slice:

- cross-route error/log/private-metadata redaction and bounded public-error schemas;
- final private-file serving validation/use binding after DEV04/DEV01 integration;
- private-control/session/deployment lock ownership, permissions, topology and race regressions against the moving canonical runtime;
- re-check outbound URL/DNS/address policy if any new configurable fetch surface appears;
- revalidate all security gates on the next exact canonical parent without weakening canonical provenance.
