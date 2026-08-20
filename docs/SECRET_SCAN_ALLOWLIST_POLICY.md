# Secret scan allowlist policy

The public repository guard is fail-closed. An allowlist is never a content-security or container-detection bypass.

`.secret-scan-allowlist.json` may be used only for a specifically reviewed non-secret binary object that cannot be UTF-8 text-inspected. Every entry requires exact repository-relative path, exact lowercase SHA-256 and a substantive review reason.

The allowlist never overrides prohibited filenames/path classes, private-key markers, setup-route patterns, protected assignments, archive/container recognition, archive-member policy, traversal/nesting/member/decompression limits, unsupported/corrupt/ambiguous container blocking or the hard text inspection limit.

Archive recognition is parser-backed and precedes binary allowlisting. ZIP containers are recognized even when they contain a legal executable/self-extracting prefix and do not start with `PK` at byte zero. TAR-family containers are parser-probed as well. If the same blob is valid as more than one supported container type, it is treated as ambiguous/polyglot and fails closed. Filename extension and parsed content must agree when an archive-like extension is present.

Renamed/nested supported containers are recursively inspected within bounded depth/member/expanded-size limits. Raw compressed streams and unsupported/corrupt containers fail closed. TAR symlink, hardlink, device, FIFO and other non-regular members are rejected. ZIP Unix symlink/special-member metadata is also rejected rather than treated as an ordinary file.

Secret assignment detection includes project-specific variables plus conservative common credential aliases for API identifiers/hashes/keys, session/string-session, 2FA/password, bearer/access/refresh tokens and client secrets. Findings are redacted. Exact approved placeholders and safe environment-reference forms remain allowed; mixed literal/template values are not placeholders.

Private operational artifacts such as `.env*`, sessions, databases, keys, logs, cookies and browser-profile material are prohibited from public publication and are deterministically excluded from production recovery candidates.

For Git release construction, broad directory names such as `data`, `media`, `cache` or `uploads` are not by themselves grounds to silently remove tracked source. Exact audited source is preserved; tracked forbidden private/runtime files or explicit persistent-binding conflicts hard-fail the release instead.

Never use the allowlist to publish an unknown production backup or private baseline archive. Recovery backup material stays private/server-side; only a sanitized recovered source tree that passes the hardened scanner and exact manifest/reconciliation gates may proceed to independent audit.
