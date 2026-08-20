# Secret scan allowlist policy

The public repository guard is fail-closed. An allowlist is never a content-security or container-detection bypass.

`.secret-scan-allowlist.json` may be used only for a specifically reviewed non-secret binary object that cannot be UTF-8 text-inspected. Every entry requires exact repository-relative path, exact lowercase SHA-256 and a substantive review reason.

The allowlist never overrides prohibited filenames/path classes, private-key markers, setup-route patterns, protected assignments, archive/container recognition, archive-member policy, traversal/nesting/member/decompression limits, unsupported/corrupt container blocking or the hard text inspection limit.

Archive recognition is content-first. ZIP and TAR-family containers are recognized from their bytes even when renamed to generic extensions. Filename extension and content signature must agree when an archive-like extension is present. Renamed/nested supported containers are recursively inspected. Raw compressed streams and unsupported/corrupt/ambiguous containers fail closed. TAR symlink, hardlink, device, FIFO and other special members are rejected.

Secret assignment detection includes project-specific variables plus conservative common credential aliases for API identifiers/hashes/keys, session/string-session, 2FA/password, bearer/access/refresh tokens and client secrets. Findings are redacted. Exact approved placeholders and safe environment-reference forms remain allowed; mixed literal/template values are not placeholders.

Private operational artifacts such as `.env*`, sessions, databases, keys, logs, cookies and browser-profile material are prohibited from public publication and are deterministically excluded from production recovery candidates.

Never use the allowlist to publish an unknown production backup or baseline archive. Recovery material stays private/server-side until positive source-file policy, hardened scanning and manifest/hash verification all pass.
