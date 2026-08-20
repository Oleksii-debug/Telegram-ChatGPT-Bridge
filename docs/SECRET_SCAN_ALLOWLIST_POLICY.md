# Secret scan allowlist policy

The public repository guard is fail-closed. An allowlist is not a content-security bypass.

`.secret-scan-allowlist.json` may be used only for a specifically reviewed non-secret binary object that cannot be UTF-8 text-inspected. Every entry requires:

- exact repository-relative path;
- exact lowercase SHA-256 of the file bytes;
- a substantive human-readable review reason.

The allowlist never overrides any of the following:

- prohibited filenames or path classes;
- private-key markers;
- concrete setup-route patterns;
- secret-like assignments in dotenv, YAML, JSON, TOML-like or similar text;
- supported archive recursion and archive-member policy;
- archive path traversal, nesting, member-count or decompression-size limits;
- unsupported/corrupt archive fail-closed behavior;
- text objects beyond the hard inspection policy limit.

Supported ZIP and TAR-family containers are recursively inspected. Nested containers are inspected within bounded depth/member/expanded-size limits. Unsupported or corrupt archive/container formats remain blocked for public import.

Oversized text is scanned for protected content instead of being skipped. Mixed literal/template values such as `prefix-${HOME}-suffix` are not placeholders. Only exact approved placeholder grammars are exempt.

Never use the allowlist to publish an unknown production backup or baseline archive. Production recovery material remains private/server-side until deterministic exclusion, scanner checks and manifest/hash verification pass.
