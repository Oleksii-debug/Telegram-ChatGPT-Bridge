# Secret scan allowlist policy

The repository secret guard fails closed on tracked archive/container files, binary/uninspectable files, and objects larger than 5,000,000 bytes.

An exception is allowed only when all of the following are reviewed together in `.secret-scan-allowlist.json`:

- exact repository-relative `path`;
- exact lowercase SHA-256 of the file bytes;
- non-empty human-readable `reason` explaining why the artifact is safe and necessary.

The allowlist does not override prohibited filenames, secret-like text assignments, private-key markers, or concrete setup-route detection. It exists only for intentionally reviewed non-secret artifacts that cannot be safely text-inspected by the guard.

Any changed artifact hash requires a new review. Never use the allowlist to import an unknown HOSTiQ baseline archive or backup. Production recovery material must first be sanitized outside the public repository, then inspected before publication.
