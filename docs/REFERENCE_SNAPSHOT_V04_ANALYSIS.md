# Reference snapshot v0.4 — analytical inventory only

`Telegram_Bridge_HOSTiQ_CURRENT_SANITIZED_v0.4.zip` is **REFERENCE / ANALYTICAL INPUT ONLY**. It is not a Drive/live first-hand authority, not a release artifact, and not deployment permission.

Safe archive facts: file count `44`; archive bytes `61554`; archive SHA-256 `f6c639effd2be00ebba1afbacc082faacd4bfc397a4ac9d056e4ef0eac50c6bf`.

Selected non-secret path/hash facts:
- `bridge/app.py` — 28172 bytes — SHA-256 `2ce44ff026dece52ac19ca6088bf720f4a9606b3a7c463add80f4fff502a919a`
- `bridge/telegram_backend.py` — 26691 bytes — SHA-256 `dd987b846afeee1bdf3e872c8decc860c3a02e4a165be04c3e37e418527c99e1`
- `bridge/security.py` — 8264 bytes — SHA-256 `a73a7d6e129f589c23d0e8809e35add8c98918bfb442d43d52f9b1d01d17c72a`
- `bridge/store.py` — 7888 bytes — SHA-256 `d9db22fd90ab722c4773b1d6e55c6931cb6e8b7809f4fe0ea0b17845eb8e2d71`
- `passenger_wsgi.py` — 104 bytes — SHA-256 `d0c47cd1b99d274c12eccb7e605a3aa968b071f549c508f2ff0d64db508eb419`
- `install_server.sh` — 0 bytes — SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- `tests/test_core.py` — 8735 bytes — SHA-256 `35610b660d3ac8b356384eacf5a2b98b5c8c8d50fb3c483c85cd60da4231fc3a`

Observed analytical structure includes a substantial `bridge/` application package, one test module, server/cron helpers and OpenAPI/self-test tooling. At the audited PR #2 fan-out anchor, `bridge/app.py` is absent from the PR line, so the snapshot may inform later interface reconciliation but cannot be silently imported as authoritative production source.

DEV1 does not publish runtime/private values from the snapshot and does not use the snapshot to claim HOSTiQ reconciliation, Passenger identity, deployed SHA or product PASS.
