# Operations package — audit only

Nothing in this directory is authorized for production execution yet.

- `recovery_capture.py` is recovery-only: topology validation, private backup first, conservative source candidate, hardened scan and manifest/hash; no mail, cron or deployment.
- `release_guard.py` owns protected/private path policy, central topology validation, shared persistent-state bindings, approval provenance/one-time consumption, atomic release switching and pair-aware retention.
- `deploy_release.py` is a future versioned deployer. It defaults to dry-run. Code+.venv are immutable per release while mutable Telegram/session/runtime/database/private state remains in one shared private root outside releases.
- Future execution requires approved Python 3.11, external exact-provenance approval, quiesce, restart/reload, running-release identity, unauthenticated smoke and authenticated smoke hooks under a private control root outside Git.
- Rollback switches only immutable code+.venv; shared mutable state is not reverted. Passenger/WSGI restart plus previous-SHA identity and rollback smoke are mandatory.

There is intentionally no active `.cpanel.yml` and no repository-controlled auto-deploy enable marker in this package.
