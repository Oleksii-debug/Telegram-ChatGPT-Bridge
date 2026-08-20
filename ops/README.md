# Operations package — two-stream audit boundary

Nothing in this directory authorizes an unapproved production promotion.

Stream A (GitHub/code):
- `secret_scan.py` guards current/public history, parser-probes supported containers before allowlisting, rejects SFX/polyglot ambiguity and ZIP/TAR special members.
- `release_guard.py` owns topology, exact audited payload rules, shared persistent-state bindings, private control-plane trust, approval checks, atomic switching and retention.
- `deploy_release.py` implements deterministic **PREPARE -> independent AUDIT/APPROVAL -> EXECUTE**. PREPARE builds/tests an immutable exact payload and stable manifest; EXECUTE verifies that exact artifact rather than rebuilding it.

Stream B (HOSTiQ/live):
- `recovery_capture.py` performs recovery-only backup/sanitized candidate generation; no mail, cron or deployment.
- `baseline_reconcile.py` produces hash-only non-secret recovered-production vs exact-Git-ref reconciliation evidence.
- `runtime_evidence.py` collects only non-secret facts from the actual application/Passenger Python runtime. It never serializes environment values, Telegram credentials, sessions or request data.

Future live execution requires a trusted private control root outside Git with runtime manifest, short-lived single-use approval, quiesce, resume/unquiesce, restart/reload, running-SHA identity, unauthenticated smoke and authenticated smoke hooks. Success cannot become `DEPLOYED` until resume succeeds. Rollback/pre-live recovery also require explicit resume.

Immutable code + `.venv` switch together; mutable Telegram/session/runtime/database state remains in one shared private root and is not reverted merely because code is rolled back.

There is intentionally no active `.cpanel.yml` and no repository-controlled auto-deploy enable marker in this package.
