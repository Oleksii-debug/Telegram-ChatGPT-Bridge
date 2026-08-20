# Operations package — audit only

Nothing in this directory is authorized for production execution yet.

- `recovery_capture.py` is recovery-only: private backup, deterministic candidate, hardened scan, manifest/hash; no mail, no cron, no deployment.
- `release_guard.py` contains non-overridable protected-path, symlink, approval, atomic-switch and retention safety primitives.
- `deploy_release.py` is a future versioned deployer. It defaults to dry-run and requires an external exact-SHA approval plus private smoke hooks outside Git before `--execute` can proceed.

There is intentionally no active `.cpanel.yml` and no repository-controlled auto-deploy enable marker in this package.
