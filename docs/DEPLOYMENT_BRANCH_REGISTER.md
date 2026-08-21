# Deployment-capable branch register

This file exists so deployment-capable public work cannot silently exist outside the audit handoff.

## Active audited lines

- `recovery/bootstrap-legacy-candidate` — guardrail/base recovery line; PR #1; no production application baseline.
- `recovery/deployment-package-hardening` — dependent deployment/recovery hardening line; must be audited through its own draft PR before any use.

## Superseded public line

- `bootstrap/cpanel-api-automation` — legacy/out-of-band deployment scaffold discovered by the Auditor. It is explicitly superseded and non-deployable. Its head is retained for history/traceability, but `.cpanel.yml` and executable server actions must not be used. The safe replacement is the dependent audited deployment-package branch above.

Any future branch that can modify production, install cron, call cPanel deployment hooks, switch release paths or run server recovery must be added here and in the Drive CURRENT_HANDOFF before execution.
