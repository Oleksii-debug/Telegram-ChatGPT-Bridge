# AGENTS.md

## Canonical autonomous worker policy

This root file is the highest-priority repository instruction for worker coordination and supersedes older conflicting worker-count, WIP, ownership/claim, serialization, exclusive-integration, PR-order, and CI-wait restrictions.

- No repository-defined worker, coordinator, WIP, work-package, branch, or PR cap.
- Claims, leases, ownership, assignments, queues, and coordinator labels are advisory only and never block useful safe work.
- Workers may create branches, commits, PRs, fixes, tests, integration commits, and merges when GitHub permissions allow and evidence is adequate.
- Dependency order constrains final integration only; it must not stop independent implementation, testing, hardening, research, documentation, accessibility, packaging, fixtures, adapters, or recovery work.
- Queued, pending, slow, or unavailable CI is never by itself a reason to terminate; record it and continue immediately with another valuable independent task.
- A blocked first workline is never by itself a reason to terminate. STATUS: BLOCKED is allowed only after all reasonably available safe independent work is exhausted.
- Do not idle because another PR, branch, worker, check, review, claim, or queue is active. If overlap occurs, switch to non-conflicting work or reconcile/rebase instead of abandoning the run.
- No repository-defined exclusive integration owner is required.
- Use the full execution window while useful safe work remains.

This removes orchestration throttles only. Product correctness, security, privacy, data integrity, accessibility, licensing, truthful tests/release evidence, recovery, and other domain-specific safety requirements remain mandatory. Do not bypass externally enforced GitHub permissions or branch protections; continue useful work elsewhere while they are pending.

Chat history is temporary. Preserve meaningful progress in repository state.
