# DEV09 SWARM QA — exact-current checkpoint

Role: DEV09 independent engineering QA. This layer is QA-only and does not authorize merge, deploy, Passenger restart, Telegram authorization, or live Telegram write.

Exact canonical parent: `cb058b74fcb9fc8afdff52a294b94b54a1c36b71` on `work3/integration-release-candidate`.

## Current result

Canonical integration provenance is now reconciled and green on this exact parent. Recovery Guard #353 reaches the full regression gate and fails on exactly three stale cross-lane tests; exact non-live PREPARE is therefore not executed on this SHA.

The three current source/non-live blockers are:

1. `test_devb_round2_release.DevBRound2ReleaseContractsTests.test_passenger_binding_rejects_runtime_from_different_wsgi`
2. `test_devb_round2_release.DevBRound2ReleaseContractsTests.test_preflight_manifest_and_passenger_binding_share_exact_wsgi_identity`
3. `test_devc_release_qa.PreparedAndCrossLaneTruthTests.test_v2_exact_binding_is_accepted_but_never_self_authorizes_promotion`

DEV09 reproduces those same three in a clean `git archive` of the exact parent without `.git` metadata. No production implementation weakening is indicated: DEV02 current tests already contain the updated WSGI/challenge/strong-evidence fixtures, and canonical production-readiness tests already classify legacy v2 Passenger evidence as `BLOCKED_EXTERNAL` rather than `PASS`.

## Independent QA checks

- exact PR-base SHA guard;
- exact-parent deterministic provenance check in an isolated detached worktree;
- exact-parent full unittest discovery in a clean Git archive without `.git`;
- all 67 A1-K5 criteria accounted exactly once with conservative evidence classes;
- 19 integrated routes / 17 ChatGPT Action operations;
- zero product PASS claims from synthetic/source-only evidence;
- K5 remains live/external and independently write-gated;
- current-tree and full-history secret scans;
- no auto-deploy arming markers.

Probe outputs are bounded and do not publish raw stdout/stderr, traceback text, exception messages, private Telegram content, server paths, credentials, or secret values.

## Same-role deduplication

Concurrent DEV09 PR #47 has broader auth/fuzz/mock-flow/runtime-security coverage and independently reproduces the same three cross-lane regression failures. This overlay is retained for its exact-parent bounded provenance/export diagnostics; the two QA overlays must not be mechanically merged as duplicate production changes.

## Evidence boundary

Synthetic/mock/source QA is never product PASS. HOSTiQ live identity/lifecycle, real Telegram E2E, deployed ChatGPT Action E2E, human keyboard/NVDA evidence, and K1-K5 remain separate factual gates. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
