# DEV09 SWARM QA — exact-current checkpoint

Role: DEV09 independent engineering QA. This layer is QA-only and does not authorize merge, deploy, Passenger restart, Telegram authorization, or live Telegram write.

Exact canonical parent: `a4fea8431b999e1bab7d95168ce0fc4d2a20305d` on `work3/integration-release-candidate`.

## Current source/non-live state

The prior DEV09 findings were closed on `999709f0ab2daee08fdb5c793419d1c45967238d`, where canonical Recovery Guard #369 passed full regression and real exact-head non-live PREPARE.

The canonical head subsequently integrated a new DEV02 canonical-sync verifier/tests/docs package without production runtime changes. On exact `a4fea843...`, release/package, OpenAPI, 67-criterion/19-route and secret-scan gates pass, but deterministic integration provenance fails closed because the newly integrated QA paths are not yet in the canonical provenance allowlist/accounting. Regression and PREPARE are therefore not reached by canonical Recovery Guard #374.

DEV09 separately checks the full exact-parent clean `git archive` unittest suite without `.git`. If that suite is clear, the current blocker is integration-accounting/provenance only, not an independently observed functional regression.

## Independent QA checks

- exact PR-base SHA anti-staleness guard;
- exact-parent provenance in an isolated detached worktree;
- full exact-parent unittest discovery from clean Git archive;
- all 67 A1-K5 criteria exactly once with conservative evidence classes;
- 19 integrated routes / 17 ChatGPT Action operations;
- zero product PASS claims from synthetic/source-only evidence;
- K5 remains live/external and independently write-gated;
- current-tree and full-history secret scans;
- no auto-deploy arming markers.

Probe outputs are bounded and never publish raw stdout/stderr, traceback text, exception messages, private Telegram content, server paths, credentials, or secret values.

## Evidence boundary

Synthetic/mock/source QA is never product PASS. HOSTiQ live identity/lifecycle, real Telegram E2E, deployed ChatGPT Action E2E, human keyboard/NVDA evidence, and K1-K5 remain separate factual gates. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
