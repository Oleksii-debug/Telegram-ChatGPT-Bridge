# DEV09 SWARM QA — exact-current checkpoint

Role: DEV09 independent engineering QA. This layer is QA-only and does not authorize merge, deploy, Passenger restart, Telegram authorization, or live Telegram write.

Exact canonical parent: `00684e834a523f55ea3b61c1a12cb9dc54cfd947` on `work3/integration-release-candidate`.

## Current source/non-live state

DEV09 previously found and tracked three transient integration defects across moving canonical heads: terminal DEV02 provenance drift, three stale cross-lane runtime-evidence tests, and later unaccounted DEV02 verifier/test paths. All three were closed in the canonical lane without weakening production behavior.

Exact canonical `00684e834a523f55ea3b61c1a12cb9dc54cfd947` has Recovery Guard #377 SUCCESS. Release/package validation, OpenAPI, 67-criterion/19-route truth, deterministic provenance, single deploy entrypoint, full regression, real exact-head non-live PREPARE, current/history secret scans, recovery marker and no-autodeploy guards all pass.

DEV09 independently requires the exact-parent provenance probe and the full clean `git archive` unittest suite without `.git` to remain clear. Any future canonical movement invalidates this checkpoint through the exact-parent anti-staleness gate.

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
