# DEV09 SWARM QA — exact-parent checkpoint

Role: DEV09 independent engineering QA. This layer is QA-only and does not authorize merge, deploy, Passenger restart, Telegram authorization, or live Telegram write.

Exact canonical parent for this checkpoint: `c609adfc9a1116aae635a0b14d632a5e59b6c2af` on `work3/integration-release-candidate`.

## Current canonical finding

Recovery Guard on the exact parent fails closed at deterministic integration provenance with `unexpected post-import mutation: DEV2:ops/private_evidence.py`. The package/OpenAPI/67-criterion/19-route gates before provenance pass, and current-tree/full-history secret scans pass. DEV09 does not weaken or bypass this provenance gate.

The current release-to-live manifest still records older DEV_B synchronization while the canonical tree already contains later DEV02 runtime/private-control/evidence changes. DEV01 owns semantic provenance reconciliation.

## Independent QA checks

- exact PR-base SHA guard;
- exact-parent provenance classification in an isolated detached worktree;
- exact-parent full unittest discovery in a clean `git archive` tree without `.git`;
- full checkout cross-lane regression;
- all 67 A1-K5 criteria accounted exactly once with conservative evidence classes;
- 19 integrated routes / 17 ChatGPT Action operations;
- zero product PASS claims from synthetic/source-only evidence;
- K5 remains live/external and independently write-gated;
- current-tree and full-history secret scans;
- no auto-deploy arming markers.

Probe outputs are bounded and do not publish raw stdout/stderr, traceback text, exception messages, private Telegram content, server paths, credentials, or secret values.

## Prior QA tooling defect closed

The previous DEV09 workflow invoked `ops/dev09_qa_probe.py` as a direct script and failed package import resolution. This checkpoint uses `python -m ops.dev09_qa_probe`, preserving repository package import semantics without touching production code.

## Evidence boundary

Synthetic/mock/source QA is never product PASS. HOSTiQ live identity/lifecycle, real Telegram E2E, deployed ChatGPT Action E2E, human keyboard/NVDA evidence, and K1-K5 remain separate factual gates. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
