# DEV09 SWARM QA — exact-current checkpoint

Role: DEV09 independent engineering QA. This layer is QA-only and does not authorize merge, deploy, Passenger restart, Telegram authorization, or live Telegram write.

Exact canonical parent: `4ebfceb153e94840fa046af88cee1131e0705657` on `work3/integration-release-candidate`.

## Current source/non-live state

DEV09 previously found terminal DEV02 provenance drift and three stale cross-lane runtime-evidence tests; both were closed in the canonical lane without weakening production behavior. A later DEV02 verifier-path accounting drift was also closed before this parent.

The current parent additionally integrates DEV06 contract/runtime-conformance QA and the reviewed DEV04 media/storage repair for Auditor HIGH A01-06. Canonical DEV04 provenance is explicit and byte-bound to the reviewed specialist checkpoint; the specialist workflow itself is excluded from canonical.

## A01-06 independent closure oracle

The earlier canonical implementation could durably register a downloaded file before the checkpoint result was persisted. A process loss or checkpoint-save failure in that window left an unreferenced registry record and allowed resume to download the same Telegram object again.

DEV04's canonical repair adds deterministic private download origin identity and `_recover_existing()` recovery. DEV09 now independently injects a failure into the checkpoint save immediately after a real local download/registry commit, restarts `DownloadManager`, and requires:

- the durable checkpoint still has no result before restart;
- exactly one registry record exists before restart;
- resume completes using that same registered record;
- backend download call count remains exactly one after restart;
- registry row count remains exactly one.

This is source/synthetic fault-injection only. It is not real Telegram or production Passenger restart evidence.

## Independent QA checks

- exact PR-base SHA anti-staleness guard;
- exact-parent provenance in an isolated detached worktree;
- full exact-parent unittest discovery from clean Git archive without `.git`;
- A01-06 checkpoint-save crash/restart no-redownload oracle;
- all 67 A1-K5 criteria exactly once with conservative evidence classes;
- 19 integrated routes / 17 ChatGPT Action operations;
- zero product PASS claims from synthetic/source-only evidence;
- K5 remains live/external and independently write-gated;
- current-tree and full-history secret scans;
- no auto-deploy arming markers.

Probe outputs are bounded and never publish raw stdout/stderr, traceback text, exception messages, private Telegram content, server paths, credentials, or secret values.

## Validation status

Canonical Recovery Guard #440 (`32646557925` / job `97211596051`) and the current DEV09 Independent QA run are queued at this checkpoint because of the simultaneous SWARM Actions backlog. Until they complete, status is `VALIDATION_PENDING / PRODUCT_PASS_FALSE`; no green result is inferred from source review alone.

## Evidence boundary

Synthetic/mock/source QA is never product PASS. HOSTiQ live identity/lifecycle, real Telegram E2E, deployed ChatGPT Action E2E, human keyboard/NVDA evidence, and K1-K5 remain separate factual gates. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
