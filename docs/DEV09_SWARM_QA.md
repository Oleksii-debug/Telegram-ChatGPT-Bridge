# DEV09 SWARM QA — moving-canonical checkpoint

Role: DEV09 independent engineering QA. This layer is QA-only and does not authorize merge, deploy, Passenger restart, Telegram authorization, or live Telegram write.

The current DEV09 overlay was originally restacked on canonical `4ebfceb153e94840fa046af88cee1131e0705657`. The canonical target has moved since then, so this overlay is intentionally treated as stale diagnostic evidence until the next stable exact-current restack.

## Current source/non-live state

DEV09 previously found terminal DEV02 provenance drift and three stale cross-lane runtime-evidence tests; both were closed in the canonical lane without weakening production behavior. A later DEV02 verifier-path accounting drift was also closed.

DEV04 media/storage hardening for Auditor HIGH A01-06 is now canonical-integrated with exact provenance. DEV09 retains a separate checkpoint-save crash oracle requiring recovery of the same durable registry result with no second backend download and no duplicate registry row.

DEV03 read hardening is now entering canonical integration. Source review confirms the exclusive `offset_id` history design repairs the former 5,000-message history ceiling and sender filtering now includes display name plus strict metadata-failure handling for name/username queries.

## Open DEV09 finding — global sender-only search contract

The public `search.read` handler accepts `sender` as the only search filter: `chat` may be absent and `text` may be empty. Current backend behavior, including the reviewed DEV03 repair candidate, then invokes global `iter_messages(entity=None, ...)` without a non-empty search/filter or a resolved `from_user` constraint.

Real Telethon global search requires a non-empty search string, filter, or `from_user` when `entity=None`. Therefore the locked search-by-person surface can fail for global sender-only queries even though chat-scoped display-name/username search is repaired.

DEV09 now carries two executable QA-only reproducer oracles:

- the API contract demonstrably accepts a sender-only search without chat/text;
- a strict Telethon-like global-search fake rejects the backend call because no server-side sender constraint is supplied, producing the current bounded `telegram_rpc_error` outcome.

This reproducer must be flipped into a positive closure oracle after DEV03/DEV01 chooses a bounded global sender design. DEV09 does not copy or own that production fix.

## A01-06 independent closure oracle

The earlier canonical implementation could durably register a downloaded file before the checkpoint result was persisted. A process loss or checkpoint-save failure in that window left an unreferenced registry record and allowed resume to download the same Telegram object again.

DEV04's canonical repair adds deterministic private download origin identity and `_recover_existing()` recovery. DEV09 independently injects a failure into the checkpoint save immediately after a real local download/registry commit, restarts `DownloadManager`, and requires:

- the durable checkpoint still has no result before restart;
- exactly one registry record exists before restart;
- resume completes using that same registered record;
- backend download call count remains exactly one after restart;
- registry row count remains exactly one.

This is source/synthetic fault-injection only. It is not real Telegram or production Passenger restart evidence.

## Exact-current evidence binding

PR snapshot `base_sha` is not sufficient for DEV09 anti-staleness. The target branch can move while PR metadata still reports the older base snapshot. The dedicated DEV09 workflow therefore resolves the live public ref `work3/integration-release-candidate` directly before testing and again after all evidence steps. Either mismatch against the manifest parent fails closed with `DEV09_QA_PARENT_MOVED`.

This guards both stale-start evidence and canonical movement during the QA run. It does not weaken canonical provenance and does not authorize production mutation.

## Independent QA checks

- live-target-ref exact-parent anti-staleness before and after evidence;
- exact-parent provenance in an isolated detached worktree;
- full exact-parent unittest discovery from clean Git archive without `.git`;
- A01-06 checkpoint-save crash/restart no-redownload oracle;
- global sender-only API/Telethon contract reproducer until repaired;
- all 67 A1-K5 criteria exactly once with conservative evidence classes;
- 19 integrated routes / 17 ChatGPT Action operations;
- zero product PASS claims from synthetic/source-only evidence;
- K5 remains live/external and independently write-gated;
- current-tree and full-history secret scans;
- no auto-deploy arming markers.

Probe outputs are bounded and never publish raw stdout/stderr, traceback text, exception messages, private Telegram content, server paths, credentials, or secret values.

## Evidence boundary

Synthetic/mock/source QA is never product PASS. HOSTiQ live identity/lifecycle, real Telegram E2E, deployed ChatGPT Action E2E, human keyboard/NVDA evidence, and K1-K5 remain separate factual gates. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
