# FINALWAVE-43 — scale / resource bounds

This document records synthetic/source evidence only. It authorizes no merge, deployment, Passenger restart, Telegram authorization, live Telegram operation, K5, or product PASS.

## Exact basis

- Canonical parent: `84691967e5363bc4b88dfae97371d7bf329c105d` from PR #9.
- Comparison candidate: PR #61 @ `7fb4096d43e7f98c99d3b012540526a7a08916d2`.
- Isolated branch: `finalwave26/43-resource-bounds`.
- Public repository rules apply; the profiler and tests use synthetic metadata only.

## Integrated low-risk fixes

### 1. Audit observation memory

Canonical `AuditLog.events` appended every event forever. PR #61 added a strict bound but evicted with `del events[:overflow]`; once full, a one-event overflow shifts the remaining Python list and therefore costs O(cache_limit) per write.

FINALWAVE-43 keeps the PR #61 validation/defaults but stores the observation window in `collections.deque(maxlen=...)`, making append/eviction O(1). `events` remains a chronological list snapshot for existing read/index/JSON use. Durable JSONL persistence is unchanged.

Default retained observation events: 2048. Hard constructor maximum: 100000.

### 2. Bulk-download cumulative bytes

Canonical `_accept_result()` called `_complete_files()` after every accepted result. `FileRecordStore.get()` re-hashes the underlying private file, so repeated cumulative accounting was O(N^2) in prior-file integrity reads.

The PR #61 design is retained: validate durable checkpoint results once at resume entry, sum their verified sizes once, then advance `current_total` O(1) for each newly verified result. Final response validation still revalidates every result once. Overflow deletes only the newly accepted record and leaves prior checkpoint results untouched.

The earlier PR #61 100-file/500-MiB model estimated roughly 24.17 GiB of repeated prior-file hashing before this repair. FINALWAVE tests exercise the accept primitive at 1k/5k/10k and require zero prior-file `get()` calls during acceptance. Public bulk selection remains independently bounded (default 100, constructor maximum 500).

## 1k / 5k / 10k profiler

Run:

```bash
python tools/profile_finalwave43_resource_bounds.py
```

The JSON output records for each workload:

- audit wall time, tracemalloc current/peak bytes, retained event count and retained JSON bytes;
- bulk accept wall time, tracemalloc current/peak bytes, accepted bytes, actual prior-file `get()` calls and the legacy quadratic call-count model `N*(N-1)/2`;
- encoded cursor byte size;
- configured dialog/search scan counts;
- whether default bulk/ZIP/checkpoint limits would reject the requested item count.

Wall-clock/memory values are diagnostics only, not flaky CI thresholds. Deterministic count/cap assertions live in `tests/test_finalwave43_resource_bounds.py`.

## Proven bounded / linear surfaces

### Cursor state

Read cursors contain version/scope/signature plus a bounded boundary tuple. FINALWAVE tests verify encoded cursor size remains below 256 bytes across 1k/5k/10k numeric boundaries. Cursor state itself is O(1); the server-side work performed after presenting a cursor is a separate issue below.

### ZIP memory and asymptotics

`ArchiveLimits` caps members (default 200, maximum 500) and total uncompressed input bytes. ZIP creation streams each source in 1-MiB chunks, so payload memory is bounded rather than proportional to archive size.

The current integrity design intentionally performs multiple linear passes:

1. `FileRecordStore.get(ref)` hashes each registered source before archive construction;
2. `_write_record()` streams and hashes each source again while writing ZIP data;
3. `ZipFile.testzip()` reads/decompresses archive members for CRC validation;
4. registering the final archive hashes the archive once more.

This is O(total input bytes + archive bytes), not O(N^2). Removing one of these passes would weaken an existing integrity/TOCTOU boundary unless replaced with a descriptor-bound combined validation design. No unsafe optimization is proposed in this branch.

### Per-job checkpoint size

`CheckpointStore._validate()` caps one job at 500 items. Download limits cap public bulk requests more tightly by default. Individual checkpoint payloads are therefore bounded.

## Residual resource/correctness findings — intentionally not patched here

### HIGH — search continuation rescans one bounded newest prefix

`TelethonReadBackend.search()` calls `_iter_messages(... min(scan_limit, search_scan_limit) ...)` without a server continuation offset/state. Cursor filtering happens only after that same prefix is fetched and converted. A second page therefore scans the same prefix again, and matching messages older than that prefix are unreachable. Raising `search_scan_limit` is not a fix: it increases per-page cost and still leaves a finite ceiling.

The characterization test backs the fake Telegram source with 10k messages and proves two search pages request `[5000, 5000]` from the same prefix.

Required canonical design: real Telethon continuation semantics. Chat-scoped search may use an exclusive message boundary where Telethon supports it; global SearchGlobal needs its actual continuation state. A bounded private server-side cursor/TTL store is preferable where peer/access-hash state cannot safely be exposed in a public cursor.

### MEDIUM — dialog continuation rescans only the first prefix

`list_dialogs()` fetches `dialog_scan_limit` from the beginning for every API page and applies the cursor boundary locally. With 10k synthetic dialogs, two pages request `[2000, 2000]`. Dialogs outside the first prefix are unreachable.

Required canonical design: use real Telethon dialog continuation state (offset date/id/peer as applicable), held in a bounded private cursor when necessary. Do not solve by raising the prefix cap.

### MEDIUM — sequential sender metadata resolution scales with scanned messages

`_message_record()` invokes `message.get_sender()` when available. Search builds records for the entire scanned prefix before filtering; sender/name searches can therefore perform one sender-resolution operation per scanned message. The characterization test counts 1000 sender resolutions for a 1000-message scan.

This is O(N), not O(N^2), but the sequential await chain can dominate latency and increase RPC/FloodWait exposure if entities are not already cached. A future repair should resolve the requested sender once when possible and/or use bounded entity caching/batching without changing sender correctness.

### HIGH — durable audit JSONL has no rotation/retention policy

The new in-memory window is bounded, but JSONL append persistence intentionally remains durable and has no byte/time rotation. A long-lived production service can therefore exhaust the hosting filesystem. Arbitrary truncation would destroy audit evidence.

Required canonical design: an explicit retention policy with owner-private rotation, bounded aggregate bytes/age, crash-safe rename/open continuity, and tests proving no secret/private-body logging regressions.

### HIGH — private download/registry lifecycle has no job-count/storage retention policy

Each unique download job persists a `download_jobs` row, and each job creates a persistent zero-byte lock filename under `.download-locks`. `FileRecordStore` retains registered downloaded files/ZIPs until explicit deletion. Per-job/member sizes are bounded, but the number of jobs/files over service lifetime is not.

Required canonical design: audited lifecycle policy defining resume TTL, completed/failed checkpoint retention, safe lock-file reaping, file/ZIP expiry/ownership, crash/concurrency behavior, and protection against deleting active/resumable artifacts.

### HIGH — write exactly-once tombstones and consumed preview payload retention are intentionally unbounded

`PersistentWriteStore.cleanup()` deletes only stale *uncommitted* previews and explicitly reports zero idempotency tombstones deleted. Idempotency rows are retained to prevent replay after restart; their foreign key keeps the associated consumed preview row, whose `payload_json` may contain private target/message/file metadata needed by the private write transaction.

Naive TTL deletion would re-enable duplicate sends and is rejected. Canonical resolution requires an exactly-once compaction/privacy design: preserve enough irreversible fingerprint/tombstone material to reject/replay old keys while safely minimizing private payload retention, with restart/crash/race tests and an explicit retention horizon if semantics permit one.

## Integration recommendation

Canonical integrator should semantically select:

- `bridge/downloads.py` cumulative-accounting change;
- `bridge/audit.py` FINALWAVE deque version (not PR #61 list-shift eviction);
- positive/negative/restart/concurrency/resource tests that remain valid after integration.

The specialist workflow is evidence infrastructure only and need not be integrated. Search/dialog continuation, audit-disk retention, download/file lifecycle and write-tombstone compaction should receive separate owned designs because unsafe local deletion or larger scan limits would trade correctness/durability for apparent resource improvements.
