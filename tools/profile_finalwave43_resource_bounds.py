#!/usr/bin/env python3
"""Credential-free resource-bound profiler for FINALWAVE-43.

The profiler intentionally uses only synthetic metadata. It does not connect to
Telegram, read production files, or require any secret. Wall-clock and tracemalloc
numbers are diagnostic rather than pass/fail thresholds; deterministic call/count
bounds live in tests/test_finalwave43_resource_bounds.py.
"""

from __future__ import annotations

import json
import sys
import time
import tracemalloc
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bridge.archive import ArchiveLimits
from bridge.audit import AuditLog
from bridge.backend import TelethonReadConfig
from bridge.downloads import DownloadLimits, DownloadManager
from bridge.models import encode_cursor
from bridge.storage import DownloadItem, FileRecord


WORKLOADS = (1_000, 5_000, 10_000)


class CountingFiles:
    def __init__(self) -> None:
        self.get_calls = 0
        self.deleted = 0

    def get(self, file_ref: str):
        del file_ref
        self.get_calls += 1
        return None

    def delete(self, file_ref: str) -> bool:
        del file_ref
        self.deleted += 1
        return True


def record(index: int) -> FileRecord:
    return FileRecord(
        file_ref=f"record-{index}",
        path=f"/synthetic/record-{index}",
        name=f"record-{index}.bin",
        mime_type="application/octet-stream",
        size=1,
        sha256="a" * 64,
        created_at=1,
    )


def item(index: int) -> DownloadItem:
    return DownloadItem(
        item_id=f"item-{index}",
        chat="1",
        message_id=index + 1,
        source_file_ref=f"tg_{index}_0123456789abcdef0123",
        name=f"file-{index}.bin",
        mime_type="application/octet-stream",
    )


def measured(callable_obj):
    tracemalloc.start()
    started = time.perf_counter()
    result = callable_obj()
    elapsed = time.perf_counter() - started
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return result, {
        "elapsed_seconds": elapsed,
        "tracemalloc_current_bytes": current,
        "tracemalloc_peak_bytes": peak,
    }


def audit_profile(count: int) -> dict[str, object]:
    def run():
        log = AuditLog(memory_event_limit=256)
        for index in range(count):
            log.write("request", request_id=str(index), status=200)
        return log

    log, metrics = measured(run)
    metrics.update(
        {
            "workload": count,
            "retained_events": len(log.events),
            "configured_event_limit": log.memory_event_limit,
            "retained_json_bytes": len(json.dumps(log.events, separators=(",", ":")).encode("utf-8")),
        }
    )
    return metrics


def bulk_accept_profile(count: int) -> dict[str, object]:
    files = CountingFiles()
    manager = object.__new__(DownloadManager)
    manager.files = files
    manager.limits = DownloadLimits(max_single_bytes=1, max_bulk_files=500, max_bulk_bytes=count + 1)
    payload = {"results": {}, "failures": {}}

    def run():
        total = 0
        for index in range(count):
            total = manager._accept_result(payload, item(index), record(index), current_total=total)
        return total

    total, metrics = measured(run)
    metrics.update(
        {
            "workload": count,
            "accepted_bytes": total,
            "prior_file_get_calls_during_accept": files.get_calls,
            "legacy_prior_get_calls_model": count * (count - 1) // 2,
            "result_entries": len(payload["results"]),
            "production_max_bulk_files": DownloadLimits().max_bulk_files,
            "note": "workload exercises the internal accept primitive; public bulk selection remains hard-bounded",
        }
    )
    return metrics


def cursor_profile(count: int) -> dict[str, object]:
    cursor = encode_cursor(
        {
            "v": 2,
            "scope": "search",
            "sig": "a" * 24,
            "boundary": ["2026-01-01T00:00:00Z", count, "1"],
        }
    )
    return {"workload": count, "cursor_bytes": len(cursor.encode("ascii"))}


def bounded_surface_profile(count: int) -> dict[str, object]:
    read = TelethonReadConfig()
    archive = ArchiveLimits()
    downloads = DownloadLimits()
    return {
        "workload": count,
        "dialog_scan_per_page": min(count, read.dialog_scan_limit),
        "search_scan_per_page": min(count, read.search_scan_limit),
        "two_dialog_pages_current_scan_model": 2 * min(count, read.dialog_scan_limit),
        "two_search_pages_current_scan_model": 2 * min(count, read.search_scan_limit),
        "bulk_request_accepted_by_default_limit": count <= downloads.max_bulk_files,
        "zip_request_accepted_by_default_limit": count <= archive.max_members,
        "checkpoint_item_schema_accepted": count <= 500,
    }


def retention_truth() -> dict[str, object]:
    return {
        "audit_memory_cache": "bounded",
        "audit_disk_jsonl": "unbounded_policy_missing",
        "download_job_rows": "unbounded_retention_missing",
        "download_job_lock_files": "unbounded_retention_missing",
        "private_file_registry": "unbounded_retention_missing",
        "write_idempotency_tombstones": "intentionally_unbounded_exactly_once_safety",
        "consumed_preview_payloads": "retained_via_idempotency_fk",
        "safe_action": "do_not_delete_without_audited_retention_exactly_once_policy",
    }


def main() -> int:
    report = {
        "schema": "finalwave43-resource-profile-v1",
        "synthetic_only": True,
        "workloads": [
            {
                "count": count,
                "audit": audit_profile(count),
                "bulk_accept": bulk_accept_profile(count),
                "cursor": cursor_profile(count),
                "bounded_surfaces": bounded_surface_profile(count),
            }
            for count in WORKLOADS
        ],
        "retention_truth": retention_truth(),
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
