# -*- coding: utf-8 -*-
"""Prove one audit JSONL record stays atomic across Passenger processes.

The worker injects a deterministic short first write. Without a process-shared
record lock, several processes can append first halves before any appends its
second half, corrupting JSONL framing. No private content is used.
"""
from __future__ import annotations

import json
import multiprocessing as mp
import os
import tempfile
import time
import unittest
from pathlib import Path


def _context():
    return mp.get_context("fork" if "fork" in mp.get_all_start_methods() else "spawn")


class _OSProxy:
    def __init__(self, real_os, partial_count, count_lock, overlap_event):
        self._real = real_os
        self._partial_count = partial_count
        self._count_lock = count_lock
        self._overlap_event = overlap_event
        self._used_short_write = False

    def __getattr__(self, name):
        return getattr(self._real, name)

    def write(self, fd, data):
        if not self._used_short_write and len(data) > 1:
            self._used_short_write = True
            half = max(1, len(data) // 2)
            written = self._real.write(fd, data[:half])
            with self._count_lock:
                self._partial_count.value += 1
                if self._partial_count.value >= 2:
                    self._overlap_event.set()
            # Pre-fix: another process reaches its first half and sets this event,
            # making the interleaving deterministic. With flock: no peer reaches
            # write() until this record finishes, so this bounded wait simply times out.
            self._overlap_event.wait(0.20)
            return written
        return self._real.write(fd, data)


def _worker(path, index, barrier, partial_count, count_lock, overlap_event, output):
    import bridge.audit as audit_module

    audit_module.os = _OSProxy(os, partial_count, count_lock, overlap_event)
    try:
        log = audit_module.AuditLog(Path(path))
        barrier.wait(timeout=10)
        log.write("short-write-stress", request_id=f"worker-{index}", count=index)
        output.put("ok")
    except BaseException as exc:
        output.put(type(exc).__name__)


class Finalwave39AuditPartialWriteTests(unittest.TestCase):
    def test_six_process_short_writes_preserve_jsonl_record_framing(self):
        ctx = _context()
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / "audit"
            parent.mkdir(mode=0o700)
            path = parent / "bridge.jsonl"
            barrier = ctx.Barrier(6)
            partial_count = ctx.Value("i", 0)
            count_lock = ctx.Lock()
            overlap_event = ctx.Event()
            output = ctx.Queue()
            workers = [
                ctx.Process(
                    target=_worker,
                    args=(str(path), index, barrier, partial_count, count_lock, overlap_event, output),
                )
                for index in range(6)
            ]
            for worker in workers:
                worker.start()
            deadline = time.monotonic() + 15
            for worker in workers:
                worker.join(max(0.1, deadline - time.monotonic()))
            alive = [worker for worker in workers if worker.is_alive()]
            for worker in alive:
                worker.terminate()
                worker.join(2)
            self.assertFalse(alive, "audit short-write workers hung")

            results = [output.get(timeout=3) for _ in workers]
            self.assertEqual(results.count("ok"), 6, results)
            self.assertTrue(all(worker.exitcode == 0 for worker in workers), [worker.exitcode for worker in workers])
            lines = path.read_text(encoding="ascii").splitlines()
            self.assertEqual(len(lines), 6, lines)
            payloads = [json.loads(line) for line in lines]
            self.assertEqual({payload["request_id"] for payload in payloads}, {f"worker-{i}" for i in range(6)})
            self.assertTrue(all(payload["event"] == "short-write-stress" for payload in payloads))


if __name__ == "__main__":
    unittest.main()
