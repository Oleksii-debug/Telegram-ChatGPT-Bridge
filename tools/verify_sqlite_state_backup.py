# -*- coding: utf-8 -*-
"""Server-side verifier for a private SQLite-aware persistent-state backup.

The command intentionally emits only stable non-secret counts/status. It never
prints archive contents, database paths, rows, or private state values.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from ops.sqlite_state_backup import (
    SQLiteStateBackupError,
    verify_archive_hash_pair,
    verify_private_state_archive,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-sqlite-count", type=int)
    args = parser.parse_args(argv)
    try:
        verify_archive_hash_pair(args.archive)
        databases = verify_private_state_archive(args.archive)
    except SQLiteStateBackupError:
        print("SQLITE_STATE_BACKUP_VERIFICATION_FAILED")
        return 2
    if args.expected_sqlite_count is not None and len(databases) != args.expected_sqlite_count:
        print("SQLITE_STATE_BACKUP_VERIFICATION_FAILED")
        return 2
    print(f"SQLITE_STATE_BACKUP_VERIFIED db_count={len(databases)} hash_verified=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
