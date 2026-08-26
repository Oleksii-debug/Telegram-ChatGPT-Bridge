# -*- coding: utf-8 -*-
"""SQLite-aware private persistent-state backup primitives.

The deployment engine's outer quiesce remains authoritative for cross-file and
cross-database invariants.  This module removes dependence on DB/WAL/SHM timing:
every SQLite database is copied with SQLite's online backup API and verified
before the private state tree is archived.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

SQLITE_HEADER = b"SQLite format 3\x00"
SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm")


class SQLiteStateBackupError(RuntimeError):
    """Stable fail-closed error for unsafe or unverifiable private state."""


@dataclass(frozen=True)
class SQLiteBackupReport:
    sqlite_databases: tuple[str, ...]
    ordinary_files: tuple[str, ...]
    skipped_sqlite_sidecars: tuple[str, ...]
    directory_count: int

    @property
    def sqlite_count(self) -> int:
        return len(self.sqlite_databases)


def _mode(st: os.stat_result) -> int:
    return stat.S_IMODE(st.st_mode)


def _owner_ok(st: os.stat_result) -> bool:
    return not hasattr(os, "geteuid") or st.st_uid == os.geteuid()


def _safe_lstat(path: Path, *, expected: str) -> os.stat_result:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise SQLiteStateBackupError(f"persistent state {expected} is unavailable") from exc
    if not _owner_ok(st):
        raise SQLiteStateBackupError(f"persistent state {expected} owner is unsafe")
    return st


def _validate_directory(path: Path) -> os.stat_result:
    st = _safe_lstat(path, expected="directory")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SQLiteStateBackupError("persistent state directory topology is unsafe")
    if _mode(st) & 0o022:
        raise SQLiteStateBackupError("persistent state directory is group/world writable")
    return st


def _validate_regular(path: Path) -> os.stat_result:
    st = _safe_lstat(path, expected="file")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SQLiteStateBackupError("persistent state file topology is unsafe")
    if _mode(st) & 0o022:
        raise SQLiteStateBackupError("persistent state file is group/world writable")
    return st


def _is_sqlite_database(path: Path) -> bool:
    st = _validate_regular(path)
    if st.st_size < len(SQLITE_HEADER):
        return False
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SQLiteStateBackupError("persistent state file cannot be opened safely") from exc
    try:
        fst = os.fstat(fd)
        if (
            not stat.S_ISREG(fst.st_mode)
            or fst.st_nlink != 1
            or not _owner_ok(fst)
            or (fst.st_dev, fst.st_ino) != (st.st_dev, st.st_ino)
        ):
            raise SQLiteStateBackupError("persistent state file changed during validation")
        return os.read(fd, len(SQLITE_HEADER)) == SQLITE_HEADER
    finally:
        os.close(fd)


def _sidecar_base(path: Path) -> Path | None:
    raw = str(path)
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        if raw.endswith(suffix):
            return Path(raw[: -len(suffix)])
    return None


def _walk_source(root: Path) -> Iterator[tuple[Path, os.stat_result]]:
    """Walk lexical tree without following symlinks, rejecting unsafe nodes."""
    stack = [root]
    while stack:
        current = stack.pop()
        st = _safe_lstat(current, expected="entry")
        if stat.S_ISLNK(st.st_mode):
            raise SQLiteStateBackupError("persistent state symlink is forbidden")
        if stat.S_ISDIR(st.st_mode):
            _validate_directory(current)
            yield current, st
            try:
                children = sorted(current.iterdir(), key=lambda p: p.name, reverse=True)
            except OSError as exc:
                raise SQLiteStateBackupError("persistent state directory cannot be enumerated") from exc
            stack.extend(children)
            continue
        if stat.S_ISREG(st.st_mode):
            _validate_regular(current)
            yield current, st
            continue
        raise SQLiteStateBackupError("persistent state contains unsupported special file")


def _copy_regular_verified(source: Path, destination: Path, *, expected: os.stat_result | None = None) -> None:
    before = _validate_regular(source)
    if expected is not None and (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns):
        raise SQLiteStateBackupError("non-SQLite persistent file changed before backup")
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        src_fd = os.open(source, flags)
    except OSError as exc:
        raise SQLiteStateBackupError("persistent state file cannot be opened safely") from exc
    try:
        opened = os.fstat(src_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not _owner_ok(opened)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise SQLiteStateBackupError("persistent state file changed before copy")
        tmp = destination.with_name(f".{destination.name}.copying")
        if tmp.exists() or tmp.is_symlink():
            raise SQLiteStateBackupError("persistent state snapshot staging collision")
        out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
        dst_fd = os.open(tmp, out_flags, _mode(opened) or 0o600)
        try:
            while True:
                chunk = os.read(src_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(dst_fd, view)
                    if written <= 0:
                        raise SQLiteStateBackupError("persistent state snapshot write failed")
                    view = view[written:]
            os.fsync(dst_fd)
            os.fchmod(dst_fd, _mode(opened))
        finally:
            os.close(dst_fd)
        after = os.fstat(src_fd)
        if (
            (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        ):
            tmp.unlink(missing_ok=True)
            raise SQLiteStateBackupError("non-SQLite persistent file changed during backup")
        os.replace(tmp, destination)
    except Exception:
        destination.with_name(f".{destination.name}.copying").unlink(missing_ok=True)
        raise
    finally:
        os.close(src_fd)


def _sqlite_uri(path: Path) -> str:
    return f"file:{quote(path.as_posix(), safe='/')}?mode=ro"


def _sqlite_backup_verified(source: Path, destination: Path, *, busy_timeout_ms: int) -> None:
    before = _validate_regular(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(f".{destination.name}.sqlite-backup")
    if tmp.exists() or tmp.is_symlink():
        raise SQLiteStateBackupError("SQLite snapshot staging collision")
    source_connection: sqlite3.Connection | None = None
    destination_connection: sqlite3.Connection | None = None
    try:
        source_connection = sqlite3.connect(
            _sqlite_uri(source), uri=True, timeout=busy_timeout_ms / 1000.0, isolation_level=None
        )
        source_connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        source_connection.execute("PRAGMA query_only=ON")
        if source_connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise SQLiteStateBackupError("source SQLite database failed quick_check")
        destination_connection = sqlite3.connect(str(tmp), timeout=busy_timeout_ms / 1000.0, isolation_level=None)
        destination_connection.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        source_connection.backup(destination_connection, pages=256, sleep=0.01)
        if destination_connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise SQLiteStateBackupError("SQLite backup failed quick_check")
        # journal_mode is a persistent database property and a WAL source may
        # transfer WAL mode to the destination. Normalize the completed private
        # snapshot to DELETE so its correctness never depends on sidecar files.
        destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        mode_row = destination_connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if mode_row is None or str(mode_row[0]).lower() != "delete":
            raise SQLiteStateBackupError("SQLite backup could not become self-contained")
        if destination_connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise SQLiteStateBackupError("normalized SQLite backup failed quick_check")
        destination_connection.close()
        destination_connection = None
        source_connection.close()
        source_connection = None
        after = _validate_regular(source)
        # DB inode/topology may not be replaced while we are proving a source identity.
        # Content changes are allowed: SQLite online backup guarantees a committed snapshot
        # even when WAL writers continue concurrently.
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise SQLiteStateBackupError("SQLite database inode changed during backup")
        os.chmod(tmp, _mode(before))
        verify = sqlite3.connect(_sqlite_uri(tmp), uri=True, timeout=busy_timeout_ms / 1000.0)
        try:
            if verify.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise SQLiteStateBackupError("closed SQLite backup failed verification")
        finally:
            verify.close()
        # A self-contained backup must not depend on copied WAL/SHM sidecars.
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            if Path(str(tmp) + suffix).exists():
                raise SQLiteStateBackupError("SQLite backup unexpectedly depends on a sidecar")
        os.replace(tmp, destination)
    except SQLiteStateBackupError:
        raise
    except (sqlite3.Error, OSError) as exc:
        raise SQLiteStateBackupError("SQLite online backup failed") from exc
    finally:
        if destination_connection is not None:
            destination_connection.close()
        if source_connection is not None:
            source_connection.close()
        tmp.unlink(missing_ok=True)
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            Path(str(tmp) + suffix).unlink(missing_ok=True)


def snapshot_persistent_state(
    source_root: Path,
    snapshot_root: Path,
    *,
    busy_timeout_ms: int = 5000,
) -> SQLiteBackupReport:
    """Build a private, self-contained state snapshot.

    SQLite databases are copied with sqlite3.Connection.backup().  Source WAL/SHM
    files are validated but never raw-copied.  Ordinary mutable files are copied
    only if their inode/size/mtime/ctime remain stable for the copy duration.
    Symlinks, hardlinks, special files, unsafe ownership/modes and orphan SQLite
    sidecars fail closed.
    """
    if not 1 <= busy_timeout_ms <= 60_000:
        raise ValueError("busy_timeout_ms must be 1..60000")
    source_root = Path(os.path.abspath(source_root))
    snapshot_root = Path(os.path.abspath(snapshot_root))
    _validate_directory(source_root)
    if snapshot_root == source_root or source_root in snapshot_root.parents or snapshot_root in source_root.parents:
        raise SQLiteStateBackupError("snapshot and persistent-state roots must not overlap")
    if snapshot_root.exists() or snapshot_root.is_symlink():
        raise SQLiteStateBackupError("snapshot root must not pre-exist")
    snapshot_root.mkdir(parents=True, mode=0o700)
    os.chmod(snapshot_root, 0o700)

    entries = list(_walk_source(source_root))
    sqlite_paths: set[Path] = set()
    sidecar_paths: set[Path] = set()
    for path, st in entries:
        if stat.S_ISDIR(st.st_mode) or path == source_root:
            continue
        sidecar_base = _sidecar_base(path)
        if sidecar_base is not None:
            sidecar_paths.add(path)
            continue
        if _is_sqlite_database(path):
            sqlite_paths.add(path)

    for sidecar in sidecar_paths:
        base = _sidecar_base(sidecar)
        assert base is not None
        if base not in sqlite_paths:
            raise SQLiteStateBackupError("orphan SQLite WAL/SHM sidecar in persistent state")
        _validate_regular(sidecar)

    sqlite_rel: list[str] = []
    ordinary_rel: list[str] = []
    skipped_rel: list[str] = []
    directory_count = 0
    try:
        for path, st in entries:
            rel = path.relative_to(source_root)
            destination = snapshot_root / rel
            if path == source_root:
                continue
            if stat.S_ISDIR(st.st_mode):
                destination.mkdir(mode=0o700)
                os.chmod(destination, _mode(st))
                directory_count += 1
                continue
            if path in sidecar_paths:
                skipped_rel.append(rel.as_posix())
                continue
            if path in sqlite_paths:
                _sqlite_backup_verified(path, destination, busy_timeout_ms=busy_timeout_ms)
                sqlite_rel.append(rel.as_posix())
            else:
                _copy_regular_verified(path, destination, expected=st)
                ordinary_rel.append(rel.as_posix())
        # Do not mirror the source root mode if it is broader than 0700; staging
        # stays private even when an accepted source root is e.g. 0750.
        os.chmod(snapshot_root, 0o700)
        verify_persistent_state_snapshot(snapshot_root, expected_sqlite=tuple(sorted(sqlite_rel)))
        return SQLiteBackupReport(
            sqlite_databases=tuple(sorted(sqlite_rel)),
            ordinary_files=tuple(sorted(ordinary_rel)),
            skipped_sqlite_sidecars=tuple(sorted(skipped_rel)),
            directory_count=directory_count,
        )
    except Exception:
        shutil.rmtree(snapshot_root, ignore_errors=True)
        raise


def verify_persistent_state_snapshot(
    snapshot_root: Path,
    *,
    expected_sqlite: tuple[str, ...] | None = None,
    busy_timeout_ms: int = 5000,
) -> tuple[str, ...]:
    """Verify topology and every SQLite database in a staged/restored snapshot."""
    snapshot_root = Path(os.path.abspath(snapshot_root))
    _validate_directory(snapshot_root)
    found: list[str] = []
    for path, st in _walk_source(snapshot_root):
        if path == snapshot_root or stat.S_ISDIR(st.st_mode):
            continue
        rel = path.relative_to(snapshot_root).as_posix()
        if _sidecar_base(path) is not None:
            raise SQLiteStateBackupError("snapshot contains raw SQLite WAL/SHM sidecar")
        if _is_sqlite_database(path):
            connection = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=busy_timeout_ms / 1000.0)
            try:
                connection.execute("PRAGMA query_only=ON")
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise SQLiteStateBackupError("snapshot SQLite database failed quick_check")
            finally:
                connection.close()
            found.append(rel)
    result = tuple(sorted(found))
    if expected_sqlite is not None and result != tuple(sorted(expected_sqlite)):
        raise SQLiteStateBackupError("snapshot SQLite inventory mismatch")
    return result


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_path(path: Path) -> None:
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_backup_root(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if path.exists() or path.is_symlink():
        st = _validate_directory(path)
        if _mode(st) != 0o700:
            raise SQLiteStateBackupError("backup root must be owner-private mode 0700")
        return path
    try:
        path.mkdir(parents=True, mode=0o700)
        os.chmod(path, 0o700)
    except OSError as exc:
        raise SQLiteStateBackupError("backup root could not be created privately") from exc
    _validate_directory(path)
    return path


def _archive_destination(backup_root: Path, final_name: str) -> tuple[Path, Path, Path]:
    if not final_name.endswith(".tar.gz") or "/" in final_name or "\\" in final_name or final_name.startswith("."):
        raise SQLiteStateBackupError("invalid private backup archive name")
    final = backup_root / final_name
    stem = final_name[:-7]
    index = 0
    while True:
        sidecar = Path(str(final) + ".sha256")
        if final.is_symlink() or sidecar.is_symlink():
            raise SQLiteStateBackupError("private backup target topology is unsafe")
        if final.exists() and not sidecar.exists():
            # Same-name unpaired archive is an incomplete prior attempt. It is
            # safe to reap only inside the owner-private backup root and only
            # after validating it as a single-link owner file with mode 0600.
            st = _validate_regular(final)
            if _mode(st) != 0o600:
                raise SQLiteStateBackupError("incomplete private backup mode is unsafe")
            final.unlink()
        elif sidecar.exists() and not final.exists():
            st = _validate_regular(sidecar)
            if _mode(st) != 0o600:
                raise SQLiteStateBackupError("orphan private backup hash mode is unsafe")
            sidecar.unlink()
        if not final.exists() and not sidecar.exists():
            break
        index += 1
        final = backup_root / f"{stem}_{index}.tar.gz"
    partial = backup_root / f".{final.name}.partial"
    snapshot = backup_root / f".{final.name}.snapshot"
    for path in (partial, snapshot, Path(str(partial) + ".sha256")):
        if path.is_symlink():
            raise SQLiteStateBackupError("private backup staging path is unsafe")
        if path.exists():
            if path.is_dir():
                st = _validate_directory(path)
                if _mode(st) != 0o700:
                    raise SQLiteStateBackupError("private backup staging directory mode is unsafe")
                shutil.rmtree(path)
            else:
                st = _validate_regular(path)
                if _mode(st) != 0o600:
                    raise SQLiteStateBackupError("private backup staging file mode is unsafe")
                path.unlink()
    return final, partial, snapshot


def _write_hash_sidecar(archive: Path) -> Path:
    sidecar = Path(str(archive) + ".sha256")
    partial = Path(str(sidecar) + ".partial")
    if sidecar.exists() or sidecar.is_symlink() or partial.is_symlink():
        raise SQLiteStateBackupError("private backup hash target collision")
    digest = sha256_path(archive)
    fd = os.open(
        partial,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0)),
        0o600,
    )
    try:
        raw = (digest + "  " + archive.name + "\n").encode("ascii")
        view = memoryview(raw)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise SQLiteStateBackupError("private backup hash write failed")
            view = view[written:]
        os.fsync(fd)
        os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    os.replace(partial, sidecar)
    _fsync_path(sidecar)
    return sidecar


def verify_archive_hash_pair(archive: Path) -> str:
    archive = Path(os.path.abspath(archive))
    sidecar = Path(str(archive) + ".sha256")
    archive_st = _validate_regular(archive)
    sidecar_st = _validate_regular(sidecar)
    if _mode(archive_st) != 0o600 or _mode(sidecar_st) != 0o600:
        raise SQLiteStateBackupError("private backup/hash mode is unsafe")
    try:
        raw = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise SQLiteStateBackupError("private backup hash sidecar is unreadable") from exc
    expected = sha256_path(archive) + "  " + archive.name + "\n"
    if raw != expected:
        raise SQLiteStateBackupError("private backup hash mismatch")
    return expected.split("  ", 1)[0]


def _safe_archive_member_name(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or not path.parts or path.parts[0] != "persistent_state" or any(part in ("", ".", "..") for part in path.parts):
        raise SQLiteStateBackupError("private backup archive contains unsafe path")
    return path


def _extract_archive_for_verification(archive: Path, destination: Path) -> Path:
    import tarfile

    destination.mkdir(mode=0o700)
    os.chmod(destination, 0o700)
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            rel = _safe_archive_member_name(member.name)
            target = destination.joinpath(*rel.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(target, stat.S_IMODE(member.mode) & 0o777)
                continue
            if not member.isfile() or member.islnk() or member.issym():
                raise SQLiteStateBackupError("private backup archive contains unsupported topology")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise SQLiteStateBackupError("private backup archive member is unreadable")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(target, flags, stat.S_IMODE(member.mode) & 0o777)
            try:
                while True:
                    chunk = extracted.read(1024 * 1024)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        written = os.write(fd, view)
                        if written <= 0:
                            raise SQLiteStateBackupError("private backup restore verification write failed")
                        view = view[written:]
                os.fsync(fd)
                os.fchmod(fd, stat.S_IMODE(member.mode) & 0o777)
            finally:
                os.close(fd)
                extracted.close()
    restored = destination / "persistent_state"
    _validate_directory(restored)
    return restored


def verify_private_state_archive(
    archive: Path,
    *,
    expected_sqlite: tuple[str, ...] | None = None,
) -> tuple[str, ...]:
    """Verify hash-independent tar readability plus restored SQLite integrity."""
    archive = Path(os.path.abspath(archive))
    st = _validate_regular(archive)
    if _mode(st) != 0o600:
        raise SQLiteStateBackupError("private state archive must be mode 0600")
    verify_root = Path(tempfile.mkdtemp(prefix=".sqlite-restore-verify-", dir=archive.parent))
    os.chmod(verify_root, 0o700)
    try:
        restored = _extract_archive_for_verification(archive, verify_root / "restore")
        return verify_persistent_state_snapshot(restored, expected_sqlite=expected_sqlite)
    finally:
        shutil.rmtree(verify_root, ignore_errors=True)


def create_private_state_archive(
    source_root: Path,
    backup_root: Path,
    final_name: str,
    *,
    busy_timeout_ms: int = 5000,
) -> tuple[Path, SQLiteBackupReport]:
    """Create and restore-verify an atomic private SQLite-aware state archive.

    The returned tarball and its ``.sha256`` companion are mode 0600.  No source
    SQLite WAL/SHM is copied.  Any failure removes partial archive/snapshot/hash
    material from the current attempt.  Existing completed backups are never
    overwritten.
    """
    import tarfile

    backup_root = _private_backup_root(backup_root)
    source_root = Path(os.path.abspath(source_root))
    if source_root == backup_root or source_root in backup_root.parents or backup_root in source_root.parents:
        raise SQLiteStateBackupError("backup and persistent-state roots must not overlap")
    final, partial, snapshot_stage = _archive_destination(backup_root, final_name)
    snapshot = snapshot_stage / "persistent_state"
    report: SQLiteBackupReport | None = None
    try:
        snapshot_stage.mkdir(mode=0o700)
        os.chmod(snapshot_stage, 0o700)
        report = snapshot_persistent_state(source_root, snapshot, busy_timeout_ms=busy_timeout_ms)
        with tarfile.open(partial, "w:gz", dereference=False) as bundle:
            bundle.add(snapshot, arcname="persistent_state", recursive=True)
        os.chmod(partial, 0o600)
        _fsync_path(partial)
        os.replace(partial, final)
        _fsync_path(final)
        verify_private_state_archive(final, expected_sqlite=report.sqlite_databases)
        _write_hash_sidecar(final)
        verify_archive_hash_pair(final)
        return final, report
    except Exception:
        partial.unlink(missing_ok=True)
        if final.exists() and not Path(str(final) + ".sha256").exists():
            final.unlink(missing_ok=True)
        Path(str(final) + ".sha256.partial").unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(snapshot_stage, ignore_errors=True)
