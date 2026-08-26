# -*- coding: utf-8 -*-
"""Fail-closed SQLite-aware backup for private Telegram Bridge state."""
from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote

SQLITE_HEADER = b"SQLite format 3\x00"
SQLITE_SIDECAR_SUFFIXES = ("-wal", "-shm")
SQLITE_FILENAME_SUFFIXES = (".sqlite", ".sqlite3", ".db")


class SQLiteStateBackupError(RuntimeError):
    """Stable fail-closed backup failure; message contains no private values."""


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


def _lstat(path: Path, kind: str) -> os.stat_result:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise SQLiteStateBackupError(f"persistent state {kind} unavailable") from exc
    if not _owner_ok(st):
        raise SQLiteStateBackupError(f"persistent state {kind} owner unsafe")
    return st


def _dir(path: Path) -> os.stat_result:
    st = _lstat(path, "directory")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SQLiteStateBackupError("persistent state directory topology unsafe")
    if _mode(st) & 0o022:
        raise SQLiteStateBackupError("persistent state directory is group/world writable")
    return st


def _file(path: Path) -> os.stat_result:
    st = _lstat(path, "file")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SQLiteStateBackupError("persistent state file topology unsafe")
    if _mode(st) & 0o022:
        raise SQLiteStateBackupError("persistent state file is group/world writable")
    return st


def _walk(root: Path) -> list[tuple[Path, os.stat_result]]:
    out: list[tuple[Path, os.stat_result]] = []
    stack = [root]
    while stack:
        path = stack.pop()
        st = _lstat(path, "entry")
        if stat.S_ISLNK(st.st_mode):
            raise SQLiteStateBackupError("persistent state symlink forbidden")
        if stat.S_ISDIR(st.st_mode):
            _dir(path)
            out.append((path, st))
            try:
                stack.extend(sorted(path.iterdir(), key=lambda item: item.name, reverse=True))
            except OSError as exc:
                raise SQLiteStateBackupError("persistent state enumeration failed") from exc
        elif stat.S_ISREG(st.st_mode):
            _file(path)
            out.append((path, st))
        else:
            raise SQLiteStateBackupError("persistent state special file forbidden")
    return out


def _sidecar_base(path: Path) -> Path | None:
    raw = str(path)
    for suffix in SQLITE_SIDECAR_SUFFIXES:
        if raw.endswith(suffix):
            return Path(raw[:-len(suffix)])
    return None


def _sqlite_named(path: Path) -> bool:
    return path.name.lower().endswith(SQLITE_FILENAME_SUFFIXES)


def _is_sqlite_database(path: Path) -> bool:
    st = _file(path)
    if st.st_size == 0 and _sqlite_named(path):
        # A zero-length file is a valid new SQLite database. Never downgrade it
        # to ordinary raw-copy handling merely because no header exists yet.
        return True
    if st.st_size < len(SQLITE_HEADER):
        if _sqlite_named(path):
            raise SQLiteStateBackupError("database-named persistent file is invalid SQLite")
        return False
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise SQLiteStateBackupError("persistent state file open failed") from exc
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or not _owner_ok(opened)
                or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino)):
            raise SQLiteStateBackupError("persistent state file changed during validation")
        header = os.read(fd, len(SQLITE_HEADER))
    finally:
        os.close(fd)
    if header == SQLITE_HEADER:
        return True
    if _sqlite_named(path):
        raise SQLiteStateBackupError("database-named persistent file is invalid SQLite")
    return False


def _copy_regular(source: Path, destination: Path, expected: os.stat_result) -> None:
    before = _file(source)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
    wanted = (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns)
    if identity != wanted:
        raise SQLiteStateBackupError("non-SQLite persistent file changed before backup")
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    out_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    tmp = destination.with_name(f".{destination.name}.copying")
    if tmp.exists() or tmp.is_symlink():
        raise SQLiteStateBackupError("persistent state snapshot staging collision")
    src_fd = dst_fd = None
    try:
        src_fd = os.open(source, flags)
        opened = os.fstat(src_fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino) or opened.st_nlink != 1 or not _owner_ok(opened):
            raise SQLiteStateBackupError("persistent state file changed before copy")
        dst_fd = os.open(tmp, out_flags, _mode(opened) or 0o600)
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
        after = os.fstat(src_fd)
        actual = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if actual != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns):
            raise SQLiteStateBackupError("non-SQLite persistent file changed during backup")
        os.close(dst_fd); dst_fd = None
        os.replace(tmp, destination)
    except OSError as exc:
        raise SQLiteStateBackupError("non-SQLite persistent file backup failed") from exc
    finally:
        if dst_fd is not None:
            os.close(dst_fd)
        if src_fd is not None:
            os.close(src_fd)
        tmp.unlink(missing_ok=True)


def _sqlite_uri(path: Path) -> str:
    return f"file:{quote(path.as_posix(), safe='/')}?mode=ro"


def _sqlite_backup_verified(source: Path, destination: Path, *, busy_timeout_ms: int) -> None:
    before = _file(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    tmp = destination.with_name(f".{destination.name}.sqlite-backup")
    if tmp.exists() or tmp.is_symlink():
        raise SQLiteStateBackupError("SQLite snapshot staging collision")
    src = dst = None
    try:
        src = sqlite3.connect(_sqlite_uri(source), uri=True, timeout=busy_timeout_ms / 1000, isolation_level=None)
        src.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        src.execute("PRAGMA query_only=ON")
        if src.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise SQLiteStateBackupError("source SQLite quick_check failed")
        dst = sqlite3.connect(str(tmp), timeout=busy_timeout_ms / 1000, isolation_level=None)
        dst.execute(f"PRAGMA busy_timeout={busy_timeout_ms}")
        dst.execute("PRAGMA synchronous=FULL")
        src.backup(dst, pages=256, sleep=0.01)
        if dst.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise SQLiteStateBackupError("SQLite backup quick_check failed")
        # Online backup may copy WAL journal mode. Make the staged copy one
        # self-contained file, then verify it independently of source sidecars.
        dst.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        row = dst.execute("PRAGMA journal_mode=DELETE").fetchone()
        if row is None or str(row[0]).lower() != "delete":
            raise SQLiteStateBackupError("SQLite backup could not become self-contained")
        if dst.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise SQLiteStateBackupError("normalized SQLite backup quick_check failed")
        dst.close(); dst = None
        src.close(); src = None
        after = _file(source)
        if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino):
            raise SQLiteStateBackupError("SQLite database inode changed during backup")
        os.chmod(tmp, _mode(before) or 0o600)
        verify = sqlite3.connect(_sqlite_uri(tmp), uri=True, timeout=busy_timeout_ms / 1000)
        try:
            if verify.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise SQLiteStateBackupError("closed SQLite backup verification failed")
        finally:
            verify.close()
        if any(Path(str(tmp) + suffix).exists() for suffix in SQLITE_SIDECAR_SUFFIXES):
            raise SQLiteStateBackupError("SQLite backup unexpectedly depends on sidecar")
        os.replace(tmp, destination)
    except SQLiteStateBackupError:
        raise
    except (sqlite3.Error, OSError) as exc:
        raise SQLiteStateBackupError("SQLite online backup failed") from exc
    finally:
        if dst is not None:
            dst.close()
        if src is not None:
            src.close()
        tmp.unlink(missing_ok=True)
        for suffix in SQLITE_SIDECAR_SUFFIXES:
            Path(str(tmp) + suffix).unlink(missing_ok=True)


def snapshot_persistent_state(source_root: Path, snapshot_root: Path, *, busy_timeout_ms: int = 5000) -> SQLiteBackupReport:
    if not 1 <= busy_timeout_ms <= 60_000:
        raise ValueError("busy_timeout_ms must be 1..60000")
    source_root = Path(os.path.abspath(source_root))
    snapshot_root = Path(os.path.abspath(snapshot_root))
    _dir(source_root)
    if snapshot_root == source_root or source_root in snapshot_root.parents or snapshot_root in source_root.parents:
        raise SQLiteStateBackupError("snapshot and persistent-state roots overlap")
    if snapshot_root.exists() or snapshot_root.is_symlink():
        raise SQLiteStateBackupError("snapshot root must not pre-exist")
    snapshot_root.mkdir(parents=True, mode=0o700)
    os.chmod(snapshot_root, 0o700)
    try:
        entries = _walk(source_root)
        sqlite_paths: set[Path] = set()
        sidecars: set[Path] = set()
        for path, st in entries:
            if path == source_root or stat.S_ISDIR(st.st_mode):
                continue
            if _sidecar_base(path) is not None:
                sidecars.add(path)
            elif _is_sqlite_database(path):
                sqlite_paths.add(path)
        for sidecar in sidecars:
            base = _sidecar_base(sidecar)
            if base not in sqlite_paths:
                raise SQLiteStateBackupError("orphan SQLite WAL/SHM sidecar")
            _file(sidecar)
        dbs: list[str] = []
        ordinary: list[str] = []
        skipped: list[str] = []
        directories = 0
        for path, st in entries:
            if path == source_root:
                continue
            rel = path.relative_to(source_root)
            dest = snapshot_root / rel
            if stat.S_ISDIR(st.st_mode):
                dest.mkdir(mode=0o700)
                os.chmod(dest, _mode(st))
                directories += 1
            elif path in sidecars:
                skipped.append(rel.as_posix())
            elif path in sqlite_paths:
                _sqlite_backup_verified(path, dest, busy_timeout_ms=busy_timeout_ms)
                dbs.append(rel.as_posix())
            else:
                _copy_regular(path, dest, st)
                ordinary.append(rel.as_posix())
        os.chmod(snapshot_root, 0o700)
        expected = tuple(sorted(dbs))
        verify_persistent_state_snapshot(snapshot_root, expected_sqlite=expected)
        return SQLiteBackupReport(expected, tuple(sorted(ordinary)), tuple(sorted(skipped)), directories)
    except Exception:
        shutil.rmtree(snapshot_root, ignore_errors=True)
        raise


def verify_persistent_state_snapshot(snapshot_root: Path, *, expected_sqlite: tuple[str, ...] | None = None,
                                     busy_timeout_ms: int = 5000) -> tuple[str, ...]:
    snapshot_root = Path(os.path.abspath(snapshot_root))
    _dir(snapshot_root)
    found: list[str] = []
    for path, st in _walk(snapshot_root):
        if path == snapshot_root or stat.S_ISDIR(st.st_mode):
            continue
        if _sidecar_base(path) is not None:
            raise SQLiteStateBackupError("snapshot contains raw SQLite WAL/SHM sidecar")
        if _is_sqlite_database(path):
            con = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=busy_timeout_ms / 1000)
            try:
                con.execute("PRAGMA query_only=ON")
                if con.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise SQLiteStateBackupError("snapshot SQLite quick_check failed")
            finally:
                con.close()
            found.append(path.relative_to(snapshot_root).as_posix())
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


def _fsync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0)))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _backup_root(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    if path.exists() or path.is_symlink():
        st = _dir(path)
        if _mode(st) != 0o700:
            raise SQLiteStateBackupError("backup root must be mode 0700")
        return path
    path.mkdir(parents=True, mode=0o700)
    os.chmod(path, 0o700)
    _dir(path)
    return path


def _archive_paths(root: Path, name: str) -> tuple[Path, Path, Path]:
    if not name.endswith(".tar.gz") or name.startswith(".") or "/" in name or "\\" in name:
        raise SQLiteStateBackupError("invalid private backup archive name")
    stem = name[:-7]
    index = 0
    while True:
        final = root / (name if index == 0 else f"{stem}_{index}.tar.gz")
        pair = Path(str(final) + ".sha256")
        if final.is_symlink() or pair.is_symlink():
            raise SQLiteStateBackupError("private backup target topology unsafe")
        if final.exists() and not pair.exists():
            if _mode(_file(final)) != 0o600:
                raise SQLiteStateBackupError("incomplete private backup mode unsafe")
            final.unlink()
        elif pair.exists() and not final.exists():
            if _mode(_file(pair)) != 0o600:
                raise SQLiteStateBackupError("orphan private backup hash mode unsafe")
            pair.unlink()
        if not final.exists() and not pair.exists():
            break
        index += 1
    partial = root / f".{final.name}.partial"
    snapshot = root / f".{final.name}.snapshot"
    for stale in (partial, snapshot, Path(str(partial) + ".sha256")):
        if stale.is_symlink():
            raise SQLiteStateBackupError("private backup staging topology unsafe")
        if stale.exists():
            if stale.is_dir():
                if _mode(_dir(stale)) != 0o700:
                    raise SQLiteStateBackupError("private backup staging mode unsafe")
                shutil.rmtree(stale)
            else:
                if _mode(_file(stale)) != 0o600:
                    raise SQLiteStateBackupError("private backup staging mode unsafe")
                stale.unlink()
    return final, partial, snapshot


def _write_hash(archive: Path) -> Path:
    sidecar = Path(str(archive) + ".sha256")
    partial = Path(str(sidecar) + ".partial")
    if sidecar.exists() or sidecar.is_symlink() or partial.exists() or partial.is_symlink():
        raise SQLiteStateBackupError("private backup hash target collision")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(partial, flags, 0o600)
    try:
        raw = f"{sha256_path(archive)}  {archive.name}\n".encode("ascii")
        view = memoryview(raw)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise SQLiteStateBackupError("private backup hash write failed")
            view = view[n:]
        os.fsync(fd); os.fchmod(fd, 0o600)
    finally:
        os.close(fd)
    os.replace(partial, sidecar); _fsync(sidecar)
    return sidecar


def verify_archive_hash_pair(archive: Path) -> str:
    archive = Path(os.path.abspath(archive))
    sidecar = Path(str(archive) + ".sha256")
    if _mode(_file(archive)) != 0o600 or _mode(_file(sidecar)) != 0o600:
        raise SQLiteStateBackupError("private backup/hash mode unsafe")
    expected = f"{sha256_path(archive)}  {archive.name}\n"
    try:
        actual = sidecar.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise SQLiteStateBackupError("private backup hash unreadable") from exc
    if actual != expected:
        raise SQLiteStateBackupError("private backup hash mismatch")
    return expected.split("  ", 1)[0]


def _member_path(name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or not path.parts or path.parts[0] != "persistent_state" or any(part in ("", ".", "..") for part in path.parts):
        raise SQLiteStateBackupError("private backup archive path unsafe")
    return path


def _extract_verify(archive: Path, destination: Path) -> Path:
    destination.mkdir(mode=0o700); os.chmod(destination, 0o700)
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle.getmembers():
            rel = _member_path(member.name)
            target = destination.joinpath(*rel.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chmod(target, stat.S_IMODE(member.mode) & 0o777)
                continue
            if not member.isfile() or member.islnk() or member.issym():
                raise SQLiteStateBackupError("private backup archive topology unsafe")
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            source = bundle.extractfile(member)
            if source is None:
                raise SQLiteStateBackupError("private backup archive member unreadable")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_CLOEXEC", 0)) | int(getattr(os, "O_NOFOLLOW", 0))
            fd = os.open(target, flags, stat.S_IMODE(member.mode) & 0o777)
            try:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    view = memoryview(chunk)
                    while view:
                        n = os.write(fd, view)
                        if n <= 0:
                            raise SQLiteStateBackupError("restore verification write failed")
                        view = view[n:]
                os.fsync(fd); os.fchmod(fd, stat.S_IMODE(member.mode) & 0o777)
            finally:
                os.close(fd); source.close()
    restored = destination / "persistent_state"
    _dir(restored)
    return restored


def verify_private_state_archive(archive: Path, *, expected_sqlite: tuple[str, ...] | None = None) -> tuple[str, ...]:
    archive = Path(os.path.abspath(archive))
    if _mode(_file(archive)) != 0o600:
        raise SQLiteStateBackupError("private state archive must be mode 0600")
    root = Path(tempfile.mkdtemp(prefix=".sqlite-restore-verify-", dir=archive.parent))
    os.chmod(root, 0o700)
    try:
        restored = _extract_verify(archive, root / "restore")
        return verify_persistent_state_snapshot(restored, expected_sqlite=expected_sqlite)
    finally:
        shutil.rmtree(root, ignore_errors=True)


def create_private_state_archive(source_root: Path, backup_root: Path, final_name: str, *, busy_timeout_ms: int = 5000) -> tuple[Path, SQLiteBackupReport]:
    backup_root = _backup_root(backup_root)
    source_root = Path(os.path.abspath(source_root))
    if source_root == backup_root or source_root in backup_root.parents or backup_root in source_root.parents:
        raise SQLiteStateBackupError("backup and persistent-state roots overlap")
    final, partial, stage = _archive_paths(backup_root, final_name)
    snapshot = stage / "persistent_state"
    try:
        stage.mkdir(mode=0o700); os.chmod(stage, 0o700)
        report = snapshot_persistent_state(source_root, snapshot, busy_timeout_ms=busy_timeout_ms)
        with tarfile.open(partial, "w:gz", dereference=False) as bundle:
            bundle.add(snapshot, arcname="persistent_state", recursive=True)
        os.chmod(partial, 0o600); _fsync(partial)
        os.replace(partial, final); _fsync(final)
        verify_private_state_archive(final, expected_sqlite=report.sqlite_databases)
        _write_hash(final); verify_archive_hash_pair(final)
        return final, report
    except Exception:
        partial.unlink(missing_ok=True)
        if final.exists() and not Path(str(final) + ".sha256").exists():
            final.unlink(missing_ok=True)
        Path(str(final) + ".sha256.partial").unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(stage, ignore_errors=True)
