# -*- coding: utf-8 -*-
"""Hermetic, privacy-safe H1/H2 Action evidence bound to one Git checkout.

No candidate schema/runtime module is imported before a clean checkout binding
exists. This module performs no network, Telegram, credential, write, deploy,
restart, or production operation. Every summary remains non-authorizing.
"""
from __future__ import annotations

import errno
import hashlib
import importlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, Mapping
from urllib.parse import urlsplit

PRODUCTION_BASE_URL = "https://tg-api.rukadopomogy.org.ua"
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_CAPTURE_BYTES = 64 * 1024
_ALLOWED_SOURCE_CLASSIFICATIONS = {"SOURCE_MOCK", "DEPLOYED_CAPTURE"}
_ALLOWED_MISMATCH_CODES = frozenset({
    "DOCUMENT_DIGEST_DRIFT", "OBSERVED_SCHEMA_VALIDATION_FAILED",
    "OPERATION_CONTRACT_DRIFT", "OPERATION_COUNT_DRIFT", "PATH_SET_DRIFT",
    "ROOT_SECURITY_DRIFT", "SERVER_ORIGIN_DRIFT",
})
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_DANGEROUS_ENVIRONMENT = frozenset({
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_CEILING_DIRECTORIES",
    "GIT_CONFIG", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_EXEC_PATH",
    "GIT_EXTERNAL_DIFF", "GIT_DIFF_OPTS", "GIT_SSH", "GIT_SSH_COMMAND",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONINSPECT",
    "PYTHONPYCACHEPREFIX",
})
_SOURCE_PREFIXES = ("bridge/", "ops/", "tools/")
_BOOTSTRAP_PATHS = frozenset({
    "ops/__init__.py", "ops/dev06_deployed_action_evidence.py",
    "tools/verify_dev06_deployed_action.py", "tools/verify_dev06_action_e2e.py",
})


class DeployedActionEvidenceError(RuntimeError):
    """Fail-closed evidence error with a stable, non-secret public code."""


def _stat_fingerprint(info: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_size,
        getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000)),
        getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000)),
    )


def _is_reparse_or_link(info: os.stat_result) -> bool:
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(attributes & reparse_flag)


def _checked_absolute_directory(value: str | os.PathLike[str] | Path) -> Path:
    try:
        raw = Path(value)
    except (TypeError, ValueError):
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_UNSAFE") from None
    if not raw.parts or ".." in raw.parts:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_UNSAFE")
    absolute = Path(os.path.abspath(os.fspath(raw)))
    current = Path(absolute.anchor)
    try:
        for part in absolute.parts[1:]:
            current = current / part
            if _is_reparse_or_link(current.lstat()):
                raise OSError
        if not stat.S_ISDIR(absolute.lstat().st_mode):
            raise OSError
    except OSError:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_UNSAFE") from None
    return absolute


def _trusted_git_executable() -> Path:
    candidates: list[Path]
    if os.name == "nt":
        # Do not derive executable locations from mutable process environment.
        candidates = [
            Path(r"C:\Program Files\Git\cmd\git.exe"),
            Path(r"C:\Program Files\Git\bin\git.exe"),
            Path(r"C:\Program Files (x86)\Git\cmd\git.exe"),
            Path(r"C:\Program Files (x86)\Git\bin\git.exe"),
        ]
    else:
        candidates = [Path("/usr/bin/git"), Path("/usr/local/bin/git")]
    for candidate in candidates:
        try:
            absolute = Path(os.path.abspath(os.fspath(candidate)))
            info = absolute.lstat()
            if _is_reparse_or_link(info) or not stat.S_ISREG(info.st_mode):
                continue
            if os.name != "nt" and info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                continue
            return absolute
        except OSError:
            continue
    raise DeployedActionEvidenceError("SOURCE_CHECKOUT_GIT_UNAVAILABLE")


_TRUSTED_GIT = _trusted_git_executable()


def _reject_hostile_process_environment() -> None:
    if any(os.environ.get(name) for name in _DANGEROUS_ENVIRONMENT):
        raise DeployedActionEvidenceError("SOURCE_EXECUTION_ENVIRONMENT_UNSAFE")


def _git_environment() -> dict[str, str]:
    env: dict[str, str] = {
        "PATH": os.pathsep.join((os.fspath(_TRUSTED_GIT.parent), os.defpath)),
        "LC_ALL": "C", "LANG": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _run_git(root: Path, *args: str, text: bool = True) -> str | bytes:
    try:
        proc = subprocess.run(
            [os.fspath(_TRUSTED_GIT), *args], cwd=root, env=_git_environment(),
            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=text, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_GIT_UNAVAILABLE") from None
    if proc.returncode != 0:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_GIT_UNAVAILABLE")
    return proc.stdout


def _source_root(source_checkout: str | os.PathLike[str] | Path) -> Path:
    root = _checked_absolute_directory(source_checkout)
    top = str(_run_git(root, "rev-parse", "--show-toplevel")).strip()
    try:
        top_root = _checked_absolute_directory(top)
    except DeployedActionEvidenceError:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_UNSAFE") from None
    if os.path.normcase(os.fspath(top_root)) != os.path.normcase(os.fspath(root)):
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_NOT_REPOSITORY_ROOT")
    return root


def _execution_checkout_root() -> Path:
    try:
        root = Path(__file__).parents[1]
    except (TypeError, ValueError, IndexError):
        raise DeployedActionEvidenceError("SOURCE_EXECUTION_MODULE_MISMATCH") from None
    checked = _source_root(root)
    try:
        relative = Path(os.path.abspath(__file__)).relative_to(checked).as_posix()
    except (OSError, ValueError):
        raise DeployedActionEvidenceError("SOURCE_EXECUTION_MODULE_MISMATCH") from None
    if relative != "ops/dev06_deployed_action_evidence.py":
        raise DeployedActionEvidenceError("SOURCE_EXECUTION_MODULE_MISMATCH")
    return checked


def _require_clean_worktree(root: Path) -> None:
    status = _run_git(root, "status", "--porcelain=v2", "-z", "--untracked-files=all", text=False)
    if not isinstance(status, bytes) or status:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_ALL_FILES_DIRTY")
    flags = _run_git(root, "ls-files", "-v", "-z", text=False)
    if not isinstance(flags, bytes) or not flags:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_IDENTITY_INVALID")
    for record in flags.split(b"\0"):
        if record and not record.startswith(b"H "):
            raise DeployedActionEvidenceError("SOURCE_CHECKOUT_INDEX_FLAGS_UNSAFE")


def _parse_tree_listing(listing: bytes) -> dict[str, tuple[str, str, str]]:
    entries: dict[str, tuple[str, str, str]] = {}
    try:
        for record in listing.split(b"\0"):
            if not record:
                continue
            metadata, raw_path = record.split(b"\t", 1)
            mode, object_type, oid = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
            if path in entries or not path or path.startswith("/") or ".." in Path(path).parts:
                raise ValueError
            entries[path] = (mode, object_type, oid)
    except (UnicodeError, ValueError):
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_IDENTITY_INVALID") from None
    if not entries:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_IDENTITY_INVALID")
    return entries


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        fd = os.open(os.fspath(path), flags)
    except OSError:
        raise DeployedActionEvidenceError("SOURCE_TRACKED_FILE_UNSAFE") from None
    failure: BaseException | None = None
    data = b""
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size < 0 or before.st_size > maximum:
            raise DeployedActionEvidenceError("SOURCE_TRACKED_FILE_UNSAFE")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        if len(data) > maximum or len(data) != before.st_size or _stat_fingerprint(before) != _stat_fingerprint(after):
            raise DeployedActionEvidenceError("SOURCE_TRACKED_FILE_CHANGED_DURING_READ")
    except BaseException as exc:
        failure = exc
    finally:
        try:
            os.close(fd)
        except OSError:
            if failure is None:
                failure = DeployedActionEvidenceError("SOURCE_TRACKED_FILE_CLOSE_FAILED")
    if failure is not None:
        if isinstance(failure, DeployedActionEvidenceError):
            raise failure
        if isinstance(failure, OSError) and failure.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
            raise DeployedActionEvidenceError("SOURCE_TRACKED_FILE_UNSAFE") from None
        raise DeployedActionEvidenceError("SOURCE_TRACKED_FILE_UNSAFE") from None
    return data


def _git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _prove_python_source_blobs(root: Path, entries: Mapping[str, tuple[str, str, str]]) -> tuple[str, int]:
    proof: list[str] = []
    for path in sorted(entries):
        if not path.endswith(".py") or not (path == "passenger_wsgi.py" or path.startswith(_SOURCE_PREFIXES)):
            continue
        mode, object_type, oid = entries[path]
        if mode not in {"100644", "100755"} or object_type != "blob" or _SHA40_RE.fullmatch(oid) is None:
            raise DeployedActionEvidenceError("SOURCE_PYTHON_BLOB_IDENTITY_INVALID")
        data = _read_regular_file(root / Path(path), maximum=4 * 1024 * 1024)
        if _git_blob_sha1(data) != oid:
            raise DeployedActionEvidenceError("SOURCE_PYTHON_BLOB_MISMATCH")
        proof.append(f"{path}\0{oid}")
    if not proof:
        raise DeployedActionEvidenceError("SOURCE_PYTHON_BLOB_IDENTITY_INVALID")
    return hashlib.sha256("\n".join(proof).encode("utf-8")).hexdigest(), len(proof)


def derive_source_binding(source_checkout: str | os.PathLike[str] | Path) -> dict[str, Any]:
    """Derive immutable identity from the exact clean executing checkout."""
    _reject_hostile_process_environment()
    root = _source_root(source_checkout)
    if root != _execution_checkout_root():
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_EXECUTION_MISMATCH")
    _require_clean_worktree(root)
    sha = str(_run_git(root, "rev-parse", "--verify", "HEAD^{commit}")).strip()
    if _SHA40_RE.fullmatch(sha) is None:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_IDENTITY_INVALID")
    tree_sha = str(_run_git(root, "rev-parse", "--verify", f"{sha}^{{tree}}")).strip()
    listing = _run_git(root, "ls-tree", "-r", "-z", "--full-tree", sha, text=False)
    if not isinstance(listing, bytes) or _SHA40_RE.fullmatch(tree_sha) is None:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_IDENTITY_INVALID")
    entries = _parse_tree_listing(listing)
    python_digest, python_count = _prove_python_source_blobs(root, entries)
    _require_clean_worktree(root)
    if str(_run_git(root, "rev-parse", "--verify", "HEAD^{commit}")).strip() != sha:
        raise DeployedActionEvidenceError("SOURCE_CHECKOUT_CHANGED_DURING_BINDING")
    base = {
        "schema_version": 2, "identity_source": "EXECUTING_EXACT_GIT_CHECKOUT",
        "candidate_sha": sha, "source_tree_sha": tree_sha,
        "source_tree_listing_sha256": hashlib.sha256(listing).hexdigest(),
        "source_python_blobs_sha256": python_digest,
        "source_python_file_count": python_count, "private_values_recorded": False,
    }
    digest = hashlib.sha256(json.dumps(base, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest()
    return {**base, "source_binding_sha256": digest}


def _validate_source_binding(binding: Mapping[str, Any], source_checkout: str | os.PathLike[str] | Path) -> dict[str, Any]:
    expected = derive_source_binding(source_checkout)
    if not isinstance(binding, Mapping) or dict(binding) != expected:
        raise DeployedActionEvidenceError("SOURCE_BINDING_MISMATCH")
    return expected


_BOUND_SHA: str | None = None
_BOUND_MODULES: tuple[ModuleType, ModuleType] | None = None


def _candidate_modules_preloaded(root: Path) -> bool:
    for module in tuple(sys.modules.values()):
        value = getattr(module, "__file__", None)
        if not isinstance(value, str) or not value:
            continue
        try:
            relative = Path(os.path.abspath(value)).relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if relative not in _BOOTSTRAP_PATHS:
            return True
    return False


def _schema_modules(binding: Mapping[str, Any], root: Path) -> tuple[ModuleType, ModuleType]:
    global _BOUND_SHA, _BOUND_MODULES
    candidate_sha = str(binding["candidate_sha"])
    if _BOUND_MODULES is not None:
        if _BOUND_SHA != candidate_sha:
            raise DeployedActionEvidenceError("SOURCE_SCHEMA_MODULE_BINDING_MISMATCH")
        _validate_source_binding(binding, root)
        return _BOUND_MODULES
    if _candidate_modules_preloaded(root):
        raise DeployedActionEvidenceError("SOURCE_SCHEMA_MODULE_PRELOADED")
    importlib.invalidate_caches()
    previous_prefix = sys.pycache_prefix
    previous_dont_write = sys.dont_write_bytecode
    try:
        with tempfile.TemporaryDirectory(prefix="w09-pycache-") as pycache:
            sys.pycache_prefix = pycache
            sys.dont_write_bytecode = True
            api = importlib.import_module("ops.dev06_api_contracts")
            runtime = importlib.import_module("ops.dev06_runtime_conformance")
    except Exception:
        raise DeployedActionEvidenceError("SOURCE_SCHEMA_MODULE_IMPORT_FAILED") from None
    finally:
        sys.pycache_prefix = previous_prefix
        sys.dont_write_bytecode = previous_dont_write
    _validate_source_binding(binding, root)
    for module, expected_path in ((api, "ops/dev06_api_contracts.py"), (runtime, "ops/dev06_runtime_conformance.py")):
        value = getattr(module, "__file__", None)
        if not isinstance(value, str):
            raise DeployedActionEvidenceError("SOURCE_EXECUTION_MODULE_MISMATCH")
        try:
            relative = Path(os.path.abspath(value)).relative_to(root).as_posix()
        except (OSError, ValueError):
            raise DeployedActionEvidenceError("SOURCE_EXECUTION_MODULE_MISMATCH") from None
        if relative != expected_path:
            raise DeployedActionEvidenceError("SOURCE_EXECUTION_MODULE_MISMATCH")
    _BOUND_SHA, _BOUND_MODULES = candidate_sha, (api, runtime)
    return _BOUND_MODULES


def _require_source_classification(value: str) -> str:
    raw = str(value or "").strip().upper()
    if raw not in _ALLOWED_SOURCE_CLASSIFICATIONS:
        raise DeployedActionEvidenceError("SOURCE_CLASSIFICATION_INVALID")
    return raw


def _require_base_url(value: str) -> str:
    raw = str(value or "").strip()
    parts = urlsplit(raw)
    if parts.scheme != "https" or not parts.netloc or parts.username is not None or parts.password is not None or parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise DeployedActionEvidenceError("BASE_URL_INVALID")
    normalized = raw[:-1] if raw.endswith("/") else raw
    if normalized != PRODUCTION_BASE_URL:
        raise DeployedActionEvidenceError("BASE_URL_NOT_PRODUCTION")
    return normalized


def canonical_json_bytes(document: Mapping[str, Any], *, maximum: int = MAX_SCHEMA_BYTES) -> bytes:
    if not isinstance(document, Mapping):
        raise DeployedActionEvidenceError("SCHEMA_DOCUMENT_NOT_OBJECT")
    try:
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise DeployedActionEvidenceError("SCHEMA_DOCUMENT_NOT_CANONICAL_JSON") from None
    if not encoded or len(encoded) > maximum:
        raise DeployedActionEvidenceError("SCHEMA_DOCUMENT_SIZE_INVALID")
    return encoded


def schema_sha256(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(document)).hexdigest()


def _declared_operation_count(document: Mapping[str, Any]) -> int:
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return 0
    return sum(1 for item in paths.values() if isinstance(item, Mapping) for operation in item.values() if isinstance(operation, Mapping) and isinstance(operation.get("operationId"), str))


def _expected_action_routes(api: ModuleType) -> tuple[Any, ...]:
    return tuple(route for route in api.CANONICAL_ROUTES if route.exposure is api.ApiExposure.ACTION)


def _operation_drift_count(expected: Mapping[str, Any], observed: Mapping[str, Any], api: ModuleType) -> int:
    expected_paths, observed_paths = expected.get("paths"), observed.get("paths")
    if not isinstance(expected_paths, Mapping) or not isinstance(observed_paths, Mapping):
        return len(_expected_action_routes(api))
    drift = 0
    for route in _expected_action_routes(api):
        exp_item, obs_item = expected_paths.get(route.path), observed_paths.get(route.path)
        exp_op = exp_item.get("post") if isinstance(exp_item, Mapping) else None
        obs_op = obs_item.get("post") if isinstance(obs_item, Mapping) else None
        if not isinstance(exp_op, Mapping) or not isinstance(obs_op, Mapping) or canonical_json_bytes(exp_op) != canonical_json_bytes(obs_op):
            drift += 1
    return drift


def compare_deployed_action_schema(source_checkout: str | os.PathLike[str] | Path, observed_document: Mapping[str, Any], *, base_url: str = PRODUCTION_BASE_URL, source_classification: str = "SOURCE_MOCK") -> dict[str, Any]:
    root = _source_root(source_checkout)
    binding = derive_source_binding(root)
    source, origin = _require_source_classification(source_classification), _require_base_url(base_url)
    api, runtime = _schema_modules(binding, root)
    expected = runtime.build_compatible_chatgpt_action_openapi(origin)
    expected_bytes, observed_bytes = canonical_json_bytes(expected), canonical_json_bytes(observed_document)
    expected_digest, observed_digest = hashlib.sha256(expected_bytes).hexdigest(), hashlib.sha256(observed_bytes).hexdigest()
    mismatch_codes: list[str] = []
    try:
        observed_validation = runtime.validate_action_compatibility(observed_document)
    except Exception:
        observed_validation = ["invalid"]
    if observed_validation:
        mismatch_codes.append("OBSERVED_SCHEMA_VALIDATION_FAILED")
    if set(expected.get("paths", {})) != set(observed_document.get("paths", {})):
        mismatch_codes.append("PATH_SET_DRIFT")
    if expected.get("servers") != observed_document.get("servers"):
        mismatch_codes.append("SERVER_ORIGIN_DRIFT")
    if expected.get("security") != observed_document.get("security"):
        mismatch_codes.append("ROOT_SECURITY_DRIFT")
    expected_count, observed_count = _declared_operation_count(expected), _declared_operation_count(observed_document)
    if expected_count != observed_count:
        mismatch_codes.append("OPERATION_COUNT_DRIFT")
    operation_drift_count = _operation_drift_count(expected, observed_document, api)
    if operation_drift_count:
        mismatch_codes.append("OPERATION_CONTRACT_DRIFT")
    if expected_digest != observed_digest:
        mismatch_codes.append("DOCUMENT_DIGEST_DRIFT")
    mismatch_codes = sorted(set(mismatch_codes))
    summary: dict[str, Any] = {
        "schema_version": 3, "candidate_sha": binding["candidate_sha"],
        "source_tree_sha": binding["source_tree_sha"],
        "source_tree_listing_sha256": binding["source_tree_listing_sha256"],
        "source_python_blobs_sha256": binding["source_python_blobs_sha256"],
        "source_python_file_count": binding["source_python_file_count"],
        "source_binding_sha256": binding["source_binding_sha256"],
        "source_classification": source,
        "server_origin_sha256": hashlib.sha256(origin.encode("utf-8")).hexdigest(),
        "expected_schema_sha256": expected_digest, "observed_schema_sha256": observed_digest,
        "expected_schema_bytes": len(expected_bytes), "observed_schema_bytes": len(observed_bytes),
        "expected_operation_count": expected_count, "observed_operation_count": observed_count,
        "operation_drift_count": operation_drift_count, "mismatch_count": len(mismatch_codes),
        "mismatch_codes": mismatch_codes, "schema_match": not mismatch_codes,
        "product_h1_pass": False, "self_authorization": False,
        "deployment_authorized": False, "production_mutated": False,
        "private_values_recorded": False,
    }
    validate_evidence_summary(summary, root)
    return summary


def validate_evidence_summary(summary: Mapping[str, Any], source_checkout: str | os.PathLike[str] | Path) -> None:
    required = {
        "schema_version", "candidate_sha", "source_tree_sha", "source_tree_listing_sha256",
        "source_python_blobs_sha256", "source_python_file_count", "source_binding_sha256",
        "source_classification", "server_origin_sha256", "expected_schema_sha256",
        "observed_schema_sha256", "expected_schema_bytes", "observed_schema_bytes",
        "expected_operation_count", "observed_operation_count", "operation_drift_count",
        "mismatch_count", "mismatch_codes", "schema_match", "product_h1_pass",
        "self_authorization", "deployment_authorized", "production_mutated", "private_values_recorded",
    }
    if not isinstance(summary, Mapping) or set(summary) != required or summary.get("schema_version") != 3:
        raise DeployedActionEvidenceError("EVIDENCE_SUMMARY_SHAPE_INVALID")
    root = _source_root(source_checkout)
    binding = derive_source_binding(root)
    for key in ("candidate_sha", "source_tree_sha", "source_tree_listing_sha256", "source_python_blobs_sha256", "source_python_file_count", "source_binding_sha256"):
        if summary.get(key) != binding[key]:
            raise DeployedActionEvidenceError("EVIDENCE_SOURCE_BINDING_INVALID")
    _require_source_classification(str(summary.get("source_classification")))
    if _SHA40_RE.fullmatch(str(summary.get("candidate_sha", ""))) is None or _SHA40_RE.fullmatch(str(summary.get("source_tree_sha", ""))) is None:
        raise DeployedActionEvidenceError("EVIDENCE_SOURCE_BINDING_INVALID")
    for key in ("source_tree_listing_sha256", "source_python_blobs_sha256", "source_binding_sha256", "server_origin_sha256", "expected_schema_sha256", "observed_schema_sha256"):
        if not isinstance(summary.get(key), str) or _SHA256_RE.fullmatch(str(summary[key])) is None:
            raise DeployedActionEvidenceError("EVIDENCE_DIGEST_INVALID")
    for key in ("source_python_file_count", "expected_schema_bytes", "observed_schema_bytes", "expected_operation_count", "observed_operation_count", "operation_drift_count", "mismatch_count"):
        if isinstance(summary.get(key), bool) or not isinstance(summary.get(key), int) or summary[key] < 0:
            raise DeployedActionEvidenceError("EVIDENCE_COUNT_INVALID")
    if summary["source_python_file_count"] > 10000 or summary["expected_schema_bytes"] > MAX_SCHEMA_BYTES or summary["observed_schema_bytes"] > MAX_SCHEMA_BYTES or summary["expected_operation_count"] > 1024 or summary["observed_operation_count"] > 1024 or summary["operation_drift_count"] > 1024:
        raise DeployedActionEvidenceError("EVIDENCE_COUNT_INVALID")
    codes = summary.get("mismatch_codes")
    if not isinstance(codes, list) or codes != sorted(set(codes)) or any(code not in _ALLOWED_MISMATCH_CODES for code in codes) or summary["mismatch_count"] != len(codes):
        raise DeployedActionEvidenceError("EVIDENCE_MISMATCH_CODES_INVALID")
    for key in ("schema_match", "product_h1_pass", "self_authorization", "deployment_authorized", "production_mutated", "private_values_recorded"):
        if not isinstance(summary.get(key), bool):
            raise DeployedActionEvidenceError("EVIDENCE_BOOLEAN_INVALID")
    if any(summary[key] for key in ("product_h1_pass", "self_authorization", "deployment_authorized", "production_mutated", "private_values_recorded")):
        raise DeployedActionEvidenceError("EVIDENCE_MUST_NOT_SELF_AUTHORIZE_OR_RECORD_PRIVATE_VALUES")
    _api, runtime = _schema_modules(binding, root)
    expected = runtime.build_compatible_chatgpt_action_openapi(PRODUCTION_BASE_URL)
    expected_bytes = canonical_json_bytes(expected)
    if summary["server_origin_sha256"] != hashlib.sha256(PRODUCTION_BASE_URL.encode("utf-8")).hexdigest() or summary["expected_schema_sha256"] != hashlib.sha256(expected_bytes).hexdigest() or summary["expected_schema_bytes"] != len(expected_bytes) or summary["expected_operation_count"] != _declared_operation_count(expected):
        raise DeployedActionEvidenceError("EVIDENCE_SOURCE_SCHEMA_BINDING_INVALID")
    derived = bool(summary["mismatch_count"] == 0 and summary["expected_schema_sha256"] == summary["observed_schema_sha256"] and summary["expected_schema_bytes"] == summary["observed_schema_bytes"] and summary["expected_operation_count"] == summary["observed_operation_count"] and summary["operation_drift_count"] == 0)
    if summary["schema_match"] is not derived:
        raise DeployedActionEvidenceError("EVIDENCE_MATCH_STATE_INVALID")


def _load_json_file(path: str | Path, *, maximum: int, label: str) -> Mapping[str, Any]:
    try:
        data = _read_regular_file(Path(path), maximum=maximum)
    except DeployedActionEvidenceError:
        raise DeployedActionEvidenceError(f"{label}_FILE_UNSAFE") from None
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError):
        raise DeployedActionEvidenceError(f"{label}_JSON_INVALID") from None
    if not isinstance(parsed, Mapping):
        raise DeployedActionEvidenceError(f"{label}_JSON_NOT_OBJECT")
    canonical_json_bytes(parsed, maximum=maximum)
    return parsed


def load_observed_schema(path: str | Path) -> Mapping[str, Any]:
    return _load_json_file(path, maximum=MAX_SCHEMA_BYTES, label="OBSERVED_SCHEMA")


def compare_deployed_action_schema_file(source_checkout: str | os.PathLike[str] | Path, observed_path: str | Path, *, source_classification: str = "SOURCE_MOCK") -> dict[str, Any]:
    before = derive_source_binding(source_checkout)
    observed = load_observed_schema(observed_path)
    _validate_source_binding(before, source_checkout)
    summary = compare_deployed_action_schema(source_checkout, observed, source_classification=source_classification)
    _validate_source_binding(before, source_checkout)
    return summary


H2_CAPTURE_KEYS = frozenset({
    "schema_version", "source_classification", "source_binding_sha256", "deployed_sha",
    "operation_id", "method", "http_status", "authorized", "read_only",
    "telegram_read_observed", "request_sha256", "response_sha256",
})


def _validate_h2_capture(capture: Mapping[str, Any], binding: Mapping[str, Any], api: ModuleType) -> dict[str, Any]:
    if not isinstance(capture, Mapping) or set(capture) != H2_CAPTURE_KEYS or capture.get("schema_version") != 1:
        raise DeployedActionEvidenceError("H2_CAPTURE_SHAPE_INVALID")
    source = _require_source_classification(str(capture.get("source_classification")))
    if capture.get("source_binding_sha256") != binding["source_binding_sha256"] or capture.get("deployed_sha") != binding["candidate_sha"]:
        raise DeployedActionEvidenceError("H2_CAPTURE_SOURCE_BINDING_INVALID")
    if capture.get("method") != "POST":
        raise DeployedActionEvidenceError("H2_CAPTURE_METHOD_INVALID")
    try:
        route = api.canonical_action(str(capture.get("operation_id")))
    except Exception:
        raise DeployedActionEvidenceError("H2_CAPTURE_OPERATION_INVALID") from None
    if route.operation_class is not api.ApiOperationClass.READ:
        raise DeployedActionEvidenceError("H2_CAPTURE_WRITE_OPERATION_REJECTED")
    for key in ("authorized", "read_only", "telegram_read_observed"):
        if not isinstance(capture.get(key), bool):
            raise DeployedActionEvidenceError("H2_CAPTURE_BOOLEAN_INVALID")
    if capture["read_only"] is not True or capture["authorized"] is not True:
        raise DeployedActionEvidenceError("H2_CAPTURE_READ_AUTHORITY_INVALID")
    if source == "DEPLOYED_CAPTURE" and capture["telegram_read_observed"] is not True:
        raise DeployedActionEvidenceError("H2_CAPTURE_LIVE_READ_MISSING")
    status = capture.get("http_status")
    if isinstance(status, bool) or not isinstance(status, int) or not (200 <= status <= 299):
        raise DeployedActionEvidenceError("H2_CAPTURE_STATUS_INVALID")
    for key in ("request_sha256", "response_sha256"):
        if not isinstance(capture.get(key), str) or _SHA256_RE.fullmatch(str(capture[key])) is None:
            raise DeployedActionEvidenceError("H2_CAPTURE_DIGEST_INVALID")
    cleaned = dict(capture)
    cleaned["source_classification"] = source
    return cleaned


def build_h2_capture(source_checkout: str | os.PathLike[str] | Path, *, operation_id: str, request_sha256: str, response_sha256: str, http_status: int, authorized: bool, telegram_read_observed: bool, source_classification: str = "SOURCE_MOCK") -> dict[str, Any]:
    root = _source_root(source_checkout)
    binding = derive_source_binding(root)
    api, _runtime = _schema_modules(binding, root)
    capture = {
        "schema_version": 1, "source_classification": source_classification,
        "source_binding_sha256": binding["source_binding_sha256"],
        "deployed_sha": binding["candidate_sha"], "operation_id": operation_id,
        "method": "POST", "http_status": http_status, "authorized": authorized,
        "read_only": True, "telegram_read_observed": telegram_read_observed,
        "request_sha256": request_sha256, "response_sha256": response_sha256,
    }
    result = _validate_h2_capture(capture, binding, api)
    _validate_source_binding(binding, root)
    return result


def summarize_h2_capture(source_checkout: str | os.PathLike[str] | Path, capture: Mapping[str, Any]) -> dict[str, Any]:
    root = _source_root(source_checkout)
    binding = derive_source_binding(root)
    api, _runtime = _schema_modules(binding, root)
    cleaned = _validate_h2_capture(capture, binding, api)
    summary = {
        "schema_version": 1, "candidate_sha": binding["candidate_sha"],
        "source_tree_sha": binding["source_tree_sha"],
        "source_binding_sha256": binding["source_binding_sha256"],
        "source_classification": cleaned["source_classification"],
        "operation_id": cleaned["operation_id"], "request_sha256": cleaned["request_sha256"],
        "response_sha256": cleaned["response_sha256"], "http_status": cleaned["http_status"],
        "authorized": cleaned["authorized"], "read_only": True,
        "telegram_read_observed": cleaned["telegram_read_observed"],
        "product_h2_pass": False, "self_authorization": False,
        "deployment_authorized": False, "production_mutated": False,
        "private_values_recorded": False,
    }
    validate_h2_summary(summary, root)
    return summary


def validate_h2_summary(summary: Mapping[str, Any], source_checkout: str | os.PathLike[str] | Path) -> None:
    required = {
        "schema_version", "candidate_sha", "source_tree_sha", "source_binding_sha256",
        "source_classification", "operation_id", "request_sha256", "response_sha256",
        "http_status", "authorized", "read_only", "telegram_read_observed",
        "product_h2_pass", "self_authorization", "deployment_authorized",
        "production_mutated", "private_values_recorded",
    }
    if not isinstance(summary, Mapping) or set(summary) != required or summary.get("schema_version") != 1:
        raise DeployedActionEvidenceError("H2_SUMMARY_SHAPE_INVALID")
    root = _source_root(source_checkout)
    binding = derive_source_binding(root)
    for key in ("candidate_sha", "source_tree_sha", "source_binding_sha256"):
        if summary.get(key) != binding[key]:
            raise DeployedActionEvidenceError("H2_SUMMARY_SOURCE_BINDING_INVALID")
    for key in ("request_sha256", "response_sha256"):
        if not isinstance(summary.get(key), str) or _SHA256_RE.fullmatch(str(summary[key])) is None:
            raise DeployedActionEvidenceError("H2_SUMMARY_DIGEST_INVALID")
    for key in ("authorized", "read_only", "telegram_read_observed", "product_h2_pass", "self_authorization", "deployment_authorized", "production_mutated", "private_values_recorded"):
        if not isinstance(summary.get(key), bool):
            raise DeployedActionEvidenceError("H2_SUMMARY_BOOLEAN_INVALID")
    if any(summary[key] for key in ("product_h2_pass", "self_authorization", "deployment_authorized", "production_mutated", "private_values_recorded")):
        raise DeployedActionEvidenceError("H2_SUMMARY_MUST_NOT_SELF_AUTHORIZE")
    if summary["authorized"] is not True or summary["read_only"] is not True:
        raise DeployedActionEvidenceError("H2_SUMMARY_READ_AUTHORITY_INVALID")
    _require_source_classification(str(summary["source_classification"]))
    if summary["source_classification"] == "DEPLOYED_CAPTURE" and summary["telegram_read_observed"] is not True:
        raise DeployedActionEvidenceError("H2_SUMMARY_LIVE_READ_MISSING")
    status = summary.get("http_status")
    if isinstance(status, bool) or not isinstance(status, int) or not (200 <= status <= 299):
        raise DeployedActionEvidenceError("H2_SUMMARY_STATUS_INVALID")
    api, _runtime = _schema_modules(binding, root)
    try:
        route = api.canonical_action(str(summary.get("operation_id")))
    except Exception:
        raise DeployedActionEvidenceError("H2_SUMMARY_OPERATION_INVALID") from None
    if route.operation_class is not api.ApiOperationClass.READ:
        raise DeployedActionEvidenceError("H2_SUMMARY_WRITE_OPERATION_REJECTED")


def summarize_h2_capture_file(source_checkout: str | os.PathLike[str] | Path, capture_path: str | Path) -> dict[str, Any]:
    before = derive_source_binding(source_checkout)
    capture = _load_json_file(capture_path, maximum=MAX_CAPTURE_BYTES, label="H2_CAPTURE")
    _validate_source_binding(before, source_checkout)
    summary = summarize_h2_capture(source_checkout, capture)
    _validate_source_binding(before, source_checkout)
    return summary
