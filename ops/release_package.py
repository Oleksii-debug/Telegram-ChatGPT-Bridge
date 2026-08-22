# -*- coding: utf-8 -*-
"""Fail-closed validation for the public deployable release package.

The checks in this module operate on public source only. They never read or
materialize Telegram credentials, sessions, bearer values, HOSTiQ private
configuration, or live server state.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Iterable

from ops.release_guard import SafetyError

WSGI_PATH = "passenger_wsgi.py"
RUNTIME_INPUT = "requirements.txt"
RUNTIME_LOCK = "requirements.lock"
TEST_INPUT = "requirements-test.txt"
TEST_LOCK = "requirements-test.lock"

# Exact public runtime closure selected for the Python 3.11 candidate.
# Optional Telethon extra `cryptg` is deliberately absent because correctness
# does not depend on that accelerator.
EXPECTED_RUNTIME_LOCK = {
    "telethon": ("1.44.0", "52fc49efb67a4916c2aedcb295ad286f4afa2aba9bf15d83ed2acdc64af0c718"),
    "pyaes": ("1.6.1", "02c1b1405c38d3c370b085fb952dd8bea3fadcee6411ad99f312cc129c536d8f"),
    "rsa": ("4.9.1", "68635866661c6836b8d39430f97a996acbd61bfa49406748ea243539fe239762"),
    "pyasn1": ("0.6.4", "deda9277cfd454080ec40b207fb6df82206a3a2688735233cdcd8d3d565f088b"),
}
DIRECT_RUNTIME = {"telethon": "1.44.0"}

_PRIVATE_PARTS = {
    ".env", "var", "private", "sessions", "session", "credentials.json",
    "token.json", "cookies", "browser-profile", "browser_profiles",
}
_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)(?:\s+--hash=sha256:([0-9a-f]{64}))?$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _logical_requirement_lines(path: Path) -> list[str]:
    try:
        physical = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise SafetyError("release dependency file is unreadable") from exc
    logical: list[str] = []
    current = ""
    for raw in physical:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            current += line[:-1].strip() + " "
            continue
        current += line
        logical.append(" ".join(current.split()))
        current = ""
    if current:
        raise SafetyError("release dependency file has unterminated continuation")
    return logical


def _parse_requirements(path: Path, *, hashes_required: bool) -> dict[str, tuple[str, str | None]]:
    parsed: dict[str, tuple[str, str | None]] = {}
    for line in _logical_requirement_lines(path):
        match = _REQUIREMENT_RE.fullmatch(line)
        if not match:
            raise SafetyError("release dependency entry is not an exact supported pin")
        name = match.group(1).casefold().replace("_", "-")
        version = match.group(2)
        digest = match.group(3)
        if hashes_required and digest is None:
            raise SafetyError("release lock entry is missing SHA-256")
        if name in parsed:
            raise SafetyError("release dependency appears more than once")
        parsed[name] = (version, digest)
    return parsed


def _valid_wsgi_all_assignment(node: ast.Assign) -> bool:
    if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name) or node.targets[0].id != "__all__":
        return False
    if not isinstance(node.value, (ast.List, ast.Tuple)) or len(node.value.elts) != 1:
        return False
    element = node.value.elts[0]
    return isinstance(element, ast.Constant) and element.value == "application"


def validate_wsgi_contract(root: Path) -> dict[str, str]:
    path = root / WSGI_PATH
    if not path.is_file() or path.is_symlink():
        raise SafetyError("canonical Passenger WSGI entrypoint is missing or unsafe")
    try:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=WSGI_PATH)
    except (OSError, UnicodeError, SyntaxError) as exc:
        raise SafetyError("canonical Passenger WSGI entrypoint is invalid") from exc

    import_seen = False
    all_seen = False
    for index, node in enumerate(tree.body):
        if (
            index == 0
            and isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            continue
        if isinstance(node, ast.ImportFrom):
            if import_seen or node.level != 0 or node.module != "bridge.app":
                raise SafetyError("Passenger WSGI entrypoint has unexpected import")
            if [(alias.name, alias.asname) for alias in node.names] != [("application", None)]:
                raise SafetyError("Passenger WSGI entrypoint must expose the recovered application symbol")
            import_seen = True
            continue
        if isinstance(node, ast.Assign) and _valid_wsgi_all_assignment(node):
            if all_seen:
                raise SafetyError("Passenger WSGI entrypoint repeats __all__")
            all_seen = True
            continue
        # A Passenger bootstrap must remain a minimal import shim. Reject calls,
        # definitions, conditionals and all other executable/structural statements.
        raise SafetyError("Passenger WSGI entrypoint contains unexpected executable statement")
    if not import_seen:
        raise SafetyError("Passenger WSGI entrypoint must import from bridge.app")
    return {"path": WSGI_PATH, "sha256": sha256_file(path)}


def validate_dependency_contract(root: Path) -> dict[str, object]:
    input_path = root / RUNTIME_INPUT
    lock_path = root / RUNTIME_LOCK
    if not input_path.is_file() or input_path.is_symlink():
        raise SafetyError("canonical runtime requirements input is missing or unsafe")
    if not lock_path.is_file() or lock_path.is_symlink():
        raise SafetyError("runtime requirements input exists without an immutable lock")

    direct = _parse_requirements(input_path, hashes_required=False)
    if {name: version for name, (version, _digest) in direct.items()} != DIRECT_RUNTIME:
        raise SafetyError("direct runtime dependency set differs from reviewed release contract")

    locked = _parse_requirements(lock_path, hashes_required=True)
    actual = {name: (version, digest) for name, (version, digest) in locked.items()}
    if actual != EXPECTED_RUNTIME_LOCK:
        raise SafetyError("runtime dependency lock differs from reviewed exact closure")

    test_input = root / TEST_INPUT
    test_lock = root / TEST_LOCK
    if test_input.exists() or test_lock.exists():
        if not (test_input.is_file() and test_lock.is_file()) or test_input.is_symlink() or test_lock.is_symlink():
            raise SafetyError("test dependency files are incomplete or unsafe")
        if not _parse_requirements(test_input, hashes_required=False):
            raise SafetyError("empty test dependency input must be omitted")
        _parse_requirements(test_lock, hashes_required=True)

    return {
        "input_sha256": sha256_file(input_path),
        "lock_sha256": sha256_file(lock_path),
        "package_count": len(locked),
        "test_dependencies_present": test_input.exists(),
    }


def _is_private_runtime_path(rel: str) -> bool:
    parts = PurePosixPath(rel).parts
    lowered = tuple(part.casefold() for part in parts)
    if any(part in _PRIVATE_PARTS for part in lowered):
        return True
    if any(part.endswith(".session") or part.endswith(".session-journal") for part in lowered):
        return True
    if any(part.startswith(".env.") for part in lowered):
        return True
    return False


def validate_public_release_tree(root: Path, paths: Iterable[str] | None = None) -> dict[str, object]:
    root = root.resolve(strict=True)
    if paths is None:
        candidates = [path.relative_to(root).as_posix() for path in root.rglob("*") if not path.is_dir()]
    else:
        candidates = [str(path) for path in paths]
    normalized = sorted(set(candidates))
    for rel in normalized:
        posix = PurePosixPath(rel)
        if posix.is_absolute() or ".." in posix.parts or _is_private_runtime_path(rel):
            raise SafetyError("private/runtime artifact is forbidden from public release payload")
    wsgi = validate_wsgi_contract(root)
    deps = validate_dependency_contract(root)
    return {
        "schema_version": 1,
        "wsgi": wsgi,
        "dependencies": deps,
        "tracked_path_count": len(normalized),
    }


def build_release_identity(root: Path, *, sha: str, repository: str) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise SafetyError("release identity requires an exact Git SHA")
    if repository != "Oleksii-debug/Telegram-ChatGPT-Bridge":
        raise SafetyError("release identity repository mismatch")
    validation = validate_public_release_tree(root)
    payload = {
        "schema_version": 1,
        "repository": repository,
        "sha": sha,
        "startup": validation["wsgi"],
        "dependencies": validation["dependencies"],
        "private_values_recorded": False,
        "deployment_authorized": False,
    }
    # Stable hash lets private HOSTiQ evidence bind to this non-secret identity.
    payload["identity_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return payload
