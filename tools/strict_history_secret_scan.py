# -*- coding: utf-8 -*-
"""Fail-closed full-history scan with narrow Python reference provenance.

The base secret scanner intentionally treats generic credential aliases as
suspicious. This wrapper suppresses only one false-positive class: a generic
alias whose every Python assignment is proven, within the same straight-line
scope, to derive from a reviewed project-secret environment reference. Literal,
unknown, reassigned, structured, control-flow or malformed sources remain
findings. No secret values are printed or returned.
"""
from __future__ import annotations

import ast
import re
import subprocess
from pathlib import PurePosixPath

from tools import secret_scan

_FINDING_RE = re.compile(r"secret-like assignment ([A-Z0-9_]+) in (.+)$")
_GENERIC = {name.upper() for name in secret_scan.GENERIC_CREDENTIAL_ALIASES}
_PROJECT_ENV = {name.upper() for name in secret_scan.PROJECT_SECRET_VARIABLES}


def _env_reference(expr: ast.AST) -> bool:
    if isinstance(expr, ast.Call):
        if expr.keywords or len(expr.args) != 1:
            return False
        func = expr.func
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "getenv"
            and isinstance(func.value, ast.Name)
            and func.value.id == "os"
        ):
            return False
        arg = expr.args[0]
        return isinstance(arg, ast.Constant) and isinstance(arg.value, str) and arg.value.upper() in _PROJECT_ENV
    if isinstance(expr, ast.Subscript):
        value = expr.value
        if not (
            isinstance(value, ast.Attribute)
            and value.attr == "environ"
            and isinstance(value.value, ast.Name)
            and value.value.id == "os"
        ):
            return False
        key = expr.slice
        return isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.upper() in _PROJECT_ENV
    return False


def _derived_expr(expr: ast.AST, derived: set[str]) -> bool:
    if _env_reference(expr):
        return True
    if isinstance(expr, ast.Name):
        return expr.id in derived
    if (
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Name)
        and expr.func.id == "str"
        and len(expr.args) == 1
        and not expr.keywords
        and isinstance(expr.args[0], ast.Name)
    ):
        return expr.args[0].id in derived
    return False


def _target_names(target: ast.AST) -> set[str]:
    if isinstance(target, ast.Name):
        return {target.id}
    return {node.id for node in ast.walk(target) if isinstance(node, ast.Name)}


def _scope_alias_safety(body: list[ast.stmt], alias_states: dict[str, list[bool]]) -> None:
    derived: set[str] = set()
    for stmt in body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            target = stmt.targets[0]
            safe = _derived_expr(stmt.value, derived)
            if safe:
                derived.add(target.id)
            else:
                derived.discard(target.id)
            if target.id.upper() in _GENERIC:
                alias_states.setdefault(target.id.upper(), []).append(safe)
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            safe = _derived_expr(stmt.value, derived)
            if safe:
                derived.add(stmt.target.id)
            else:
                derived.discard(stmt.target.id)
            if stmt.target.id.upper() in _GENERIC:
                alias_states.setdefault(stmt.target.id.upper(), []).append(safe)

        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.AsyncWith, ast.Match)):
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    targets = node.targets
                elif isinstance(node, ast.AnnAssign):
                    targets = [node.target]
                else:
                    continue
                for target in targets:
                    for name in _target_names(target):
                        if name.upper() in _GENERIC:
                            alias_states.setdefault(name.upper(), []).append(False)
        for node in ast.walk(stmt):
            if isinstance(node, ast.Dict):
                for key in node.keys:
                    if isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.upper() in _GENERIC:
                        alias_states.setdefault(key.value.upper(), []).append(False)


def _proven_safe_generic_aliases(text: str, path: str) -> set[str]:
    if PurePosixPath(path).suffix.casefold() != ".py":
        return set()
    try:
        tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError):
        return set()
    states: dict[str, list[bool]] = {}
    _scope_alias_safety(tree.body, states)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            _scope_alias_safety(node.body, states)
        elif isinstance(node, ast.ClassDef):
            for nested in ast.walk(node):
                if isinstance(nested, ast.Assign):
                    targets = nested.targets
                elif isinstance(nested, ast.AnnAssign):
                    targets = [nested.target]
                else:
                    continue
                for target in targets:
                    for name in _target_names(target):
                        if name.upper() in _GENERIC:
                            states.setdefault(name.upper(), []).append(False)
    return {alias for alias, decisions in states.items() if decisions and all(decisions)}


def _filter_python_reference_false_positives(findings: list[str], blob: bytes, path: str) -> list[str]:
    if not findings or PurePosixPath(path).suffix.casefold() != ".py":
        return findings
    try:
        text = blob.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return findings
    safe_aliases = _proven_safe_generic_aliases(text, path)
    if not safe_aliases:
        return findings
    kept: list[str] = []
    for finding in findings:
        match = _FINDING_RE.search(finding)
        if match and match.group(1).upper() in safe_aliases and match.group(2) == path:
            continue
        kept.append(finding)
    return kept


def scan_history(repo=secret_scan.ROOT) -> list[str]:
    if secret_scan._is_shallow(repo):
        return ["history: repository checkout is shallow; full-history scan is not proven"]
    out = secret_scan._commit_messages(repo)
    allow = secret_scan._load_allowlist(repo)
    for sha, rel in secret_scan._history_objects(repo):
        try:
            blob = secret_scan.run_git(repo, "cat-file", "blob", sha, text=False).stdout
        except subprocess.CalledProcessError:
            out.append(f"history-blob:{sha[:12]}: Git blob unreadable: {rel}")
            continue
        scope = f"history-blob:{sha[:12]}"
        findings = secret_scan._scan_bytes(blob, rel, scope, allow)
        out.extend(_filter_python_reference_false_positives(findings, blob, rel))
    return sorted(set(out))


def main() -> int:
    findings = scan_history(secret_scan.ROOT)
    if findings:
        print("SECRET_SCAN_FAIL")
        for finding in findings:
            print("-", finding)
        return 1
    print("SECRET_SCAN_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
