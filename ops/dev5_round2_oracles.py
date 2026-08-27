# -*- coding: utf-8 -*-
"""DEV5 Round-2 adversarial contract oracles.

These models define fail-closed, credential-free semantics for cross-lane QA.
They are not production implementations and never constitute product PASS.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import re
import threading
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Callable, Iterable, Mapping, Sequence


class OracleError(RuntimeError):
    pass


_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_IDEMPOTENCY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_OPERATION_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,79}$")
_SAFE_ERROR_CODES = {"400", "401", "403", "404", "409", "413", "429", "500", "502", "503", "504"}
_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_PUBLIC_ALLOWLIST = frozenset({("GET", "/health")})
_SETUP_RE = re.compile(r"(?:^|[\"'\s:/])setup(?:[-_/][A-Za-z0-9_-]{4,})", re.I)
_FORBIDDEN_EXAMPLE_KEYS = {
    "authorization", "bearer", "token", "session", "api_hash", "password",
    "2fa", "message_body", "file_content", "setup_route", "setup_key",
}


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_sha256(value: str, label: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise OracleError(f"{label} must be sha256")
    return value


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    remaining: int
    retry_after_seconds: int
    window_index: int


class StrictFixedWindowOracle:
    """Thread-safe deterministic single-process fixed-window oracle.

    Actor identifiers are hash-addressed. Time is required to be monotonic from
    the perspective of this instance; a backwards clock fails closed rather than
    resurrecting old quota. Stale actor buckets are pruned on window advance.
    """

    def __init__(
        self,
        limit: int,
        *,
        window_seconds: int = 60,
        clock: Callable[[], float],
        max_actors: int = 10_000,
    ) -> None:
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise ValueError("positive integer rate limit required")
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or not (1 <= window_seconds <= 86_400):
            raise ValueError("bounded positive window required")
        if isinstance(max_actors, bool) or not isinstance(max_actors, int) or max_actors <= 0:
            raise ValueError("positive actor capacity required")
        if not callable(clock):
            raise ValueError("clock callable required")
        self.limit = limit
        self.window_seconds = window_seconds
        self.clock = clock
        self.max_actors = max_actors
        self._last_now: float | None = None
        self._buckets: dict[str, tuple[int, int]] = {}
        self._lock = threading.Lock()

    @staticmethod
    def actor_hash(actor_identifier: str) -> str:
        if not isinstance(actor_identifier, str) or not actor_identifier or len(actor_identifier) > 256:
            raise OracleError("invalid actor identifier")
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in actor_identifier):
            raise OracleError("invalid actor identifier")
        if _SHA256_RE.fullmatch(actor_identifier):
            return actor_identifier
        return _sha256_text(actor_identifier)

    def _now(self) -> float:
        now = self.clock()
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not math.isfinite(float(now)) or float(now) < 0:
            raise OracleError("invalid clock value")
        now = float(now)
        if self._last_now is not None and now < self._last_now:
            raise OracleError("clock moved backward")
        self._last_now = now
        return now

    def consume(self, actor_identifier: str) -> RateDecision:
        actor = self.actor_hash(actor_identifier)
        with self._lock:
            now = self._now()
            window = int(now // self.window_seconds)
            stale = [key for key, (bucket_window, _count) in self._buckets.items() if bucket_window < window]
            for key in stale:
                self._buckets.pop(key, None)
            if actor not in self._buckets and len(self._buckets) >= self.max_actors:
                raise OracleError("actor capacity reached")
            bucket_window, count = self._buckets.get(actor, (window, 0))
            if bucket_window != window:
                bucket_window, count = window, 0
            window_end = (window + 1) * self.window_seconds
            retry = max(1, int(math.ceil(window_end - now)))
            if count >= self.limit:
                self._buckets[actor] = (window, count)
                return RateDecision(False, 0, retry, window)
            count += 1
            self._buckets[actor] = (window, count)
            return RateDecision(True, self.limit - count, 0, window)

    @property
    def tracked_actor_count(self) -> int:
        return len(self._buckets)


@dataclass(frozen=True)
class IdempotencyEntry:
    request_sha256: str
    state: str
    result_code: str | None


class CrashSafeIdempotencyOracle:
    """Exactly-once safety oracle with explicit ambiguous external-call state.

    RESERVED means the system crossed the local commit reservation boundary but
    does not yet have a durable terminal result. After restart, that state is
    RECONCILE_REQUIRED and must never automatically repeat the external write.
    Tombstones remain non-reusable after terminal-detail retention.
    """

    SCHEMA_VERSION = 1

    def __init__(self) -> None:
        self._entries: dict[str, IdempotencyEntry] = {}
        self._tombstones: dict[str, str] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _validate_key(key: str) -> str:
        if not isinstance(key, str) or not _IDEMPOTENCY_RE.fullmatch(key):
            raise OracleError("invalid idempotency key")
        return key

    @staticmethod
    def fingerprint(*, operation_kind: str, target_sha256: str, payload_sha256: str, preview_sha256: str) -> str:
        for label, value in (
            ("target", target_sha256), ("payload", payload_sha256), ("preview", preview_sha256)
        ):
            _require_sha256(value, label)
        if operation_kind not in {"SEND", "REPLY", "FORWARD", "SEND_FILE", "SEND_FILES"}:
            raise OracleError("unsupported operation kind")
        raw = json.dumps(
            {
                "operation_kind": operation_kind,
                "target_sha256": target_sha256,
                "payload_sha256": payload_sha256,
                "preview_sha256": preview_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        return hashlib.sha256(raw).hexdigest()

    def reserve(self, key: str, request_sha256: str) -> str:
        key = self._validate_key(key)
        request_sha256 = _require_sha256(request_sha256, "request")
        with self._lock:
            tombstone = self._tombstones.get(key)
            if tombstone is not None:
                return "TOMBSTONE_REUSE" if tombstone == request_sha256 else "IDEMPOTENCY_CONFLICT"
            prior = self._entries.get(key)
            if prior is None:
                self._entries[key] = IdempotencyEntry(request_sha256, "RESERVED", None)
                return "RESERVED"
            if prior.request_sha256 != request_sha256:
                return "IDEMPOTENCY_CONFLICT"
            if prior.state == "RESERVED":
                return "RECONCILE_REQUIRED"
            if prior.state == "COMMITTED":
                return prior.result_code or "COMMITTED"
            raise OracleError("invalid idempotency state")

    def complete(self, key: str, request_sha256: str, *, result_code: str = "COMMITTED") -> str:
        key = self._validate_key(key)
        request_sha256 = _require_sha256(request_sha256, "request")
        if result_code not in {"COMMITTED", "REMOTE_CONFIRMED"}:
            raise OracleError("invalid terminal result")
        with self._lock:
            prior = self._entries.get(key)
            if prior is None or prior.request_sha256 != request_sha256 or prior.state != "RESERVED":
                raise OracleError("reservation mismatch")
            self._entries[key] = IdempotencyEntry(request_sha256, "COMMITTED", result_code)
            return result_code

    def prune_terminal_detail(self, key: str) -> None:
        key = self._validate_key(key)
        with self._lock:
            prior = self._entries.get(key)
            if prior is None or prior.state != "COMMITTED":
                raise OracleError("only terminal records may be pruned")
            self._tombstones[key] = prior.request_sha256
            self._entries.pop(key, None)

    def export_state(self) -> dict[str, Any]:
        with self._lock:
            payload = {
                "schema_version": self.SCHEMA_VERSION,
                "entries": {
                    key: {
                        "request_sha256": item.request_sha256,
                        "state": item.state,
                        "result_code": item.result_code,
                    }
                    for key, item in self._entries.items()
                },
                "tombstones": dict(self._tombstones),
            }
        payload["integrity_sha256"] = self._integrity(payload)
        return copy.deepcopy(payload)

    @staticmethod
    def _integrity(payload_without_integrity: Mapping[str, Any]) -> str:
        raw = json.dumps(payload_without_integrity, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        return hashlib.sha256(raw).hexdigest()

    @classmethod
    def from_state(cls, payload: Mapping[str, Any]) -> "CrashSafeIdempotencyOracle":
        if not isinstance(payload, Mapping):
            raise OracleError("invalid idempotency state")
        copied = copy.deepcopy(dict(payload))
        integrity = copied.pop("integrity_sha256", None)
        if not isinstance(integrity, str) or not _SHA256_RE.fullmatch(integrity):
            raise OracleError("invalid idempotency integrity")
        expected = hashlib.sha256(
            json.dumps(copied, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        ).hexdigest()
        if expected != integrity:
            raise OracleError("idempotency state integrity mismatch")
        if set(copied) != {"schema_version", "entries", "tombstones"} or copied["schema_version"] != cls.SCHEMA_VERSION:
            raise OracleError("unsupported idempotency state")
        entries = copied["entries"]
        tombstones = copied["tombstones"]
        if not isinstance(entries, dict) or not isinstance(tombstones, dict):
            raise OracleError("invalid idempotency state")
        store = cls()
        for key, raw in entries.items():
            store._validate_key(key)
            if not isinstance(raw, dict) or set(raw) != {"request_sha256", "state", "result_code"}:
                raise OracleError("invalid idempotency entry")
            request_sha = _require_sha256(raw["request_sha256"], "request")
            state = raw["state"]
            result = raw["result_code"]
            if state == "RESERVED":
                if result is not None:
                    raise OracleError("reserved idempotency record has terminal result")
            elif state == "COMMITTED":
                if result not in {"COMMITTED", "REMOTE_CONFIRMED"}:
                    raise OracleError("committed idempotency record missing terminal result")
            else:
                raise OracleError("invalid idempotency state")
            store._entries[key] = IdempotencyEntry(request_sha, state, result)
        for key, request_sha in tombstones.items():
            store._validate_key(key)
            request_sha = _require_sha256(request_sha, "request")
            if key in store._entries:
                raise OracleError("idempotency key duplicated across live and tombstone state")
            store._tombstones[key] = request_sha
        return store


_DOWNLOAD_STATUSES = {"pending", "running", "partial", "complete", "failed"}


def validate_download_checkpoint_snapshot(
    payload: Mapping[str, Any], *,
    existing_file_refs: Iterable[str] | None = None,
) -> list[str]:
    """Return semantic checkpoint violations without exposing item content."""
    errors: set[str] = set()
    if not isinstance(payload, Mapping):
        return ["CHECKPOINT_NOT_OBJECT"]
    required = {"schema", "job_id", "status", "items", "results", "failures"}
    if set(payload) != required:
        errors.add("CHECKPOINT_SHAPE")
    if payload.get("schema") != 1:
        errors.add("CHECKPOINT_SCHEMA")
    status = payload.get("status")
    if status not in _DOWNLOAD_STATUSES:
        errors.add("CHECKPOINT_STATUS")
    items = payload.get("items")
    results = payload.get("results")
    failures = payload.get("failures")
    if not isinstance(items, list) or not isinstance(results, dict) or not isinstance(failures, dict):
        return sorted(errors | {"CHECKPOINT_COLLECTION_TYPES"})
    ids: list[str] = []
    for raw in items:
        if not isinstance(raw, Mapping):
            errors.add("CHECKPOINT_ITEM_SHAPE")
            continue
        item_id = raw.get("item_id")
        if not isinstance(item_id, str) or not item_id or len(item_id) > 128:
            errors.add("CHECKPOINT_ITEM_ID")
            continue
        ids.append(item_id)
        expected_size = raw.get("expected_size")
        if expected_size is not None and (isinstance(expected_size, bool) or not isinstance(expected_size, int) or expected_size < 0):
            errors.add("CHECKPOINT_EXPECTED_SIZE")
        expected_hash = raw.get("expected_sha256")
        if expected_hash is not None and (not isinstance(expected_hash, str) or not _SHA256_RE.fullmatch(expected_hash)):
            errors.add("CHECKPOINT_EXPECTED_HASH")
    id_set = set(ids)
    if len(ids) != len(id_set):
        errors.add("CHECKPOINT_DUPLICATE_ITEM")
    result_ids = set(results)
    failure_ids = set(failures)
    if not result_ids.issubset(id_set) or not failure_ids.issubset(id_set):
        errors.add("CHECKPOINT_UNKNOWN_ITEM_REFERENCE")
    if result_ids & failure_ids:
        errors.add("CHECKPOINT_RESULT_FAILURE_OVERLAP")
    existing = set(existing_file_refs) if existing_file_refs is not None else None
    if existing is not None:
        for ref in results.values():
            if not isinstance(ref, str) or ref not in existing:
                errors.add("CHECKPOINT_MISSING_FILE_RECORD")
    completed = len(result_ids)
    unresolved = id_set - result_ids
    if status == "complete" and (unresolved or failures):
        errors.add("CHECKPOINT_COMPLETE_INCONSISTENT")
    if status == "failed" and completed:
        errors.add("CHECKPOINT_FAILED_WITH_RESULTS")
    if status == "partial" and (completed == 0 or not unresolved):
        errors.add("CHECKPOINT_PARTIAL_INCONSISTENT")
    if status == "pending" and (results or failures):
        errors.add("CHECKPOINT_PENDING_HAS_OUTCOMES")
    return sorted(errors)


@dataclass(frozen=True)
class RouteRecord:
    operation_id: str
    path: str
    method: str
    access: str
    kind: str
    preview_operation_id: str | None = None

    def __post_init__(self) -> None:
        if not _OPERATION_ID_RE.fullmatch(self.operation_id):
            raise OracleError("invalid operation id")
        if not isinstance(self.path, str) or not self.path.startswith("/"):
            raise OracleError("invalid route path")
        method = self.method.upper()
        if method not in _HTTP_METHODS:
            raise OracleError("invalid route method")
        if self.access not in {"PUBLIC", "PROTECTED"}:
            raise OracleError("invalid route access")
        if self.kind not in {"READ", "PREVIEW", "COMMIT", "WRITE"}:
            raise OracleError("invalid route kind")
        object.__setattr__(self, "method", method)


def _iter_schema_operations(schema: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
    out: dict[tuple[str, str], Mapping[str, Any]] = {}
    paths = schema.get("paths")
    if not isinstance(paths, Mapping):
        return out
    for path, path_item in paths.items():
        if not isinstance(path, str) or not isinstance(path_item, Mapping):
            continue
        for method, operation in path_item.items():
            method_upper = str(method).upper()
            if method_upper in _HTTP_METHODS and isinstance(operation, Mapping):
                out[(method_upper, path)] = operation
    return out


def _walk_forbidden_openapi_material(value: Any, *, key: str = "") -> bool:
    folded_key = key.casefold().replace("-", "_")
    if folded_key in _FORBIDDEN_EXAMPLE_KEYS:
        return True
    if isinstance(value, Mapping):
        return any(_walk_forbidden_openapi_material(child, key=str(child_key)) for child_key, child in value.items())
    if isinstance(value, list):
        return any(_walk_forbidden_openapi_material(child, key=key) for child in value)
    if isinstance(value, str):
        if _SETUP_RE.search(value):
            return True
        if folded_key in {"example", "examples", "description", "url"}:
            lower = value.casefold()
            if any(marker in lower for marker in ("bearer ", "authorization:", "tg_session", "api_hash", "private message", "file_content")):
                return True
    return False


def validate_openapi_drift(schema: Mapping[str, Any], registry: Sequence[RouteRecord]) -> list[str]:
    errors: set[str] = set()
    if not isinstance(schema, Mapping) or not str(schema.get("openapi", "")).startswith("3."):
        return ["OPENAPI_VERSION"]
    operations = _iter_schema_operations(schema)
    registry_by_key: dict[tuple[str, str], RouteRecord] = {}
    operation_ids: set[str] = set()
    for route in registry:
        key = (route.method, route.path)
        if key in registry_by_key:
            errors.add("REGISTRY_DUPLICATE_ROUTE")
        if route.operation_id in operation_ids:
            errors.add("REGISTRY_DUPLICATE_OPERATION_ID")
        registry_by_key[key] = route
        operation_ids.add(route.operation_id)
    schema_operation_ids: set[str] = set()
    for key, operation in operations.items():
        if key not in registry_by_key:
            errors.add("OPENAPI_UNREGISTERED_OPERATION")
            continue
        route = registry_by_key[key]
        op_id = operation.get("operationId")
        if op_id != route.operation_id:
            errors.add("OPENAPI_OPERATION_ID_MISMATCH")
        if isinstance(op_id, str):
            if op_id in schema_operation_ids:
                errors.add("OPENAPI_DUPLICATE_OPERATION_ID")
            schema_operation_ids.add(op_id)
        if route.access == "PUBLIC":
            if key not in _PUBLIC_ALLOWLIST:
                errors.add("OPENAPI_UNAPPROVED_PUBLIC_ROUTE")
        elif not operation.get("security"):
            errors.add("OPENAPI_PROTECTED_WITHOUT_SECURITY")
        if operation.get("x-protected") is False and route.access == "PROTECTED":
            errors.add("OPENAPI_SELF_MARKER_CONTRADICTION")
        if operation.get("x-write-operation") is False and route.kind in {"WRITE", "COMMIT"}:
            errors.add("OPENAPI_SELF_MARKER_CONTRADICTION")
        responses = operation.get("responses")
        if not isinstance(responses, Mapping):
            errors.add("OPENAPI_RESPONSES_MISSING")
        else:
            for code, response in responses.items():
                if str(code) not in _SAFE_ERROR_CODES:
                    continue
                if not isinstance(response, Mapping):
                    errors.add("OPENAPI_ERROR_RESPONSE_INVALID")
                    continue
                content = response.get("content")
                media = content.get("application/json") if isinstance(content, Mapping) else None
                response_schema = media.get("schema") if isinstance(media, Mapping) else None
                properties = response_schema.get("properties") if isinstance(response_schema, Mapping) else None
                required = response_schema.get("required") if isinstance(response_schema, Mapping) else None
                if not isinstance(properties, Mapping) or not isinstance(required, list) or "error" not in properties or "error" not in required:
                    errors.add("OPENAPI_UNSTRUCTURED_ERROR")
    for key in registry_by_key:
        if key not in operations:
            errors.add("OPENAPI_REGISTERED_ROUTE_MISSING")
    for route in registry:
        if route.kind in {"COMMIT", "WRITE"}:
            if not route.preview_operation_id:
                errors.add("OPENAPI_WRITE_WITHOUT_PREVIEW_POLICY")
                continue
            preview = next((candidate for candidate in registry if candidate.operation_id == route.preview_operation_id), None)
            if preview is None or preview.kind != "PREVIEW" or (preview.method, preview.path) not in operations:
                errors.add("OPENAPI_ORPHAN_WRITE")
    if _walk_forbidden_openapi_material(schema):
        errors.add("OPENAPI_PRIVATE_MATERIAL_EXPOSED")
    return sorted(errors)


class _A11yIdParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: list[str] = []
        self.refs: list[tuple[str, str]] = []
        self.forms = 0
        self.submit_controls = 0
        self.pointer_only = 0
        self.role_controls_without_key = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        data = {str(k).casefold(): v for k, v in attrs}
        if data.get("id"):
            self.ids.append(str(data["id"]))
        for attr in ("aria-labelledby", "aria-describedby", "aria-errormessage"):
            if data.get(attr):
                for ref in str(data[attr]).split():
                    self.refs.append((attr, ref))
        folded_tag = tag.casefold()
        if folded_tag == "form":
            self.forms += 1
        if folded_tag == "button" and str(data.get("type", "submit")).casefold() == "submit":
            self.submit_controls += 1
        if folded_tag == "input" and str(data.get("type", "text")).casefold() in {"submit", "image"}:
            self.submit_controls += 1
        if any(name in data for name in ("onmouseover", "onmouseenter", "ondrag", "ondragstart", "ondrop")) and not any(name in data for name in ("onkeydown", "onkeyup", "onkeypress", "onfocus")):
            self.pointer_only += 1
        role = str(data.get("role", "")).casefold()
        if role in {"button", "link", "checkbox", "radio", "switch", "tab"} and folded_tag not in {"button", "a", "input"}:
            if "tabindex" not in data or not any(name in data for name in ("onkeydown", "onkeyup", "onkeypress")):
                self.role_controls_without_key += 1


def validate_accessibility_edges(html: str) -> list[str]:
    if not isinstance(html, str):
        raise ValueError("HTML text required")
    parser = _A11yIdParser()
    parser.feed(html)
    errors: set[str] = set()
    id_set = set(parser.ids)
    if len(id_set) != len(parser.ids):
        errors.add("A11Y_DUPLICATE_ID")
    for _attr, ref in parser.refs:
        if ref not in id_set:
            errors.add("A11Y_BROKEN_ARIA_REFERENCE")
    for match in re.finditer(r"<([A-Za-z0-9]+)([^>]*?)\bid=[\"']([^\"']+)[\"']([^>]*)>", html, re.I | re.S):
        attrs = match.group(2) + match.group(4)
        element_id = match.group(3)
        labelled = re.search(r"aria-labelledby=[\"']([^\"']+)[\"']", attrs, re.I)
        if labelled and element_id in labelled.group(1).split():
            errors.add("A11Y_SELF_LABEL_REFERENCE")
    if parser.forms and parser.submit_controls == 0:
        errors.add("A11Y_FORM_WITHOUT_SUBMIT_SEMANTICS")
    if parser.pointer_only:
        errors.add("A11Y_POINTER_ONLY_INTERACTION")
    if parser.role_controls_without_key:
        errors.add("A11Y_NON_NATIVE_CONTROL_KEYBOARD")
    return sorted(errors)


def privacy_safe_ci_summary(
    *,
    code_sha: str,
    environment_class: str,
    test_count: int,
    passed_count: int,
    failed_count: int,
    blocked_count: int,
    run_id: int | None = None,
    job_id: int | None = None,
) -> dict[str, Any]:
    if not isinstance(code_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", code_sha):
        raise OracleError("exact Git SHA required")
    if environment_class not in {"github-ci", "synthetic", "reference-snapshot", "hostiq-sanitized"}:
        raise OracleError("unreviewed environment class")
    counts = (test_count, passed_count, failed_count, blocked_count)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in counts):
        raise OracleError("non-negative integer counts required")
    if passed_count + failed_count + blocked_count != test_count:
        raise OracleError("result counts do not sum to test count")
    for value in (run_id, job_id):
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value <= 0):
            raise OracleError("positive numeric CI identifiers required")
    result: dict[str, Any] = {
        "schema_version": 1,
        "code_sha": code_sha,
        "environment_class": environment_class,
        "test_count": test_count,
        "passed_count": passed_count,
        "failed_count": failed_count,
        "blocked_count": blocked_count,
    }
    if run_id is not None:
        result["github_run_id"] = run_id
    if job_id is not None:
        result["github_job_id"] = job_id
    return result
