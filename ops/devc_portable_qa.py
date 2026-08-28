# -*- coding: utf-8 -*-
"""Portable DEV_C end-to-end QA gates for Telegram Bridge.

This module contains credential-free verification helpers.  It deliberately
separates synthetic/source checks from live product evidence and performs no
Telegram, HOSTiQ, or network side effects.
"""
from __future__ import annotations

import hashlib
import importlib
import math
import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import PurePosixPath
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import unquote

from ops.acceptance_harness import CRITERIA


class PortableQAError(RuntimeError):
    pass


EVIDENCE_CLASSES = frozenset(
    {"SYNTHETIC_EXECUTABLE", "REAL_SOURCE_REQUIRED", "LIVE_EXTERNAL_REQUIRED"}
)
EXPECTED_PREDECESSOR_SHAS = {
    "DEV1": "26a2df12c350f670a703b236edc3648f339b64a9",
    "DEV2": "19910ec89c85aec6d9ddd31abca0f4cab4dac6cb",
    "DEV3": "4f2c162320c2cbd8e1b0fc2b91a62d2a50806653",
    "DEV4": "fc409c7e0bd782148df5cb1a00f9f624b7008548",
    "DEV5": "82643ade0f1b5157d311e06a700223a1501ae062",
}
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_CONFUSABLE_SEPARATORS = {"\u2044", "\u2215", "\uff0f", "\uff3c"}


# These are coverage/evidence classes, never product PASS labels.  The choices
# are deliberately conservative: human, Passenger, deployed Action and final
# user scenarios stay external even when prerequisite synthetic tests exist.
_SYNTHETIC_IDS = frozenset(
    {
        "B4", "B5", "B7", "B8",
        "C3", "C4", "C6",
        "D1", "D2", "D3", "D4", "D5", "D6",
        "E1", "E2", "E3", "E4", "E5",
        "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8",
        "G1", "G2", "G3", "G4", "G5",
        "H3", "H4", "H5",
        "J2", "J3", "J5",
    }
)
_LIVE_IDS = frozenset(
    {
        "A5", "C1", "C2", "C5", "H1", "H2",
        "I1", "I4", "I6",
        "J1", "J4", "J6",
        "K1", "K2", "K3", "K4", "K5",
    }
)
_HUMAN_ACCESSIBILITY_IDS = frozenset({"I1", "I4", "I6"})


@dataclass(frozen=True)
class AcceptancePlanEntry:
    criterion: str
    evidence_class: str
    human_verification_required: bool = False
    explicit_write_approval_required: bool = False


def acceptance_plan() -> dict[str, AcceptancePlanEntry]:
    """Return an exact one-to-one plan for all Drive A1-K5 criteria."""
    result: dict[str, AcceptancePlanEntry] = {}
    for criterion in CRITERIA:
        if criterion in _LIVE_IDS:
            evidence_class = "LIVE_EXTERNAL_REQUIRED"
        elif criterion in _SYNTHETIC_IDS:
            evidence_class = "SYNTHETIC_EXECUTABLE"
        else:
            evidence_class = "REAL_SOURCE_REQUIRED"
        result[criterion] = AcceptancePlanEntry(
            criterion=criterion,
            evidence_class=evidence_class,
            human_verification_required=criterion in _HUMAN_ACCESSIBILITY_IDS,
            explicit_write_approval_required=criterion == "K5",
        )
    validate_acceptance_plan(result)
    return result


def validate_acceptance_plan(plan: Mapping[str, AcceptancePlanEntry]) -> None:
    if set(plan) != set(CRITERIA) or len(plan) != 67:
        raise PortableQAError("acceptance plan must map all 67 criteria exactly once")
    for criterion, item in plan.items():
        if not isinstance(item, AcceptancePlanEntry) or item.criterion != criterion:
            raise PortableQAError("acceptance plan entry identity mismatch")
        if item.evidence_class not in EVIDENCE_CLASSES:
            raise PortableQAError("invalid acceptance evidence class")
        if item.human_verification_required != (criterion in _HUMAN_ACCESSIBILITY_IDS):
            raise PortableQAError("human accessibility truth boundary mismatch")
        if item.explicit_write_approval_required != (criterion == "K5"):
            raise PortableQAError("K5 explicit approval truth boundary mismatch")
    for criterion in ("K1", "K2", "K3", "K4", "K5"):
        if plan[criterion].evidence_class != "LIVE_EXTERNAL_REQUIRED":
            raise PortableQAError("final user scenarios must remain live external")


def coverage_counts(plan: Mapping[str, AcceptancePlanEntry] | None = None) -> dict[str, int]:
    selected = plan or acceptance_plan()
    counts = {name: 0 for name in sorted(EVIDENCE_CLASSES)}
    for item in selected.values():
        counts[item.evidence_class] += 1
    return counts


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def strict_relative_path(value: str) -> str:
    """Canonicalise a private relative member path or fail closed.

    Percent decoding is repeated to expose double-encoded traversal.  NFKC is
    used only as a security probe so normal Unicode/Cyrillic names remain NFC.
    """
    if not isinstance(value, str) or not (1 <= len(value) <= 512):
        raise PortableQAError("invalid relative path")
    candidate = value
    for _ in range(3):
        if any(ord(ch) < 32 or ord(ch) == 127 for ch in candidate):
            raise PortableQAError("control character in relative path")
        if "\\" in candidate or any(ch in candidate for ch in _CONFUSABLE_SEPARATORS):
            raise PortableQAError("unsafe path separator")
        decoded = unquote(candidate)
        if decoded == candidate:
            break
        candidate = decoded
    if "%" in candidate:
        # Residual percent material is ambiguous for downstream decoders.
        raise PortableQAError("ambiguous percent encoding")
    if "\\" in candidate or any(ch in candidate for ch in _CONFUSABLE_SEPARATORS):
        raise PortableQAError("unsafe path separator")
    if candidate.startswith("//") or _WINDOWS_DRIVE_RE.match(candidate):
        raise PortableQAError("absolute or drive path rejected")
    security_view = unicodedata.normalize("NFKC", candidate)
    if "\\" in security_view or security_view.startswith("/") or security_view.startswith("//"):
        raise PortableQAError("compatibility-normalised absolute path rejected")
    if _WINDOWS_DRIVE_RE.match(security_view):
        raise PortableQAError("compatibility-normalised drive path rejected")
    security_parts = security_view.split("/")
    if any(part in {"", ".", ".."} for part in security_parts):
        raise PortableQAError("dot or empty path segment rejected")
    canonical = unicodedata.normalize("NFC", candidate)
    path = PurePosixPath(canonical)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in canonical.split("/")):
        raise PortableQAError("unsafe relative path")
    return path.as_posix()


def classify_bearer_shape(header_value: object) -> str:
    """Classify header syntax only; no real bearer value is ever required."""
    if header_value is None:
        return "MISSING"
    if not isinstance(header_value, str) or not header_value:
        return "MALFORMED"
    if header_value != header_value.strip() or len(header_value) > 600:
        return "MALFORMED"
    parts = header_value.split(" ")
    if len(parts) != 2 or parts[0] != "Bearer":
        return "MALFORMED"
    opaque = parts[1]
    if not (1 <= len(opaque) <= 512) or any(ch.isspace() or ord(ch) < 33 or ord(ch) == 127 for ch in opaque):
        return "MALFORMED"
    return "SHAPE_VALID"


@dataclass(frozen=True)
class QARoute:
    method: str
    path: str
    operation_id: str
    access: str
    operation_class: str
    action_exported: bool
    action: str | None = None
    pair_operation_id: str | None = None
    explicit_user_command_required: bool = False
    consequential: bool = False

    @property
    def key(self) -> tuple[str, str]:
        return self.method.upper(), self.path


_REFERENCE_READ_ROUTES: tuple[QARoute, ...] = (
    QARoute("GET", "/health", "health.get", "public", "health", False),
    QARoute("POST", "/api/v1/dialogs/list", "dialogs.list", "protected", "read", True),
    QARoute("POST", "/api/v1/history/read", "history.read", "protected", "read", True),
    QARoute("POST", "/api/v1/search", "search.read", "protected", "read", True),
    QARoute("POST", "/api/v1/media/metadata", "media.metadata", "protected", "read", True),
    QARoute("POST", "/api/v1/downloads/single", "downloads.single", "protected", "read", True),
    QARoute("POST", "/api/v1/downloads/bulk", "downloads.bulk", "protected", "read", True),
    QARoute("POST", "/api/v1/downloads/resume", "downloads.resume", "protected", "read", True),
    QARoute("POST", "/api/v1/archives/create", "archives.create", "protected", "read", True),
    QARoute("POST", "/api/v1/files/get", "files.metadata", "protected", "read", True),
    QARoute("GET", "/api/v1/files/{file_ref}", "files.content", "protected_or_signed", "read", False),
)


def _write_reference(action: str, path_stem: str, preview_id: str, commit_id: str) -> tuple[QARoute, QARoute]:
    preview = QARoute(
        "POST", f"/api/v1/{path_stem}/preview", preview_id, "protected", "write_preview", True,
        action=action, pair_operation_id=commit_id, consequential=False,
    )
    commit = QARoute(
        "POST", f"/api/v1/{path_stem}/commit", commit_id, "protected", "write_commit", True,
        action=action, pair_operation_id=preview_id, explicit_user_command_required=True, consequential=True,
    )
    return preview, commit


_REFERENCE_ACTION_ROUTES: tuple[QARoute, ...] = (
    # Read operation IDs intentionally reflect DEV4's ChatGPT Action namespace.
    QARoute("POST", "/api/v1/dialogs/list", "listTelegramDialogs", "protected", "read", True),
    QARoute("POST", "/api/v1/history/read", "readTelegramHistory", "protected", "read", True),
    QARoute("POST", "/api/v1/search", "searchTelegramMessages", "protected", "read", True),
    QARoute("POST", "/api/v1/media/metadata", "getTelegramMediaMetadata", "protected", "read", True),
    QARoute("POST", "/api/v1/downloads/single", "downloadTelegramMediaSingle", "protected", "read", True),
    QARoute("POST", "/api/v1/downloads/bulk", "downloadTelegramMediaBulk", "protected", "read", True),
    QARoute("POST", "/api/v1/downloads/resume", "resumeTelegramDownload", "protected", "read", True),
    QARoute("POST", "/api/v1/archives/create", "createTelegramArchive", "protected", "read", True),
    QARoute("POST", "/api/v1/files/get", "getStoredTelegramFile", "protected", "read", True),
    *_write_reference("SEND", "messages/send", "previewTelegramSend", "commitTelegramSend"),
    *_write_reference("REPLY", "messages/reply", "previewTelegramReply", "commitTelegramReply"),
    *_write_reference("FORWARD", "messages/forward", "previewTelegramForward", "commitTelegramForward"),
    *_write_reference("SEND_FILES", "files/send", "previewTelegramFiles", "commitTelegramFiles"),
)


def predecessor_reference_interfaces() -> tuple[tuple[QARoute, ...], tuple[QARoute, ...]]:
    return _REFERENCE_READ_ROUTES, _REFERENCE_ACTION_ROUTES


def validate_route_action_contract(
    read_routes: Sequence[QARoute], action_routes: Sequence[QARoute]
) -> list[str]:
    """Return privacy-safe defect codes for router/OpenAPI contract drift."""
    defects: set[str] = set()
    read_keys: set[tuple[str, str]] = set()
    public_keys: set[tuple[str, str]] = set()
    expected_action_read: set[tuple[str, str]] = set()
    for route in read_routes:
        if route.key in read_keys:
            defects.add("READ_ROUTE_DUPLICATE")
        read_keys.add(route.key)
        if route.access == "public":
            public_keys.add(route.key)
        elif route.access not in {"protected", "protected_or_signed"}:
            defects.add("READ_ACCESS_UNKNOWN")
        if route.operation_class == "read" and route.action_exported:
            expected_action_read.add(route.key)
    if public_keys != {("GET", "/health")}:
        defects.add("PUBLIC_ALLOWLIST_DRIFT")

    action_keys: set[tuple[str, str]] = set()
    action_ids: set[str] = set()
    actual_action_read: set[tuple[str, str]] = set()
    by_id: dict[str, QARoute] = {}
    for route in action_routes:
        if route.key in action_keys:
            defects.add("ACTION_ROUTE_DUPLICATE")
        action_keys.add(route.key)
        if not route.operation_id or route.operation_id in action_ids:
            defects.add("ACTION_OPERATION_ID_DUPLICATE")
        action_ids.add(route.operation_id)
        by_id[route.operation_id] = route
        if route.access != "protected":
            defects.add("ACTION_OPERATION_NOT_PROTECTED")
        if route.operation_class == "read":
            actual_action_read.add(route.key)
        if route.operation_class == "write_preview" and route.consequential:
            defects.add("PREVIEW_MARKED_CONSEQUENTIAL")
        if route.operation_class == "write_commit":
            if not route.consequential:
                defects.add("COMMIT_NOT_CONSEQUENTIAL")
            if not route.explicit_user_command_required:
                defects.add("COMMIT_MISSING_EXPLICIT_COMMAND")
    if expected_action_read != actual_action_read:
        defects.add("READ_ACTION_ROUTE_DRIFT")

    for route in action_routes:
        if route.operation_class not in {"write_preview", "write_commit"}:
            continue
        pair = by_id.get(route.pair_operation_id or "")
        if pair is None or pair.action != route.action:
            defects.add("WRITE_PAIR_MISSING_OR_MISMATCHED")
            continue
        if pair.operation_class == route.operation_class:
            defects.add("WRITE_PAIR_SAME_CLASS")
    return sorted(defects)


def _candidate_components_present() -> tuple[bool, bool]:
    read_present = False
    action_present = False
    try:
        read_module = importlib.import_module("bridge.routes")
        read_present = hasattr(read_module, "READ_ROUTE_REGISTRY")
    except (ImportError, ModuleNotFoundError):
        pass
    try:
        action_module = importlib.import_module("ops.openapi_registry")
        action_present = hasattr(action_module, "OPERATIONS")
    except (ImportError, ModuleNotFoundError):
        pass
    return read_present, action_present


def discover_candidate_routes() -> tuple[tuple[QARoute, ...], tuple[QARoute, ...]] | None:
    """Discover an integrated candidate without importing sibling branches.

    None means the current validation head is still the QA-only DEV1 base.  One
    component without the other is a fail-closed partial-integration defect.
    """
    read_present, action_present = _candidate_components_present()
    if not read_present and not action_present:
        return None
    if read_present != action_present:
        raise PortableQAError("partial integrated router/OpenAPI candidate")

    read_module = importlib.import_module("bridge.routes")
    action_module = importlib.import_module("ops.openapi_registry")
    read_rows: list[QARoute] = []
    for raw in read_module.registry_snapshot("/api/v1"):
        read_rows.append(
            QARoute(
                str(raw["method"]).upper(), str(raw["path"]), str(raw["operation_id"]),
                str(raw["access"]), str(raw["operation_class"]),
                not (str(raw["path"]) == "/health" or str(raw["path"]).endswith("/{file_ref}")),
            )
        )

    generated = action_module.build_action_openapi("https://bridge.example.invalid")
    action_rows: list[QARoute] = []
    for spec in action_module.OPERATIONS:
        operation_class = getattr(spec.operation_class, "value", str(spec.operation_class))
        op_doc = generated["paths"][spec.path][spec.method.lower()]
        action_rows.append(
            QARoute(
                str(spec.method).upper(), str(spec.path), str(spec.operation_id),
                "protected" if bool(spec.protected) else "public",
                {"READ": "read", "WRITE_PREVIEW": "write_preview", "WRITE_COMMIT": "write_commit"}.get(
                    str(operation_class), str(operation_class).casefold()
                ),
                True, action=getattr(spec, "action", None), pair_operation_id=getattr(spec, "pair_operation_id", None),
                explicit_user_command_required=bool(getattr(spec, "explicit_user_commit_required", False)),
                consequential=bool(op_doc.get("x-openai-isConsequential", False)),
            )
        )
    return tuple(read_rows), tuple(action_rows)


def validate_discovered_candidate() -> list[str]:
    discovered = discover_candidate_routes()
    if discovered is None:
        return ["INTEGRATED_CANDIDATE_NOT_PRESENT"]
    return validate_route_action_contract(*discovered)


def probe_integration_interface_compatibility() -> list[str]:
    """Probe DEV1 stable interfaces against integrated DEV3/DEV4 semantics.

    It runs only when the read and Action components are both present.  This
    converts known predecessor vocabulary differences into executable QA rather
    than silently assuming adapters will fit.
    """
    discovered = discover_candidate_routes()
    if discovered is None:
        return ["INTEGRATED_CANDIDATE_NOT_PRESENT"]
    defects: set[str] = set()
    interfaces = importlib.import_module("ops.integration_interfaces")
    zero = "0" * 64
    try:
        interfaces.WritePreview(zero, "SEND_FILES", zero, zero, 1)
    except (TypeError, ValueError):
        defects.add("DEV1_WRITE_KIND_SEND_FILES_INCOMPATIBLE")
    try:
        interfaces.RoutePolicy("POST", "/api/v1/dialogs/list", "dialogs.list", "PROTECTED_READ")
    except (TypeError, ValueError):
        defects.add("DEV3_OPERATION_ID_GRAMMAR_INCOMPATIBLE")
    try:
        interfaces.RoutePolicy("POST", "/api/v1/dialogs/list", "listTelegramDialogs", "PROTECTED_READ")
    except (TypeError, ValueError):
        defects.add("DEV4_OPERATION_ID_GRAMMAR_INCOMPATIBLE")
    safe_classes = set(getattr(interfaces, "SAFE_ROUTE_CLASSES", set()))
    if "PROTECTED_OR_SIGNED" not in safe_classes:
        defects.add("DEV3_SIGNED_FILE_ACCESS_CLASS_NOT_REPRESENTABLE")
    return sorted(defects)


class _AccessibilityParser(HTMLParser):
    INTERACTIVE_ROLES = {"button", "link", "checkbox", "switch", "menuitem"}
    POINTER_EVENTS = {"onclick", "ondblclick", "onmousedown", "onmouseup", "onmouseover", "onmouseenter", "onpointerdown", "ondragstart"}
    KEY_EVENTS = {"onkeydown", "onkeyup", "onkeypress"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: list[str] = []
        self.label_targets: set[str] = set()
        self.controls: list[dict[str, Any]] = []
        self.aria_refs: list[tuple[str | None, str, str]] = []
        self.heading_levels: list[int] = []
        self.button_stack: list[int] = []
        self.label_depth = 0
        self.form_stack: list[bool] = []
        self.form_submit_states: list[bool] = []
        self.rule_errors: set[str] = set()

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {str(k).casefold(): "" if v is None else str(v) for k, v in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        data = self._attrs(attrs)
        element_id = data.get("id")
        if element_id:
            self.ids.append(element_id)
        if tag == "label":
            self.label_depth += 1
            if data.get("for"):
                self.label_targets.add(data["for"])
        if tag == "form":
            self.form_stack.append(False)
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.heading_levels.append(int(tag[1]))

        for attribute in ("aria-labelledby", "aria-describedby"):
            for target in data.get(attribute, "").split():
                self.aria_refs.append((element_id, attribute, target))

        interactive = tag in {"input", "button", "select", "textarea", "a"} or data.get("role") in self.INTERACTIVE_ROLES
        if interactive:
            record = {"tag": tag, "attrs": data, "nested_label": self.label_depth > 0, "text": ""}
            self.controls.append(record)
            index = len(self.controls) - 1
            if tag == "button":
                self.button_stack.append(index)
            tabindex = data.get("tabindex")
            if tabindex is not None:
                try:
                    tab_value = int(tabindex)
                except ValueError:
                    self.rule_errors.add("INVALID_TABINDEX")
                else:
                    if tab_value > 0:
                        self.rule_errors.add("POSITIVE_TABINDEX")
                    if ("hidden" in data or data.get("aria-hidden", "").casefold() == "true") and tab_value >= 0:
                        self.rule_errors.add("HIDDEN_FOCUSABLE_CONTROL")
            pointer = any(name in data for name in self.POINTER_EVENTS)
            keyboard = any(name in data for name in self.KEY_EVENTS)
            native_keyboard = tag in {"input", "button", "select", "textarea", "a"}
            if pointer and not (keyboard or native_keyboard):
                self.rule_errors.add("POINTER_ONLY_CONTROL")
            if data.get("role") in self.INTERACTIVE_ROLES and tag not in {"button", "a", "input"}:
                if not keyboard or tabindex is None:
                    self.rule_errors.add("NON_NATIVE_CONTROL_MISSING_KEYBOARD_SEMANTICS")

        if self.form_stack:
            input_type = data.get("type", "").casefold()
            if tag == "button" and input_type in {"", "submit"}:
                self.form_stack[-1] = True
            if tag == "input" and input_type == "submit":
                self.form_stack[-1] = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.casefold()
        if tag == "label" and self.label_depth:
            self.label_depth -= 1
        if tag == "button" and self.button_stack:
            self.button_stack.pop()
        if tag == "form" and self.form_stack:
            self.form_submit_states.append(self.form_stack.pop())

    def handle_data(self, data: str) -> None:
        if self.button_stack and data.strip():
            index = self.button_stack[-1]
            self.controls[index]["text"] += data.strip()


def analyze_accessibility_source(html: str) -> list[str]:
    if not isinstance(html, str) or len(html.encode("utf-8")) > 1_000_000:
        raise PortableQAError("bounded HTML source required")
    parser = _AccessibilityParser()
    parser.feed(html)
    parser.close()
    errors = set(parser.rule_errors)
    id_set = set(parser.ids)
    if len(id_set) != len(parser.ids):
        errors.add("DUPLICATE_ID")
    for owner, attribute, target in parser.aria_refs:
        if target not in id_set:
            errors.add("BROKEN_ARIA_REFERENCE")
        if owner is not None and owner == target:
            errors.add("SELF_ARIA_REFERENCE")
    for record in parser.controls:
        tag = record["tag"]
        data = record["attrs"]
        control_id = data.get("id")
        aria_name = data.get("aria-label", "").strip() or data.get("aria-labelledby", "").strip()
        if tag in {"input", "select", "textarea"} and data.get("type", "").casefold() not in {"hidden", "submit", "button"}:
            if not (record["nested_label"] or aria_name or (control_id and control_id in parser.label_targets)):
                errors.add("UNLABELED_INPUT")
        if tag == "button" and not (aria_name or record["text"].strip()):
            errors.add("UNNAMED_BUTTON")
        if tag == "input" and data.get("type", "").casefold() in {"submit", "button"}:
            if not (aria_name or data.get("value", "").strip()):
                errors.add("UNNAMED_BUTTON")
        if data.get("aria-invalid", "").casefold() == "true" and not data.get("aria-describedby", "").strip():
            errors.add("INVALID_INPUT_WITHOUT_TEXT_ASSOCIATION")
    for previous, current in zip(parser.heading_levels, parser.heading_levels[1:]):
        if current > previous + 1:
            errors.add("HEADING_LEVEL_JUMP")
    if any(not state for state in parser.form_submit_states):
        errors.add("FORM_WITHOUT_SUBMIT_SEMANTICS")
    return sorted(errors)


_ALLOWED_SUMMARY_KEYS = frozenset(
    {
        "criterion", "evidence_class", "state", "reason_code", "reason_codes",
        "count", "file_count", "result_count", "duration_ms", "http_status",
        "code_sha", "sha256", "identifier_sha256", "operation_sha256",
        "tree_scan_passed", "history_scan_passed", "schema_valid", "success",
    }
)


def validate_public_summary(value: object, *, depth: int = 0) -> None:
    """Fail closed on free-form public QA summaries.

    This is intentionally narrower than application logging.  Public evidence
    should use counts, bounded statuses and hashes rather than private labels.
    """
    if depth > 3:
        raise PortableQAError("public summary nesting too deep")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if not (-1_000_000_000 <= value <= 1_000_000_000):
            raise PortableQAError("public summary integer out of bounds")
        return
    if isinstance(value, str):
        if _SHA40_RE.fullmatch(value) or _SHA256_RE.fullmatch(value):
            return
        if not re.fullmatch(r"[A-Z0-9_.:-]{1,80}", value):
            raise PortableQAError("free-form public summary text rejected")
        return
    if isinstance(value, list):
        if len(value) > 32:
            raise PortableQAError("public summary list too large")
        for item in value:
            validate_public_summary(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 32:
            raise PortableQAError("public summary object too large")
        for key, item in value.items():
            if key not in _ALLOWED_SUMMARY_KEYS:
                raise PortableQAError("unreviewed public summary field")
            validate_public_summary(item, depth=depth + 1)
        return
    raise PortableQAError("unsupported public summary value")


@dataclass(frozen=True)
class LiveProtocol:
    scenario_id: str
    execute_now: bool
    required_gates: tuple[str, ...]
    public_evidence_fields: tuple[str, ...]


def live_protocols() -> dict[str, LiveProtocol]:
    common = ("AUDITED_DEPLOYED_SHA", "PASSENGER_RUNTIME_VERIFIED", "PRIVATE_API_AUTH_READY")
    protocols = {
        "H2": LiveProtocol("H2", False, common + ("CHATGPT_ACTION_CONNECTED_READ_ONLY",), ("result_count", "operation_sha256")),
        "K1": LiveProtocol("K1", False, common + ("TELEGRAM_AUTHORIZED",), ("result_count", "identifier_sha256")),
        "K2": LiveProtocol("K2", False, common + ("TELEGRAM_AUTHORIZED",), ("result_count", "identifier_sha256")),
        "K3": LiveProtocol("K3", False, common + ("TELEGRAM_AUTHORIZED",), ("file_count", "sha256")),
        "K4": LiveProtocol("K4", False, common + ("TELEGRAM_AUTHORIZED",), ("operation_sha256", "state")),
        "K5": LiveProtocol(
            "K5", False,
            common + ("TELEGRAM_AUTHORIZED", "INDEPENDENT_AUDITOR_WRITE_APPROVAL", "EXPLICIT_USER_COMMIT", "SAFE_DESTINATION_CONFIRMED"),
            ("operation_sha256", "result_count"),
        ),
    }
    validate_live_protocols(protocols)
    return protocols


def validate_live_protocols(protocols: Mapping[str, LiveProtocol]) -> None:
    if set(protocols) != {"H2", "K1", "K2", "K3", "K4", "K5"}:
        raise PortableQAError("live protocol registry incomplete")
    for key, protocol in protocols.items():
        if protocol.scenario_id != key or protocol.execute_now:
            raise PortableQAError("live protocol must be prepared but not auto-executed")
        if any("DESTINATION:" in gate or "@" in gate for gate in protocol.required_gates):
            raise PortableQAError("live protocol must not embed a real destination")
    k5 = protocols["K5"]
    gates = set(k5.required_gates)
    if "INDEPENDENT_AUDITOR_WRITE_APPROVAL" not in gates or "EXPLICIT_USER_COMMIT" not in gates:
        raise PortableQAError("K5 approval gates missing")


def predecessor_sha_matrix_valid() -> bool:
    return len(EXPECTED_PREDECESSOR_SHAS) == 5 and all(_SHA40_RE.fullmatch(value) for value in EXPECTED_PREDECESSOR_SHAS.values())


def privacy_safe_sequence_summary(step_counts: Mapping[str, int], code_sha: str) -> dict[str, object]:
    """Build a body/name-free summary for a mocked full user sequence."""
    if not _SHA40_RE.fullmatch(code_sha):
        raise PortableQAError("exact code SHA required")
    if not step_counts or any(
        not isinstance(name, str) or not re.fullmatch(r"[A-Z0-9_.:-]{1,40}", name)
        or isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > 1_000_000
        for name, count in step_counts.items()
    ):
        raise PortableQAError("bounded stable step counts required")
    digest_source = "|".join(f"{name}:{step_counts[name]}" for name in sorted(step_counts))
    result = {
        "criterion": "K4",
        "evidence_class": "SYNTHETIC_EXECUTABLE",
        "state": "MOCK_SEQUENCE_COMPLETE",
        "count": sum(step_counts.values()),
        "code_sha": code_sha,
        "operation_sha256": _sha256_text(digest_source),
    }
    validate_public_summary(result)
    return result
