# -*- coding: utf-8 -*-
"""DEV10 accessibility/setup/live-E2E protocol gates.

This module is deliberately credential-free and side-effect-free.  It may prove
structural readiness and protocol consistency, but it cannot produce a human
NVDA PASS, authorize Telegram login, authorize production deployment, or send a
Telegram message.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Iterable, Mapping

from ops.acceptance_contracts import coverage_report as legacy_coverage_report
from ops.acceptance_harness import (
    AUTH_NOT_YET_REQUIRED,
    AUTH_REQUIRED,
    evaluate_telegram_auth_gate,
)
from ops.candidate_contracts import candidate_acceptance_coverage

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

ACCESSIBILITY_CRITERIA = ("C1", "I1", "I2", "I3", "I4", "I5", "I6", "I7")
HUMAN_NVDA_CRITERIA = frozenset({"C1", "I1", "I4", "I6"})
STRUCTURAL_SOURCE_CRITERIA = frozenset({"I2", "I3", "I5", "I7"})
HUMAN_STATUS = frozenset({"NOT_EXECUTED", "PASS", "FAIL", "BLOCKED"})


class ProtocolError(ValueError):
    """Fail-closed validation error for DEV10 public protocol data."""


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ProtocolError(f"{label} must be boolean")
    return value


def _sha40(value: Any, label: str = "candidate_sha") -> str:
    if not isinstance(value, str) or not SHA40_RE.fullmatch(value):
        raise ProtocolError(f"{label} must be exact SHA-40")
    return value


def _sha256(value: Any, label: str = "sha256") -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise ProtocolError(f"{label} must be exact SHA-256")
    return value


class _SetupMarkupParser(HTMLParser):
    """Static prerequisite parser; never a browser or assistive-tech oracle."""

    NATIVE_INTERACTIVE = {"button", "a", "input", "select", "textarea", "summary"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.labels_for: set[str] = set()
        self.controls: list[dict[str, str]] = []
        self.buttons: list[dict[str, str]] = []
        self.button_text: list[str] = []
        self._button_depth = 0
        self.headings: list[int] = []
        self.main_count = 0
        self.live_region_count = 0
        self.positive_tabindex = False
        self.pointer_only = False
        self.aria_labelledby_refs: list[str] = []
        self.aria_describedby_refs: list[str] = []

    @staticmethod
    def _attrs(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
        return {str(k).casefold(): "" if v is None else str(v) for k, v in attrs}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.casefold()
        data = self._attrs(attrs)
        element_id = data.get("id")
        if element_id:
            self.ids.add(element_id)
        if tag == "label" and data.get("for"):
            self.labels_for.add(data["for"])
        if tag in {"input", "select", "textarea"}:
            if not (tag == "input" and data.get("type", "").casefold() == "hidden"):
                self.controls.append(data)
        if tag == "button":
            self.buttons.append(data)
            self.button_text.append("")
            self._button_depth += 1
        if tag in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self.headings.append(int(tag[1]))
        if tag == "main" or data.get("role", "").casefold() == "main":
            self.main_count += 1
        role = data.get("role", "").casefold()
        aria_live = data.get("aria-live", "").casefold()
        if role in {"status", "alert"} or aria_live in {"polite", "assertive"}:
            self.live_region_count += 1
        tabindex = data.get("tabindex")
        if tabindex:
            try:
                if int(tabindex) > 0:
                    self.positive_tabindex = True
            except ValueError:
                self.positive_tabindex = True
        if "onclick" in data and tag not in self.NATIVE_INTERACTIVE:
            if not any(key in data for key in ("onkeydown", "onkeyup", "onkeypress")):
                self.pointer_only = True
        if data.get("aria-labelledby"):
            self.aria_labelledby_refs.extend(data["aria-labelledby"].split())
        if data.get("aria-describedby"):
            self.aria_describedby_refs.extend(data["aria-describedby"].split())

    def handle_data(self, data: str) -> None:
        if self._button_depth and self.button_text:
            self.button_text[-1] += data

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "button" and self._button_depth:
            self._button_depth -= 1


def analyze_setup_markup(html: str) -> dict[str, bool | int]:
    """Return structural prerequisites only.

    `human_nvda_pass` is intentionally hard-coded False.  Static parsing cannot
    prove actual focus order, keyboard operability in a browser, or NVDA live
    announcement behavior.
    """
    if not isinstance(html, str) or not html or len(html.encode("utf-8")) > 1_000_000:
        raise ProtocolError("setup markup must be non-empty bounded UTF-8 text")
    parser = _SetupMarkupParser()
    parser.feed(html)
    explicit_labels = all(
        bool(control.get("id") and control["id"] in parser.labels_for)
        or bool(control.get("aria-labelledby"))
        for control in parser.controls
    )
    button_names = all(
        bool(attrs.get("aria-label"))
        or bool(attrs.get("aria-labelledby"))
        or bool(text.strip())
        for attrs, text in zip(parser.buttons, parser.button_text)
    )
    heading_structure = bool(parser.headings) and parser.headings[0] == 1
    if heading_structure:
        heading_structure = all(cur - prev <= 1 for prev, cur in zip(parser.headings, parser.headings[1:]))
    refs_resolve = all(ref in parser.ids for ref in parser.aria_labelledby_refs + parser.aria_describedby_refs)
    structural_ready = all((
        explicit_labels,
        button_names,
        heading_structure,
        parser.main_count == 1,
        parser.live_region_count >= 1,
        not parser.positive_tabindex,
        not parser.pointer_only,
        refs_resolve,
    ))
    return {
        "structural_ready": structural_ready,
        "labels_present": explicit_labels,
        "accessible_names_present": button_names,
        "heading_structure_valid": heading_structure,
        "main_landmark_valid": parser.main_count == 1,
        "status_region_present": parser.live_region_count >= 1,
        "positive_tabindex_absent": not parser.positive_tabindex,
        "mouse_only_absent": not parser.pointer_only,
        "aria_references_resolve": refs_resolve,
        "control_count": len(parser.controls),
        "button_count": len(parser.buttons),
        "human_nvda_pass": False,
    }


def authoritative_accessibility_projection() -> dict[str, str]:
    rows = candidate_acceptance_coverage()
    projection = {
        str(row["criterion"]): str(row["evidence_class"])
        for row in rows
        if row["criterion"] in ACCESSIBILITY_CRITERIA
    }
    if set(projection) != set(ACCESSIBILITY_CRITERIA):
        raise ProtocolError("authoritative accessibility projection incomplete")
    for criterion in HUMAN_NVDA_CRITERIA:
        if projection[criterion] != "LIVE_EXTERNAL_REQUIRED":
            raise ProtocolError("human accessibility criterion was source-promoted")
    for criterion in STRUCTURAL_SOURCE_CRITERIA:
        if projection[criterion] != "REAL_SOURCE_REQUIRED":
            raise ProtocolError("structural accessibility criterion classification drift")
    return projection


def detect_legacy_accessibility_truth_drift() -> tuple[str, ...]:
    """Identify criteria where the older synthetic coverage disagrees with the candidate truth boundary."""
    authoritative = authoritative_accessibility_projection()
    legacy = {
        str(row.get("criterion")): str(row.get("coverage"))
        for row in legacy_coverage_report()
        if isinstance(row, dict) and row.get("criterion") in ACCESSIBILITY_CRITERIA
    }
    if set(legacy) != set(ACCESSIBILITY_CRITERIA):
        raise ProtocolError("legacy accessibility projection incomplete")
    return tuple(c for c in ACCESSIBILITY_CRITERIA if legacy[c] != authoritative[c])


@dataclass(frozen=True)
class HumanNvdaGate:
    state: str
    human_nvda_pass: bool
    structural_ready: bool
    deployed_prerequisites_ready: bool

    def public_facts(self) -> dict[str, bool | str]:
        return {
            "state": self.state,
            "human_nvda_pass": self.human_nvda_pass,
            "structural_ready": self.structural_ready,
            "deployed_prerequisites_ready": self.deployed_prerequisites_ready,
        }


def evaluate_human_nvda_gate(
    *,
    structural_ready: bool,
    audited_deployed_sha_known: bool,
    passenger_runtime_verified: bool,
    setup_surface_available: bool,
    human_run_status: str = "NOT_EXECUTED",
) -> HumanNvdaGate:
    for label, value in (
        ("structural_ready", structural_ready),
        ("audited_deployed_sha_known", audited_deployed_sha_known),
        ("passenger_runtime_verified", passenger_runtime_verified),
        ("setup_surface_available", setup_surface_available),
    ):
        _bool(value, label)
    if human_run_status not in HUMAN_STATUS:
        raise ProtocolError("invalid human NVDA run status")
    deployed_ready = audited_deployed_sha_known and passenger_runtime_verified and setup_surface_available
    if not structural_ready or not deployed_ready:
        return HumanNvdaGate("BLOCKED", False, structural_ready, deployed_ready)
    if human_run_status == "NOT_EXECUTED":
        return HumanNvdaGate("READY_FOR_HUMAN", False, True, True)
    if human_run_status == "PASS":
        return HumanNvdaGate("HUMAN_PASS_RECORDED", True, True, True)
    if human_run_status == "FAIL":
        return HumanNvdaGate("HUMAN_FAIL_RECORDED", False, True, True)
    return HumanNvdaGate("BLOCKED", False, True, True)


def evaluate_auth_readiness(
    *,
    sanitized_application_source_ready: bool,
    passenger_runtime_verified: bool,
    server_setup_ready: bool,
    setup_session_is_first_human_blocker: bool,
    synthetic_only: bool = False,
) -> dict[str, Any]:
    """Delegate to the canonical boolean-only auth gate; never accepts credential values."""
    return evaluate_telegram_auth_gate(
        sanitized_application_source_ready=sanitized_application_source_ready,
        passenger_runtime_verified=passenger_runtime_verified,
        server_setup_ready=server_setup_ready,
        setup_session_is_first_human_blocker=setup_session_is_first_human_blocker,
        synthetic_only=synthetic_only,
    )


def telegram_setup_stage_plan(auth_state: str) -> tuple[dict[str, Any], ...]:
    if auth_state not in {AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED}:
        raise ProtocolError("invalid Telegram authorization state")
    allowed = auth_state == AUTH_REQUIRED
    stage_ids = (
        "OPEN_PRIVATE_ONE_TIME_SETUP",
        "ENTER_PHONE_IN_PRIVATE_SETUP",
        "REQUEST_LOGIN_CODE",
        "ENTER_LOGIN_CODE_IN_PRIVATE_SETUP",
        "ENTER_2FA_ONLY_IF_TELEGRAM_REQUIRES_IT",
        "VERIFY_SESSION_PERSISTED_PRIVATELY",
        "ROTATE_OR_DISABLE_ONE_TIME_SETUP_GATE",
        "RESTART_AND_VERIFY_SESSION_SURVIVES",
    )
    return tuple({
        "stage_id": stage_id,
        "user_input_allowed": allowed and stage_id in {
            "ENTER_PHONE_IN_PRIVATE_SETUP",
            "ENTER_LOGIN_CODE_IN_PRIVATE_SETUP",
            "ENTER_2FA_ONLY_IF_TELEGRAM_REQUIRES_IT",
        },
        "execute_now": False,
        "public_secret_value_allowed": False,
    } for stage_id in stage_ids)


@dataclass(frozen=True)
class ScenarioPlan:
    criterion: str
    operation_class: str
    required_gates: tuple[str, ...]
    expected_external_effect_count: int
    execute_now: bool = False


def live_scenario_plans() -> tuple[ScenarioPlan, ...]:
    common = ("AUDITED_DEPLOYED_SHA", "PASSENGER_RUNTIME_VERIFIED", "PRIVATE_API_AUTH_READY", "TELEGRAM_AUTHORIZED")
    return (
        ScenarioPlan("K1", "READ", common + ("ACTION_READ_ONLY_CONNECTED",), 0),
        ScenarioPlan("K2", "READ", common + ("ACTION_READ_ONLY_CONNECTED", "SAFE_PERSON_QUERY_SELECTED"), 0),
        ScenarioPlan("K3", "READ_DOWNLOAD", common + ("ACTION_READ_ONLY_CONNECTED", "PRIVATE_DOWNLOAD_READY"), 0),
        ScenarioPlan("K4", "WRITE_PREVIEW_ONLY", common + ("ACTION_WRITE_SCHEMA_VERIFIED", "ZERO_EFFECT_PREVIEW_READY"), 0),
        ScenarioPlan("K5", "WRITE_COMMIT_ONCE", common + (
            "ACTION_WRITE_SCHEMA_VERIFIED",
            "INDEPENDENT_AUDITOR_WRITE_APPROVAL",
            "SAFE_DESTINATION_CONFIRMED",
            "FRESH_EXPLICIT_USER_COMMIT",
            "IDEMPOTENCY_READY",
        ), 1),
    )


def k5_readiness(
    *,
    audited_deployed_sha_known: bool,
    passenger_runtime_verified: bool,
    private_api_auth_ready: bool,
    telegram_authorized: bool,
    action_write_schema_verified: bool,
    independent_auditor_write_approval: bool,
    safe_destination_confirmed: bool,
    destination_sha256: str | None,
    fresh_explicit_user_commit: bool,
    idempotency_ready: bool,
) -> dict[str, Any]:
    flags = {
        "audited_deployed_sha_known": audited_deployed_sha_known,
        "passenger_runtime_verified": passenger_runtime_verified,
        "private_api_auth_ready": private_api_auth_ready,
        "telegram_authorized": telegram_authorized,
        "action_write_schema_verified": action_write_schema_verified,
        "independent_auditor_write_approval": independent_auditor_write_approval,
        "safe_destination_confirmed": safe_destination_confirmed,
        "fresh_explicit_user_commit": fresh_explicit_user_commit,
        "idempotency_ready": idempotency_ready,
    }
    for label, value in flags.items():
        _bool(value, label)
    destination_hash_present = destination_sha256 is not None
    if destination_hash_present:
        _sha256(destination_sha256, "destination_sha256")
    if safe_destination_confirmed and not destination_hash_present:
        raise ProtocolError("confirmed safe destination requires hash-only public binding")
    ready = all(flags.values()) and destination_hash_present
    return {
        "state": "READY_FOR_EXPLICIT_LIVE_EXECUTION" if ready else "BLOCKED",
        "protocol_ready": ready,
        "execute_now": False,
        "expected_external_effect_count": 1,
        "destination_hash_present": destination_hash_present,
    }


def validate_human_accessibility_evidence(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate privacy-safe human evidence with no transcript, labels, names or screen text."""
    exact_keys = {
        "criterion", "candidate_sha", "status", "step_count", "finding_count",
        "keyboard_only_verified", "spoken_name_role_state_verified",
        "focus_order_verified", "status_announcement_verified",
        "no_private_content_recorded",
    }
    if not isinstance(payload, Mapping) or set(payload) != exact_keys:
        raise ProtocolError("human accessibility evidence schema mismatch")
    criterion = payload.get("criterion")
    if criterion not in HUMAN_NVDA_CRITERIA:
        raise ProtocolError("criterion is not a DEV10 human accessibility criterion")
    candidate_sha = _sha40(payload.get("candidate_sha"))
    status = payload.get("status")
    if status not in {"PASS", "FAIL", "BLOCKED"}:
        raise ProtocolError("invalid human evidence status")
    for key in (
        "keyboard_only_verified", "spoken_name_role_state_verified",
        "focus_order_verified", "status_announcement_verified",
        "no_private_content_recorded",
    ):
        _bool(payload.get(key), key)
    for key in ("step_count", "finding_count"):
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 1000):
            raise ProtocolError(f"{key} must be bounded integer")
    required = {
        "C1": ("keyboard_only_verified", "spoken_name_role_state_verified", "focus_order_verified", "status_announcement_verified"),
        "I1": ("keyboard_only_verified",),
        "I4": ("focus_order_verified",),
        "I6": ("status_announcement_verified",),
    }[criterion]
    if status == "PASS" and (not payload["no_private_content_recorded"] or any(not payload[k] for k in required)):
        raise ProtocolError("human PASS missing required verified facts")
    return {
        "criterion": criterion,
        "candidate_sha": candidate_sha,
        "status": status,
        "step_count": payload["step_count"],
        "finding_count": payload["finding_count"],
        "keyboard_only_verified": payload["keyboard_only_verified"],
        "spoken_name_role_state_verified": payload["spoken_name_role_state_verified"],
        "focus_order_verified": payload["focus_order_verified"],
        "status_announcement_verified": payload["status_announcement_verified"],
        "no_private_content_recorded": payload["no_private_content_recorded"],
    }


def human_nvda_step_ids() -> tuple[str, ...]:
    return (
        "START_FROM_DOCUMENT_TOP",
        "TAB_FORWARD_THROUGH_EVERY_INTERACTIVE_CONTROL",
        "SHIFT_TAB_BACK_THROUGH_EVERY_INTERACTIVE_CONTROL",
        "VERIFY_SPOKEN_NAME_ROLE_STATE",
        "ACTIVATE_WITH_KEYBOARD_ONLY",
        "TRIGGER_VALIDATION_ERROR_WITH_NONSECRET_TEST_INPUT",
        "VERIFY_ERROR_ANNOUNCEMENT_WITHOUT_FOCUS_LOSS",
        "VERIFY_STATUS_ANNOUNCEMENT_AFTER_STATE_CHANGE",
        "RECOVER_FROM_ERROR_WITH_KEYBOARD_ONLY",
        "REPEAT_KEY_FLOW_IN_NVDA_BROWSE_AND_FOCUS_MODES",
        "RECORD_ONLY_RESULT_CODES_COUNTS_AND_HASHES",
    )


def operator_bootstrap_contract() -> dict[str, bool | str]:
    return {
        "mode": "ONE_TIME_SUPPORT_MANAGED_BOOTSTRAP",
        "user_recurring_cpanel_required": False,
        "private_runtime_preserved": True,
        "session_storage_preserved": True,
        "backup_before_change_required": True,
        "passenger_restart_requires_gate": True,
        "rollback_required": True,
    }


def assert_dev10_protocol_consistent() -> None:
    projection = authoritative_accessibility_projection()
    if any(projection[c] != "LIVE_EXTERNAL_REQUIRED" for c in HUMAN_NVDA_CRITERIA):
        raise ProtocolError("human NVDA truth boundary invalid")
    plans = live_scenario_plans()
    if [plan.criterion for plan in plans] != ["K1", "K2", "K3", "K4", "K5"]:
        raise ProtocolError("K scenario plan order invalid")
    if any(plan.execute_now for plan in plans):
        raise ProtocolError("live scenario plan must not self-execute")
    k5 = plans[-1]
    required = set(k5.required_gates)
    if not {"INDEPENDENT_AUDITOR_WRITE_APPROVAL", "SAFE_DESTINATION_CONFIRMED", "FRESH_EXPLICIT_USER_COMMIT"} <= required:
        raise ProtocolError("K5 safety gates incomplete")


assert_dev10_protocol_consistent()
