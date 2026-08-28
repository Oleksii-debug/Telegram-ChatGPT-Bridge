# -*- coding: utf-8 -*-
"""DEV10 binding between source-green evidence and human/live accessibility evidence.

This module is credential-free and side-effect-free. It prevents a source/PR
result, a GitHub pull-request merge ref, stale live prerequisite evidence, or a
stale human NVDA result from being mistaken for evidence about the release
actually deployed and running.

It never authorizes deployment, Telegram login, a ChatGPT Action live call, or
Telegram writes. Human NVDA PASS remains an explicit human result bound to an
exact deployed SHA and an exact setup-surface hash.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from ops.acceptance_harness import AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED

SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SOURCE_IDENTITY_KINDS = frozenset({"EXACT_BRANCH_HEAD_SHA", "EXACT_RELEASE_SHA"})
FORBIDDEN_IDENTITY_KINDS = frozenset({"PR_MERGE_REF", "WORKTREE_HEAD", "SHORT_SHA", "PR_NUMBER"})
HUMAN_CRITERIA = frozenset({"C1", "I1", "I4", "I6"})
HUMAN_STATUSES = frozenset({"PASS", "FAIL", "BLOCKED"})
_LIVE_BINDING_KEYS = frozenset({
    "deployed_sha",
    "release_gate_sha",
    "live_manifest_sha",
    "passenger_application_sha",
    "running_sha",
    "setup_surface_sha256",
    "independent_auditor_release_gate",
    "live_manifest_reconciled",
    "passenger_application_process_verified",
    "running_sha_verified",
    "private_setup_surface_ready",
})
_RECEIPT_KEYS = frozenset({
    "criterion",
    "deployed_sha",
    "setup_surface_sha256",
    "status",
    "step_count",
    "finding_count",
    "keyboard_only_verified",
    "spoken_name_role_state_verified",
    "focus_order_verified",
    "status_announcement_verified",
    "no_private_content_recorded",
})


class HumanLiveGateError(ValueError):
    """Fail-closed error for DEV10 live-human evidence contracts."""


def _bool(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise HumanLiveGateError(f"{label} must be boolean")
    return value


def _sha40(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA40_RE.fullmatch(value):
        raise HumanLiveGateError(f"{label} must be exact SHA-40")
    return value


def _sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
        raise HumanLiveGateError(f"{label} must be exact SHA-256")
    return value


def validate_source_identity_kind(kind: Any) -> str:
    """Reject identities that can move or describe a PR merge rather than release bytes."""
    if not isinstance(kind, str):
        raise HumanLiveGateError("source_identity_kind must be string")
    if kind in FORBIDDEN_IDENTITY_KINDS:
        raise HumanLiveGateError("source identity is not an exact deployable release identity")
    if kind not in SOURCE_IDENTITY_KINDS:
        raise HumanLiveGateError("unknown source identity kind")
    return kind


@dataclass(frozen=True)
class LivePrerequisiteBinding:
    """Privacy-safe live prerequisite facts bound to exact release identities.

    Each SHA field is independently recorded by the corresponding live evidence
    stage. Booleans alone are never accepted as sufficient proof because a stale
    True value from a prior deployment must not be reusable for a new release.
    """

    deployed_sha: str
    release_gate_sha: str
    live_manifest_sha: str
    passenger_application_sha: str
    running_sha: str
    setup_surface_sha256: str
    independent_auditor_release_gate: bool
    live_manifest_reconciled: bool
    passenger_application_process_verified: bool
    running_sha_verified: bool
    private_setup_surface_ready: bool

    def release_identities_match(self) -> bool:
        return all(
            value == self.deployed_sha
            for value in (
                self.release_gate_sha,
                self.live_manifest_sha,
                self.passenger_application_sha,
                self.running_sha,
            )
        )


def validate_live_prerequisite_binding(payload: Mapping[str, Any]) -> LivePrerequisiteBinding:
    """Validate exact, bounded live evidence without accepting private values.

    The schema contains only SHA identities, a setup-surface hash and booleans.
    It intentionally has no fields for host paths, URLs, tokens, Telegram data,
    screenshots, transcripts, credentials or session material.
    """
    if not isinstance(payload, Mapping) or set(payload) != _LIVE_BINDING_KEYS:
        raise HumanLiveGateError("live prerequisite binding schema mismatch")

    values = {
        "deployed_sha": _sha40(payload.get("deployed_sha"), "deployed_sha"),
        "release_gate_sha": _sha40(payload.get("release_gate_sha"), "release_gate_sha"),
        "live_manifest_sha": _sha40(payload.get("live_manifest_sha"), "live_manifest_sha"),
        "passenger_application_sha": _sha40(payload.get("passenger_application_sha"), "passenger_application_sha"),
        "running_sha": _sha40(payload.get("running_sha"), "running_sha"),
        "setup_surface_sha256": _sha256(payload.get("setup_surface_sha256"), "setup_surface_sha256"),
    }
    flags = {}
    for key in (
        "independent_auditor_release_gate",
        "live_manifest_reconciled",
        "passenger_application_process_verified",
        "running_sha_verified",
        "private_setup_surface_ready",
    ):
        flags[key] = _bool(payload.get(key), key)
    return LivePrerequisiteBinding(**values, **flags)


@dataclass(frozen=True)
class HumanLiveReadiness:
    state: str
    exact_deployment_bound: bool
    live_prerequisites_ready: bool
    ready_for_human_nvda: bool
    telegram_user_input_allowed: bool
    human_nvda_pass: bool = False
    live_execution_authorized: bool = False

    def public_facts(self) -> dict[str, bool | str]:
        return {
            "state": self.state,
            "exact_deployment_bound": self.exact_deployment_bound,
            "live_prerequisites_ready": self.live_prerequisites_ready,
            "ready_for_human_nvda": self.ready_for_human_nvda,
            "telegram_user_input_allowed": self.telegram_user_input_allowed,
            "human_nvda_pass": False,
            "live_execution_authorized": False,
        }


def evaluate_human_live_readiness(
    *,
    source_sha: str,
    source_identity_kind: str,
    source_ci_green: bool,
    nonlive_prepare_verified: bool,
    live_binding: Mapping[str, Any],
    telegram_auth_state: str,
) -> HumanLiveReadiness:
    """Evaluate whether a human NVDA run may be requested, never whether it passed.

    Source-green evidence is necessary but insufficient. Every live prerequisite
    is independently SHA-bound to the deployed release, so stale booleans from a
    prior deployment cannot be mixed with a newer source/deployed SHA.
    """
    source_sha = _sha40(source_sha, "source_sha")
    validate_source_identity_kind(source_identity_kind)
    _bool(source_ci_green, "source_ci_green")
    _bool(nonlive_prepare_verified, "nonlive_prepare_verified")
    binding = validate_live_prerequisite_binding(live_binding)
    if telegram_auth_state not in {AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED}:
        raise HumanLiveGateError("invalid Telegram authorization state")

    source_matches_deployed = source_sha == binding.deployed_sha
    release_gate_matches = binding.release_gate_sha == binding.deployed_sha
    live_manifest_matches = binding.live_manifest_sha == binding.deployed_sha
    passenger_matches = binding.passenger_application_sha == binding.deployed_sha
    running_matches = binding.running_sha == binding.deployed_sha
    exact = (
        source_matches_deployed
        and release_gate_matches
        and live_manifest_matches
        and passenger_matches
        and running_matches
    )
    prelive_ready = source_ci_green and nonlive_prepare_verified and binding.independent_auditor_release_gate
    live_ready = (
        prelive_ready
        and exact
        and binding.live_manifest_reconciled
        and binding.passenger_application_process_verified
        and binding.running_sha_verified
        and binding.private_setup_surface_ready
    )

    if not source_ci_green or not nonlive_prepare_verified:
        state = "BLOCKED_PRELIVE_GATE"
    elif not source_matches_deployed:
        state = "BLOCKED_DEPLOYED_SHA_MISMATCH"
    elif not binding.independent_auditor_release_gate:
        state = "BLOCKED_PRELIVE_GATE"
    elif not release_gate_matches:
        state = "BLOCKED_RELEASE_GATE_SHA_MISMATCH"
    elif not live_manifest_matches:
        state = "BLOCKED_LIVE_MANIFEST_SHA_MISMATCH"
    elif not binding.live_manifest_reconciled:
        state = "BLOCKED_LIVE_RECONCILIATION"
    elif not passenger_matches:
        state = "BLOCKED_PASSENGER_SHA_MISMATCH"
    elif not binding.passenger_application_process_verified:
        state = "BLOCKED_PASSENGER_APPLICATION_PROCESS"
    elif not running_matches:
        state = "BLOCKED_RUNNING_SHA_MISMATCH"
    elif not binding.running_sha_verified:
        state = "BLOCKED_RUNNING_SHA"
    elif not binding.private_setup_surface_ready:
        state = "BLOCKED_PRIVATE_SETUP_SURFACE"
    else:
        state = "READY_FOR_HUMAN_NVDA"

    return HumanLiveReadiness(
        state=state,
        exact_deployment_bound=exact,
        live_prerequisites_ready=live_ready,
        ready_for_human_nvda=live_ready,
        telegram_user_input_allowed=live_ready and telegram_auth_state == AUTH_REQUIRED,
    )


def _validate_receipt_content(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate receipt schema/content without deciding whether its identity is current."""
    if not isinstance(payload, Mapping) or set(payload) != _RECEIPT_KEYS:
        raise HumanLiveGateError("human receipt schema mismatch")

    criterion = payload.get("criterion")
    if criterion not in HUMAN_CRITERIA:
        raise HumanLiveGateError("criterion is not human-live accessibility evidence")
    deployed_sha = _sha40(payload.get("deployed_sha"), "deployed_sha")
    surface_hash = _sha256(payload.get("setup_surface_sha256"), "setup_surface_sha256")
    status = payload.get("status")
    if status not in HUMAN_STATUSES:
        raise HumanLiveGateError("invalid human receipt status")

    for key in (
        "keyboard_only_verified",
        "spoken_name_role_state_verified",
        "focus_order_verified",
        "status_announcement_verified",
        "no_private_content_recorded",
    ):
        _bool(payload.get(key), key)
    for key in ("step_count", "finding_count"):
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not (0 <= value <= 1000):
            raise HumanLiveGateError(f"{key} must be bounded integer")

    required = {
        "C1": ("keyboard_only_verified", "spoken_name_role_state_verified", "focus_order_verified", "status_announcement_verified"),
        "I1": ("keyboard_only_verified",),
        "I4": ("focus_order_verified",),
        "I6": ("status_announcement_verified",),
    }[criterion]
    if status == "PASS":
        if not payload["no_private_content_recorded"]:
            raise HumanLiveGateError("human PASS cannot record private content")
        if any(not payload[key] for key in required):
            raise HumanLiveGateError("human PASS missing criterion-required verification")

    normalized = {key: payload[key] for key in sorted(_RECEIPT_KEYS)}
    normalized["deployed_sha"] = deployed_sha
    normalized["setup_surface_sha256"] = surface_hash
    return normalized


def validate_deployed_human_receipt(
    payload: Mapping[str, Any],
    *,
    expected_deployed_sha: str,
    expected_setup_surface_sha256: str,
) -> dict[str, Any]:
    """Validate a privacy-safe human result against the current deployed surface.

    No transcripts, control labels, Telegram identifiers, messages, filenames,
    setup paths or credential values are accepted by the schema.
    """
    expected_deployed_sha = _sha40(expected_deployed_sha, "expected_deployed_sha")
    expected_setup_surface_sha256 = _sha256(expected_setup_surface_sha256, "expected_setup_surface_sha256")
    normalized = _validate_receipt_content(payload)
    if normalized["deployed_sha"] != expected_deployed_sha:
        raise HumanLiveGateError("human receipt is stale for deployed SHA")
    if normalized["setup_surface_sha256"] != expected_setup_surface_sha256:
        raise HumanLiveGateError("human receipt is stale for setup surface")
    return normalized


def assess_human_receipt_currentness(
    payload: Mapping[str, Any],
    *,
    current_deployed_sha: str,
    current_setup_surface_sha256: str,
) -> str:
    """Return CURRENT only for semantically valid evidence on the current surface.

    A malformed or false-PASS receipt fails validation rather than being labelled
    CURRENT. Any deployment or setup-surface identity change makes a previously
    valid receipt explicitly stale.
    """
    current_deployed_sha = _sha40(current_deployed_sha, "current_deployed_sha")
    current_setup_surface_sha256 = _sha256(current_setup_surface_sha256, "current_setup_surface_sha256")
    normalized = _validate_receipt_content(payload)
    if normalized["deployed_sha"] != current_deployed_sha:
        return "STALE_DEPLOYED_SHA"
    if normalized["setup_surface_sha256"] != current_setup_surface_sha256:
        return "STALE_SETUP_SURFACE"
    return "CURRENT"


def deployment_change_invalidates_human_evidence(
    *,
    previous_deployed_sha: str,
    current_deployed_sha: str,
    previous_setup_surface_sha256: str,
    current_setup_surface_sha256: str,
) -> bool:
    previous_deployed_sha = _sha40(previous_deployed_sha, "previous_deployed_sha")
    current_deployed_sha = _sha40(current_deployed_sha, "current_deployed_sha")
    previous_setup_surface_sha256 = _sha256(previous_setup_surface_sha256, "previous_setup_surface_sha256")
    current_setup_surface_sha256 = _sha256(current_setup_surface_sha256, "current_setup_surface_sha256")
    return previous_deployed_sha != current_deployed_sha or previous_setup_surface_sha256 != current_setup_surface_sha256


def current_source_green_projection(*, source_sha: str, recovery_guard_success: bool, nonlive_prepare_verified: bool) -> dict[str, Any]:
    """Public source-only projection deliberately incapable of human/live PASS."""
    source_sha = _sha40(source_sha, "source_sha")
    _bool(recovery_guard_success, "recovery_guard_success")
    _bool(nonlive_prepare_verified, "nonlive_prepare_verified")
    source_ready = recovery_guard_success and nonlive_prepare_verified
    return {
        "source_sha": source_sha,
        "source_release_ready": source_ready,
        "human_nvda_pass": False,
        "telegram_user_input_allowed": False,
        "production_pass": False,
        "live_execution_authorized": False,
    }


__all__ = [
    "HumanLiveGateError",
    "HumanLiveReadiness",
    "LivePrerequisiteBinding",
    "assess_human_receipt_currentness",
    "current_source_green_projection",
    "deployment_change_invalidates_human_evidence",
    "evaluate_human_live_readiness",
    "validate_deployed_human_receipt",
    "validate_live_prerequisite_binding",
    "validate_source_identity_kind",
]
