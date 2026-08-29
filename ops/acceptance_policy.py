# -*- coding: utf-8 -*-
"""Canonical authority policy for all A--K acceptance criteria.

The policy is deliberately data-only and has no dependency on the acceptance
harness.  Coverage inventory and typed result validation both consume the same
table, preventing planning metadata from drifting away from PASS authority.
"""
from __future__ import annotations

from types import MappingProxyType
from typing import Any, Mapping


EVIDENCE_CLASSES = frozenset({
    "SYNTHETIC_EXECUTABLE",
    "REAL_SOURCE_REQUIRED",
    "LIVE_EXTERNAL_REQUIRED",
})
AUTHORITY_CLASSES = frozenset({
    "SYNTHETIC_TEST",
    "SOURCE_CI",
    "LIVE_RUNTIME",
    "INDEPENDENT_AUDITOR",
    "INDEPENDENT_HUMAN",
    "USER_CONFIRMATION",
})
AUTHORITY_PROVIDER_POLICY = MappingProxyType({
    "SYNTHETIC_TEST": frozenset({"SYNTHETIC_TEST"}),
    "SOURCE_CI": frozenset({"GITHUB_ACTIONS"}),
    "LIVE_RUNTIME": frozenset({"LIVE_ENDPOINT", "HOSTIQ_PRIVATE"}),
    "INDEPENDENT_AUDITOR": frozenset({"DRIVE_CONTROL"}),
    "INDEPENDENT_HUMAN": frozenset({"DRIVE_CONTROL"}),
    "USER_CONFIRMATION": frozenset({"DRIVE_CONTROL"}),
})

CRITERION_IDS = tuple(
    f"{group}{number}"
    for group, count in (
        ("A", 5), ("B", 8), ("C", 6), ("D", 6), ("E", 6), ("F", 8),
        ("G", 5), ("H", 5), ("I", 7), ("J", 6), ("K", 5),
    )
    for number in range(1, count + 1)
)

SYNTHETIC_EXECUTABLE = frozenset({
    "B4", "B5", "B7", "B8",
    "C3", "C4", "C6",
    "D1", "D2", "D3", "D4", "D5", "D6",
    "E1", "E2", "E3", "E4", "E5",
    "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8",
    "G1", "G2", "G3", "G4", "G5",
    "H3", "H4", "H5",
    "J2", "J3", "J5",
})
LIVE_EXTERNAL_REQUIRED = frozenset({
    "A5",
    "C1", "C2", "C5",
    "H1", "H2",
    "I1", "I4", "I6",
    "J1", "J4", "J6",
    "K1", "K2", "K3", "K4", "K5",
})
HUMAN_ACCESSIBILITY_REQUIRED = frozenset({"C1", "I1", "I4", "I6"})

_ENVIRONMENTS = {
    "SYNTHETIC_EXECUTABLE": frozenset({
        "SYNTHETIC", "GITHUB_CI", "LOCAL_TEST", "AUDITOR_REPLAY",
    }),
    "REAL_SOURCE_REQUIRED": frozenset({
        "GITHUB_CI", "LOCAL_TEST", "AUDITOR_REPLAY", "HOSTIQ_PRIVATE_STAGING",
    }),
    "LIVE_EXTERNAL_REQUIRED": frozenset({"HOSTIQ_PRODUCTION"}),
}
_PROVIDERS = {
    "SYNTHETIC_EXECUTABLE": frozenset({"SYNTHETIC_TEST", "GITHUB_ACTIONS"}),
    "REAL_SOURCE_REQUIRED": frozenset({
        "GITHUB_ACTIONS", "DRIVE_CONTROL", "HOSTIQ_PRIVATE",
    }),
    "LIVE_EXTERNAL_REQUIRED": frozenset({
        "LIVE_ENDPOINT", "HOSTIQ_PRIVATE", "DRIVE_CONTROL",
    }),
}


def _criterion_policy(criterion: str) -> Mapping[str, Any]:
    if criterion in LIVE_EXTERNAL_REQUIRED:
        evidence_class = "LIVE_EXTERNAL_REQUIRED"
        required_authorities = {"LIVE_RUNTIME"}
    elif criterion in SYNTHETIC_EXECUTABLE:
        evidence_class = "SYNTHETIC_EXECUTABLE"
        required_authorities = set()
    else:
        evidence_class = "REAL_SOURCE_REQUIRED"
        required_authorities = set()

    required_true_facts = {"success"}
    required_fact_values: dict[str, Any] = {}
    required_fact_keys: set[str] = set()
    requires_deployed_sha = evidence_class == "LIVE_EXTERNAL_REQUIRED"

    if criterion == "A3":
        required_fact_values["http_status"] = 200
    if criterion == "B4":
        required_true_facts.update({"tree_scan_passed", "history_scan_passed"})
        required_fact_values["findings_count"] = 0
    if criterion in HUMAN_ACCESSIBILITY_REQUIRED:
        required_authorities.add("INDEPENDENT_HUMAN")
        required_true_facts.add("human_verified")
    if criterion in {"C1", "I1"}:
        required_true_facts.add("keyboard_operable")
    if criterion == "I4":
        required_true_facts.add("tab_order_valid")
    if criterion in {"C1", "I6"}:
        required_true_facts.add("nvda_verified")
    if criterion in {"H1", "H2", "J1", "J4", "J6", "K1", "K2", "K3", "K4", "K5"}:
        required_authorities.add("INDEPENDENT_AUDITOR")
    if criterion == "H1":
        required_true_facts.add("schema_valid")
        required_fact_keys.add("observed_sha")
    if criterion == "H2":
        required_true_facts.add("authorized")
        required_fact_values["operation_kind"] = "READ"
        required_fact_keys.add("observed_sha")
    if criterion in {"J1", "J4", "J6"}:
        required_fact_keys.add("observed_sha")
    if criterion == "K5":
        required_authorities.add("USER_CONFIRMATION")
        required_true_facts.update({
            "w10_approval_verified",
            "safe_destination_verified",
            "exact_preview_verified",
            "exact_text_verified",
            "idempotency_bound",
            "fresh_user_confirmation",
            "commit_single_use",
            "deduplicated",
        })
        required_fact_values.update({
            "operation_kind": "SEND",
            "external_effect_count": 1,
            "replay_duplicate_count": 0,
        })
        required_fact_keys.update({
            "payload_sha256",
            "identifier_sha256",
            "idempotency_sha256",
            "preview_fingerprint_sha256",
        })

    return MappingProxyType({
        "criterion": criterion,
        "evidence_class": evidence_class,
        "allowed_environment_classes": _ENVIRONMENTS[evidence_class],
        "allowed_primary_providers": _PROVIDERS[evidence_class],
        "required_authority_classes": frozenset(required_authorities),
        "required_true_facts": frozenset(required_true_facts),
        "required_fact_values": MappingProxyType(required_fact_values),
        "required_fact_keys": frozenset(required_fact_keys),
        "requires_deployed_sha": requires_deployed_sha,
        "human_verification_required": criterion in HUMAN_ACCESSIBILITY_REQUIRED,
        "explicit_write_approval_required": criterion == "K5",
    })


CRITERION_POLICIES = MappingProxyType({
    criterion: _criterion_policy(criterion) for criterion in CRITERION_IDS
})


def criterion_policy(criterion: str) -> Mapping[str, Any]:
    try:
        return CRITERION_POLICIES[criterion]
    except (KeyError, TypeError):
        raise ValueError("unknown acceptance criterion") from None


def validate_policy_table() -> None:
    if len(CRITERION_IDS) != 67 or len(set(CRITERION_IDS)) != 67:
        raise ValueError("acceptance criterion policy identity mismatch")
    if set(CRITERION_POLICIES) != set(CRITERION_IDS):
        raise ValueError("acceptance criterion policy coverage mismatch")
    counts = {name: 0 for name in EVIDENCE_CLASSES}
    for criterion, policy in CRITERION_POLICIES.items():
        if policy["criterion"] != criterion:
            raise ValueError("acceptance criterion policy key mismatch")
        evidence_class = policy["evidence_class"]
        if evidence_class not in EVIDENCE_CLASSES:
            raise ValueError("acceptance evidence class invalid")
        counts[evidence_class] += 1
        if not policy["required_true_facts"] or "success" not in policy["required_true_facts"]:
            raise ValueError("acceptance PASS must require success")
        if not policy["required_authority_classes"].issubset(AUTHORITY_CLASSES):
            raise ValueError("acceptance authority class invalid")
    if counts != {
        "LIVE_EXTERNAL_REQUIRED": 17,
        "REAL_SOURCE_REQUIRED": 13,
        "SYNTHETIC_EXECUTABLE": 37,
    }:
        raise ValueError("acceptance criterion policy counts mismatch")


validate_policy_table()
