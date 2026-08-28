# -*- coding: utf-8 -*-
"""DEV10 operator/setup UX contracts.

Credential-free, side-effect-free rules for the one-time bootstrap boundary.
These helpers do not operate HOSTiQ, Telegram, cPanel, Passenger, or ChatGPT
Actions and cannot authorize a live step.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from ops.acceptance_harness import AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED


class OperatorUxError(ValueError):
    pass


ACTORS = frozenset({"USER", "SUPPORT", "AUTOMATION", "AUDITOR"})
USER_AUTH_ACTIONS = frozenset({
    "OPEN_PRIVATE_SETUP",
    "ENTER_PHONE",
    "ENTER_LOGIN_CODE",
    "ENTER_2FA_IF_REQUIRED",
    "CONFIRM_SPOKEN_STATUS",
})


@dataclass(frozen=True)
class BootstrapStep:
    actor: str
    action: str
    requires_cpanel: bool = False
    accepts_private_user_input: bool = False
    execute_now: bool = False

    def public_facts(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "action": self.action,
            "requires_cpanel": self.requires_cpanel,
            "accepts_private_user_input": self.accepts_private_user_input,
            "execute_now": self.execute_now,
        }


def _validate_auth_state(auth_state: str) -> str:
    if auth_state not in {AUTH_NOT_YET_REQUIRED, AUTH_REQUIRED}:
        raise OperatorUxError("invalid Telegram authorization state")
    return auth_state


def validate_bootstrap_steps(auth_state: str, steps: Iterable[BootstrapStep]) -> tuple[BootstrapStep, ...]:
    """Fail closed on recurring/manual cPanel work or premature user-secret work."""
    auth_state = _validate_auth_state(auth_state)
    rows = tuple(steps)
    if not rows or len(rows) > 32:
        raise OperatorUxError("bootstrap step set must be non-empty and bounded")
    for step in rows:
        if not isinstance(step, BootstrapStep):
            raise OperatorUxError("bootstrap step type mismatch")
        if step.actor not in ACTORS:
            raise OperatorUxError("bootstrap actor invalid")
        if not isinstance(step.action, str) or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,63}", step.action):
            raise OperatorUxError("bootstrap action invalid")
        if step.actor == "USER" and step.requires_cpanel:
            raise OperatorUxError("user must not be a recurring cPanel operator")
        if step.actor == "USER" and step.action not in USER_AUTH_ACTIONS:
            raise OperatorUxError("user action exceeds minimal one-time authorization scope")
        if step.accepts_private_user_input and step.actor != "USER":
            raise OperatorUxError("private user input must stay in the private user setup step")
        if auth_state == AUTH_NOT_YET_REQUIRED and step.actor == "USER":
            if step.execute_now or step.accepts_private_user_input:
                raise OperatorUxError("Telegram user input requested before authoritative auth gate")
        if step.execute_now:
            raise OperatorUxError("DEV10 planning contract never self-executes bootstrap steps")
    return rows


def support_managed_bootstrap_plan(auth_state: str) -> tuple[BootstrapStep, ...]:
    """Return a non-self-executing plan with no recurring cPanel burden on the user."""
    auth_state = _validate_auth_state(auth_state)
    rows: list[BootstrapStep] = [
        BootstrapStep("SUPPORT", "PREPARE_SERVER_DEPENDENCIES"),
        BootstrapStep("SUPPORT", "VERIFY_PRIVATE_SETUP_GATE"),
        BootstrapStep("AUTOMATION", "VERIFY_PASSENGER_RUNTIME"),
    ]
    if auth_state == AUTH_REQUIRED:
        rows.extend((
            BootstrapStep("USER", "OPEN_PRIVATE_SETUP"),
            BootstrapStep("USER", "ENTER_PHONE", accepts_private_user_input=True),
            BootstrapStep("USER", "ENTER_LOGIN_CODE", accepts_private_user_input=True),
            BootstrapStep("USER", "ENTER_2FA_IF_REQUIRED", accepts_private_user_input=True),
            BootstrapStep("USER", "CONFIRM_SPOKEN_STATUS"),
        ))
    rows.extend((
        BootstrapStep("AUTOMATION", "VERIFY_SESSION_PERSISTENCE"),
        BootstrapStep("SUPPORT", "ROTATE_OR_DISABLE_SETUP_GATE"),
        BootstrapStep("SUPPORT", "RESTART_PASSENGER"),
        BootstrapStep("AUTOMATION", "RUN_HARMLESS_HEALTH_SMOKE"),
    ))
    return validate_bootstrap_steps(auth_state, rows)


def completion_handoff_contract() -> dict[str, Any]:
    """Public, non-secret completion semantics for an accessible setup page."""
    return {
        "user_cpanel_required": False,
        "user_terminal_required": False,
        "restart_owner": "SUPPORT_OR_AUTOMATION",
        "dependency_install_owner": "SUPPORT_OR_AUTOMATION",
        "public_secret_copy_required": False,
        "recurring_manual_server_admin_required": False,
        "execute_now": False,
    }


def scan_manual_admin_copy(text: str) -> tuple[str, ...]:
    """Detect direct user-facing cPanel/Python-App operator instructions.

    This is a narrow regression oracle, not a natural-language accessibility
    certification engine. Neutral documentation mentioning cPanel is not enough;
    the text must contain an operator action near the cPanel reference.
    """
    if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8")) > 131072:
        raise OperatorUxError("operator copy must be non-empty bounded UTF-8 text")
    normalized = " ".join(text.casefold().split())
    findings: set[str] = set()

    def near(left: str, right: str) -> bool:
        return bool(re.search(left + r".{0,160}" + right, normalized) or re.search(right + r".{0,160}" + left, normalized))

    cpanel = r"cpanel"
    if near(cpanel, r"(?:run\s+pip\s+install|pip\s+install|виконайте\s+run\s+pip\s+install|встановіть\s+requirements)"):
        findings.add("USER_MANUAL_CPANEL_DEPENDENCY_INSTALL")
    if near(cpanel, r"(?:restart(?:\s+python\s+app)?|натисніть\s+restart|перезапуст(?:іть|ити)|рестарт)"):
        findings.add("USER_MANUAL_CPANEL_RESTART")
    if near(cpanel, r"(?:відкрийте|зайдіть|перейдіть|open|go\s+to|log\s+in|увійдіть)"):
        findings.add("USER_MANUAL_CPANEL_NAVIGATION")
    return tuple(sorted(findings))


def operator_ux_readiness(*, auth_state: str, setup_copy: str) -> dict[str, Any]:
    """Source/pre-live readiness only; never human NVDA or production PASS."""
    _validate_auth_state(auth_state)
    findings = scan_manual_admin_copy(setup_copy)
    plan = support_managed_bootstrap_plan(auth_state)
    return {
        "source_operator_copy_ready": not findings,
        "manual_admin_finding_count": len(findings),
        "manual_admin_findings": list(findings),
        "user_step_count": sum(1 for step in plan if step.actor == "USER"),
        "user_cpanel_required": False,
        "human_nvda_pass": False,
        "live_execution_authorized": False,
    }
