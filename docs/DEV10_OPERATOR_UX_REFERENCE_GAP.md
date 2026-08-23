# DEV10 Operator / Setup UX — Reference-Gap Contract

Status: `REFERENCE_ANALYSIS_ONLY / SOURCE_PROTOCOL / NO_LIVE_EXECUTION`.

## Why this exists

The sanitized HOSTiQ v0.4 project snapshot is explicitly reference-only, not live authority and not deployment permission. After fresh Drive/GitHub reconstruction, DEV10 inspected its one-time setup implementation only to derive regression cases for the current locked UX requirement: the user must not become a recurring cPanel/server operator.

The reference setup forms contain useful accessibility structure: explicit labels, named buttons, headings and text errors. However, selected reference-only operator copy tells the user to perform dependency installation and Python App restart through cPanel. This observation is **not** a claim about the current live production surface. It is a regression fixture showing a class of UX that the final production bootstrap must avoid.

## Current authoritative boundary

- `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative.
- No phone, login code, 2FA password, Telegram session or API secret is requested now.
- Structural/source checks are not human NVDA PASS.
- No production deploy, Passenger restart, live Action call or Telegram operation is authorized by this document or DEV10 code.

## Fail-closed operator model

`ops/dev10_operator_ux.py` defines the following constraints:

1. The user is never assigned a cPanel step.
2. The user is never assigned dependency installation, Passenger restart or general server administration.
3. Before Telegram authorization becomes authoritative `REQUIRED`, the plan contains no user/private-input step.
4. When authorization is later `REQUIRED`, user interaction is limited to the private one-time authorization surface: open it, enter phone/login code, enter 2FA only if Telegram requires it, and confirm spoken status.
5. Server dependency preparation, setup-gate management and restart belong to HOSTiQ support or automation.
6. Every generated DEV10 plan remains `execute_now=false`; the protocol cannot self-authorize live work.
7. Public/source readiness always keeps `human_nvda_pass=false` and `live_execution_authorized=false`.

## Regression oracle

`scan_manual_admin_copy()` is intentionally narrow. It flags direct user-facing cPanel instructions for dependency installation, restart or navigation. It is not a natural-language accessibility certification engine and does not convert documentation analysis into acceptance PASS.

The tests include sanitized reference-style phrases only. They contain no credential values, private Telegram data, setup route or live server evidence.

## Production completion target

A final accessible setup completion state should communicate that authorization succeeded and what will happen next, without requiring the user to open cPanel or a server terminal. Dependency installation/restart/rotation/health verification should be handled by support or automation. If a human NVDA test is later authorized, C1/I1/I4/I6 must still be verified separately on the exact deployed setup surface.
