# DEV10 Accessibility / Setup UX / Live-E2E Protocol

Status: source/protocol hardening only. This document does not authorize merge, deployment, Passenger restart, Telegram authorization, ChatGPT Action live execution, human NVDA PASS, or K5.

## Truth boundary

DEV10 treats accessibility evidence in three different layers:

1. **Structural prerequisite evidence** can inspect markup and source properties such as explicit labels, accessible button names, heading order, one main landmark, absence of positive `tabindex`, absence of obvious pointer-only controls, resolvable ARIA references, and presence of a status/live region.
2. **Human keyboard/NVDA evidence** is a separate live evidence class. C1, I1, I4 and I6 cannot become PASS from source parsing, unit tests, browser-free HTML checks, or a developer assertion. They require an actual human run against the exact deployed audited release.
3. **Product/live scenarios** H1/H2 and K1-K5 require the deployed release/runtime/Telegram/Action prerequisites specified by the acceptance plan. K5 additionally requires Independent Auditor write approval, a confirmed safe destination, a fresh explicit user commit and idempotency readiness.

The current integrated candidate truth projection classifies C1/I1/I4/I6 as `LIVE_EXTERNAL_REQUIRED`. A legacy synthetic coverage helper still projects the accessibility criteria differently. `ops.dev10_accessibility_protocol.detect_legacy_accessibility_truth_drift()` makes that disagreement explicit so downstream tooling cannot silently treat the older projection as authoritative.

## Current Telegram authorization state

Current authoritative state is `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED`.

DEV10 must not request or collect a phone number, Telegram login code, 2FA password, session/StringSession, API hash, bearer token, setup-route value or other private credential while earlier release/runtime/server gates remain unresolved.

The boolean-only canonical authorization gate may transition to `USER_TELEGRAM_AUTH_REQUIRED` only when all of the following are true:

- sanitized real application source is ready;
- actual Passenger runtime is verified;
- server-side setup is ready;
- Telegram setup/session input is the first remaining human-dependent blocker;
- the work is not synthetic-only.

Even after the state becomes REQUIRED, credential values belong only in the authenticated private one-time setup flow. Public GitHub, Drive reports, issue comments and ChatGPT handoff evidence must contain no credential values.

## Setup UX structural contract

The setup surface should satisfy all of these source-level prerequisites before a human NVDA run is scheduled:

- one meaningful `h1` and no heading-level jumps;
- exactly one main landmark;
- every non-hidden form control has an explicit programmatic label using a visible `label[for]` or a valid `aria-labelledby` reference;
- every button has an accessible name;
- no positive `tabindex`; DOM order should be the intended keyboard order;
- no non-native pointer-only action;
- every `aria-labelledby` and `aria-describedby` reference resolves;
- at least one status/error announcement region using `role="status"`, `role="alert"`, or a valid `aria-live` value;
- status and validation information is text, not color/position/icon-only;
- no secret is prefilled into markup or embedded in client-visible source.

These checks are prerequisites only. They cannot prove runtime focus behavior, focus restoration, keyboard traps, NVDA speech output, browse/focus mode behavior, or actual live-region announcements.

## Human keyboard/NVDA execution protocol

Run this protocol only after the exact audited deployed SHA is known, the Passenger application runtime is verified, the intended setup/operator surface is live, and the relevant safety gate permits the test.

Use the exact deployed release. Start NVDA normally. Do not record private Telegram content or credentials in evidence.

1. Start at the top of the document and identify the page heading and main landmark.
2. Press Tab repeatedly through every interactive control. Record only whether focus order is logical; do not record field values.
3. Press Shift+Tab back through the same controls. Confirm no trap, inaccessible control or unexpected focus loss.
4. At every control, verify NVDA speaks a usable name, role and state where applicable.
5. Activate each non-consequential setup/operator control using the keyboard only. Do not use the mouse as a fallback.
6. Trigger one validation error using non-secret test input. Confirm the error is available as text and is announced without unexplained focus loss.
7. Correct the test input and confirm the UI recovers by keyboard alone.
8. Trigger one safe state/status change and verify NVDA announces the status at the relevant time.
9. Repeat the essential path using NVDA browse mode and focus mode where applicable.
10. For C1, verify the entire allowed one-time setup interaction can be completed with keyboard/NVDA when the authorization gate is legitimately REQUIRED.
11. Record only privacy-safe result codes, booleans, counts and exact release SHA. Do not record spoken transcripts, phone numbers, codes, chat names, person names, message text, filenames, server paths, tokens or session material.

A structural green result may set `structural_ready=true`; it must keep `human_nvda_pass=false` until the human protocol above is actually executed and independently accepted.

## Human evidence schema

`validate_human_accessibility_evidence()` accepts only the following bounded fields:

- criterion: C1, I1, I4 or I6;
- exact candidate SHA-40;
- status: PASS, FAIL or BLOCKED;
- step count;
- finding count;
- keyboard-only verified boolean;
- spoken name/role/state verified boolean;
- focus-order verified boolean;
- status-announcement verified boolean;
- no-private-content-recorded boolean.

Free-form details, transcripts and arbitrary nested evidence are intentionally rejected. A PASS is rejected unless the criterion-specific human fact is true and `no_private_content_recorded=true`.

## Private one-time Telegram authorization protocol

While authorization state is NOT_YET_REQUIRED, every stage below is planning-only and no user credential input is requested.

When the authoritative state becomes REQUIRED, the one-time sequence is:

1. Open the authenticated private one-time setup surface.
2. Enter the phone number only in that private surface.
3. Request the Telegram login code.
4. Enter the code only in the private surface.
5. Enter 2FA only if Telegram explicitly requires it.
6. Verify that the authorized session is persisted in private server-side storage outside the public release payload.
7. Rotate or disable the one-time setup gate according to the approved setup design.
8. Restart/reload through the approved production lifecycle and verify the session survives.

Public evidence records only status/reason codes and safe booleans/counts. It never records the entered values.

## ChatGPT Action deployed E2E protocol

Do not execute until the deployed Action gate is open.

Read-only first:

- prove the deployed OpenAPI schema is the schema for the exact audited deployed release;
- prove bearer protection on every private Action operation;
- connect the Action in read-only mode;
- run a harmless authenticated read and verify a useful structured response;
- run missing/wrong-auth negatives and verify no private content leaks;
- verify structured errors and bounded retry metadata;
- verify no private setup/session/login routes exist in the Action schema.

Only after read-only E2E is accepted should write preview paths be exercised. Preview must create zero Telegram side effects. Commit testing remains separately gated.

## K1-K5 final user scenario protocol

All plans are non-self-executing. They require the exact audited deployed SHA, verified Passenger runtime, private API auth readiness and an authorized Telegram session.

### K1 — list chats

Use the deployed Action/read route to request the dialog list. Verify correct bounded results and no unauthorized leak. Expected external write effects: 0.

### K2 — recent messages from a person

Select a safe known query without putting the person's name into public evidence. Use the deployed search/history flow and verify the returned result set privately. Public evidence uses counts/hashes only. Expected external write effects: 0.

### K3 — files from chat/date window

Use a controlled safe window, list media, download the selected material through private file handling and build the ZIP. Verify archive integrity and private serving. Public evidence stores only counts/hashes/statuses. Expected external write effects: 0.

### K4 — draft/preview reply

Create a reply preview and verify the target privately. Confirm that preview alone performs zero Telegram writes. Do not commit. Expected external write effects: 0.

### K5 — explicit one-send scenario

K5 remains locked until every gate below is simultaneously true:

- exact audited deployed SHA known;
- Passenger runtime verified;
- private API auth ready;
- Telegram authorized;
- deployed write Action schema verified;
- Independent Auditor write approval present;
- safe destination confirmed;
- safe destination represented in public evidence only by a SHA-256 binding, not by the destination name/ID;
- fresh explicit user commit for this exact test;
- idempotency/duplicate-protection state ready.

Then, and only then, the approved operator executes exactly one test commit. Verify one external effect. Replay the exact commit/idempotency request only as approved and verify no second external effect. If outcome is ambiguous, do not blind-resend; follow reconciliation policy.

DEV10 protocol code returns `execute_now=false` even when every prerequisite is present. The protocol layer itself never sends a message.

## Safe destination protocol

A K5 destination must be selected before the fresh user commit and accepted by the Independent Auditor. The destination must be intentionally safe for a one-message test, and the test message must be non-sensitive and clearly recognizable as a controlled bridge test.

Never place the destination name, username, phone number, chat title or Telegram identifier in public evidence. Public evidence may bind the reviewed destination by a SHA-256 only. Confirmation of a safe destination without a valid hash-only binding fails closed.

## Operator/bootstrap model

Normal operation must not require recurring cPanel work by the user. The target mode is `ONE_TIME_SUPPORT_MANAGED_BOOTSTRAP`:

- one-time HOSTiQ/server-side setup where needed;
- exact approved release identity;
- backup before production mutation;
- preserve private runtime configuration and Telegram session storage;
- use the correct Python 3.11 application environment;
- gated Passenger restart/reload;
- post-change health and safe auth smoke;
- automatic/immediate rollback on failed mandatory checks;
- record deployed SHA and privacy-safe outcome evidence.

After bootstrap, approved releases should use the audited noninteractive deployment path. The user should not routinely edit server files, paste commands, move code, or operate cPanel.

## Recovery instructions

If setup, restart, Action E2E or a live acceptance step fails:

1. Stop the current acceptance sequence; do not improvise a write retry.
2. Preserve private session/config/state and do not copy it into GitHub/Drive/chat.
3. Record only bounded failure code/count/hash evidence.
4. If the failure followed a production change, invoke the approved rollback path and verify health/running identity.
5. If Telegram write outcome is ambiguous, require reconciliation; never blindly resend.
6. After recovery, re-establish exact deployed SHA, runtime identity, auth state and session persistence before resuming the live protocol.
7. A failed human NVDA run remains FAIL/BLOCKED until repeated against the exact corrected deployed release; source-only remediation is not a human PASS.

## Current DEV10 execution boundary

At the time this protocol was introduced, canonical production promotion remained blocked and `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remained authoritative. Therefore DEV10 executes source/protocol tests only. No Telegram credential request, production mutation, Passenger restart, deployed Action invocation or live Telegram write is part of this branch.
