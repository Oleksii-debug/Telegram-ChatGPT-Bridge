# DEV3 Round 2 — read-side hardening and integration contract

This document describes candidate code in `work/application-read-media`. It is not proof of HOSTiQ deployment, Telegram authorization, or product acceptance.

## Canonical route source

`bridge/routes.py` is the read application route registry. It classifies routes independently from OpenAPI annotations so schema validators do not have to trust optional self-declared markers.

The only public route is `GET /health`. Dialog, history, search, media, download, resume, archive and file-metadata operations are protected reads. File-content download is `protected_or_signed`; a valid signed reference is still subject to the injected rate-limiter.

Unknown routes and protected wrong-method requests fail closed. The registry exposes a deterministic non-secret snapshot intended for later DEV4/DEV5 OpenAPI comparison after independent integration review.

## Request parsing

The WSGI JSON boundary enforces Content-Type, Content-Length, total byte limit, strict UTF-8, object shape, duplicate-key rejection, bounded nesting and bounded aggregate JSON nodes. Integer fields accept JSON integers only; booleans, floats and numeric strings are not coerced. Lone surrogate code points in request text are rejected.

These controls execute after authentication/rate limiting on protected POST routes so malformed bodies do not become an unauthenticated parsing oracle or bypass abuse limits.

## Telethon lifecycle

`TelethonReadBackend` remains lazy: constructing/importing it performs no Telegram network activity. For clients that expose lifecycle hooks, every read operation performs:

1. client factory;
2. `connect()`;
3. `is_user_authorized()` check;
4. bounded operation;
5. `disconnect()` in `finally` on success, controlled error, authorization failure, cancellation or timeout.

Clients without lifecycle hooks remain supported as externally managed deterministic fakes. Raw backend exception text is never copied into the public error object. FloodWait remains a bounded structured 429 with retry hint.

Partial Telethon file metadata is fail-soft: absent or malformed optional name/MIME/size/duration/dimensions become `null` rather than producing `TypeError` or the literal string `"None"`. Stable logical media references remain deterministic across process restarts.

## Checkpoints and concurrency

Download checkpoints are integrity-hashed and now validate embedded job identity, schema, item identifiers, opaque source refs, result refs, failure shapes and terminal completeness. A DB row whose embedded job ID does not match the lookup key fails closed even when an attacker recomputes the payload hash.

`DownloadManager` serializes one job with a private POSIX `flock` file keyed by SHA-256(job ID), so the same job cannot be resumed concurrently by separate workers on the same host. Lock paths carry no raw job ID and require owner, regular-file, single-link, mode-0600 and empty-file topology. Different jobs use independent locks.

A `complete` checkpoint whose registered result file is missing/corrupt is an explicit integrity failure, never a silently shorter success. Actual-size bulk overflow deletes the newly rejected file record as well as its private file instead of leaving a dead public reference row.

Backend-returned download paths are lstat-checked before resolution; symlink, hardlink, non-regular and out-of-staging paths fail closed.

## Evidence boundary

All tests use synthetic objects/files and dummy injected material only. No Telegram API credential, session, login code, 2FA value, bearer value, setup route, private message/media, HOSTiQ credential or production file is required or permitted in repository evidence.

Real Passenger identity, live source reconciliation, deployed SHA, restart/smoke/rollback, Telegram read E2E and ChatGPT/OpenAPI E2E remain external evidence gates. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged until the Auditor moves that gate.
