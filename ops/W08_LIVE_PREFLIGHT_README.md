# W08 live preflight boundary

This file is a non-authorizing operator boundary for the exact source candidate. It does not deploy, restart Passenger, access Telegram session content, or grant deployment authority.

Required input is the exact approved candidate SHA already bound by the independent W10 source gate. The live phase must collect only hash/status facts: active release identity, application root classification, `passenger_wsgi.py` identity, Python 3.11 executable/version, dependency manifest identity, disk capacity, private backup existence, SQLite topology including WAL/SHM presence, session presence only (never session content), file permissions, deployment journal state, and health/unauthenticated rejection results.

Evidence must distinguish candidate/reference facts from real Passenger process facts. A shell invocation of Python, a test WSGI import, or an HTTP 200 alone is not Passenger proof.

The live operator must not overwrite persistent Telegram write/idempotency/AMBIGUOUS/high-water databases, must not restore stale state during rollback, and must not expose private values in public evidence.

A deployment remains blocked until the live evidence package proves exact candidate binding, candidate-specific backup, WAL-safe state preservation, real Passenger application-process identity, and a recoverable previous release.
