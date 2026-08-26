# Outbound Network Boundary — FINALWAVE-48

## Scope

This document records the source-level outbound HTTP/URL trust boundary for the
Telegram ChatGPT Bridge. It is not production evidence and does not authorize a
deploy, Passenger restart, Telegram authorization, live Telegram read/write, or
K5.

## Canonical Action boundary

The public ChatGPT Action request schemas do not accept an arbitrary outbound
URL/URI/host/endpoint for any operation. `SEND_FILES` accepts only opaque Bridge
file references with an expected SHA-256 and size. The unified WSGI runtime also
rejects unknown fields both at the top-level send-files request and inside every
file reference.

Therefore a caller cannot turn `SEND_FILES` into a server-side fetch request.

The historical `ops.file_send_policy` external-HTTPS helpers were validation
helpers, not an address-bound fetch transport. Treating a separate DNS
resolution result as sufficient SSRF protection would be incorrect because the
address used by the later connection could differ (DNS rebinding / TOCTOU).
External URL file ingestion is now fail-closed. The compatibility functions
remain only so stale callers fail deterministically with
`external_url_sources_disabled`; the module contains no HTTP client, resolver,
or redirect follower.

Any future remote-URL ingestion feature requires a separate security design and
independent audit. At minimum the transport would need to bind the verified
address to the actual connection, preserve TLS hostname verification, disable
redirects by default, cap response bytes, apply explicit deadlines, and define
its DNS/rebinding assumptions without calling a resolve-then-connect check
"DNS pinning".

## Passenger challenged health probe

The intentional HTTP probe is constrained to:

- scheme: HTTPS;
- host: `tg-api.rukadopomogy.org.ua`;
- path: `/health`;
- port: omitted or explicit `443`, normalized to the canonical no-port URL;
- userinfo: forbidden;
- query: forbidden;
- fragment: forbidden;
- IP literals: forbidden by exact-host matching;
- trailing-dot and lookalike/punycode hosts: forbidden by exact-host matching;
- host case variants: rejected so the accepted textual authority is canonical;
- redirects: disabled for same-origin and cross-origin responses;
- ambient HTTP/HTTPS proxy routing: disabled for the evidence request;
- response body: at most 32 KiB;
- configured connect/read timeout: at most 20 seconds;
- response reading: chunked with a total post-connect/read deadline and the
  underlying urllib socket timeout reduced to the remaining deadline when that
  socket is available.

The raw evidence challenge is sent only to that canonical request and is not
returned in `ProbeResult`.

## DNS trust model

No DNS pinning claim is made.

The Passenger hostname is a code constant rather than user input, which removes
the ordinary arbitrary-target SSRF primitive. DNS resolution and TLS certificate
validation still rely on the host operating system resolver and public PKI.
Python's configured socket timeout is not represented as a cryptographic or
hard real-time guarantee for every possible resolver implementation.

A compromise of authoritative DNS, the local resolver, host trust store, or
equivalent infrastructure is outside this source-level SSRF claim and must not
be hidden behind a "public IP was pre-resolved" assertion.

## Evidence expectations

Regression coverage must include:

- public/private IP literals;
- hostname case variants;
- trailing-dot hosts;
- punycode/lookalike hosts;
- userinfo/query/fragment/alternate port/path;
- same-origin and cross-origin redirects;
- slow/drip response deadline behavior;
- oversized response bodies;
- absence of arbitrary URL-shaped Action fields;
- runtime rejection of URL fields in send-files payloads;
- explicit `NO_DNS_PINNING` trust-model declaration.
