# FINALWAVE-45 Unicode / Filename Correctness

Status: isolated specialist candidate. No merge, deploy, Passenger restart, Telegram authorization, live Telegram read/write, K5, or production PASS is authorized by this document.

Source parent at lane creation: `84691967e5363bc4b88dfae97371d7bf329c105d` (then-live PR #9 head).
Branch: `finalwave26/45-unicode-filenames`.
Canonical target: `work3/integration-release-candidate` through independent semantic integration only.

## Failure modes reproduced

1. `bridge.archive.unique_name()` could hang indefinitely when two archive members had the same already-maximum-length name. Appending ` (2)` and then running the old truncation removed the marker, recreated the original collision key, and repeated forever.
2. `bridge.filenames.safe_filename()` accepted lone surrogate code points. ZIP member encoding and JSON UTF-8 encoding could then raise an uncontrolled `UnicodeEncodeError`.
3. The prior collision key covered NFC + casefold but not compatibility-equivalent width forms.
4. Windows reservation checks did not cover compatibility-equivalent device spellings such as fullwidth `CON` or superscript-digit `COM`/`LPT` forms.
5. A 180-code-point filename could greatly exceed a common 255-byte POSIX component limit when it contained Cyrillic or emoji, creating a ZIP that could be valid as metadata but fail on ordinary extraction.
6. JSON media names and the send-files external display-name policy did not consume one shared filename namespace.

## Filename invariants

`bridge.filenames.safe_filename()` is a filename/display/archive policy only. It must never be applied to message bodies.

The output is:

- NFC-normalized for display stability;
- one basename component, with actual traversal components discarded at archive/display boundaries;
- free of lone surrogates and ASCII/C1 controls;
- free of bidi override/isolate controls and selected invisible filename controls;
- free of slash/backslash lookalikes enumerated by the policy;
- Windows-device-safe, including compatibility-equivalent device stems;
- no more than 180 Unicode code points;
- no more than 240 strict UTF-8 bytes, leaving extraction/collision headroom;
- extension-preserving when the suffix itself is within the bounded suffix policy.

ZWJ and ZWNJ are deliberately preserved because they are legitimate components of emoji and script grapheme sequences. General Latin/Cyrillic homoglyph folding is deliberately not performed: doing that would corrupt legitimate Cyrillic filenames. Security normalization is limited to path/control/device compatibility and collision identity.

## Collision identity

Archive member collision identity uses NFKC + casefold + NFKC-equivalent semantics. This intentionally treats these pairs as the same collision namespace even though their display spellings may differ:

- `A.txt` / `a.TXT`;
- composed / decomposed canonical Unicode equivalents;
- width/compatibility forms such as fullwidth `Ａ.txt` / ASCII `a.txt`.

`disambiguated_filename()` reserves the ` (N)` marker inside both the character and UTF-8 byte budgets. `unique_name()` is bounded by the finite size of the used-key set and fails closed with `zip_member_collision` rather than using an unbounded loop.

## JSON / media / message-text rule

`MediaRecord.to_dict()` sanitizes only the media filename at the outward JSON boundary. The internal record may retain backend identity needed for matching. `MessageRecord.text` is returned unchanged. Search continues to use the established NFKC/casefold comparison path while returning the original matched text.

Invalid surrogate search input remains a controlled request-validation error rather than being rewritten into a different search.

## Send-files rule

The external send-files policy still rejects genuine `/` and `\\` path input and invalid surrogate input. After that fail-closed validation it uses the shared filename policy for NFC, Windows device handling, separator lookalikes, trailing-dot/space semantics, and the portable byte bound.

## Adversarial coverage

`tests/test_finalwave45_unicode_filenames.py` covers:

- casefold, NFC/NFD, width compatibility;
- Cyrillic and emoji, including a ZWJ sequence;
- lone surrogates and C1/bidi/invisible controls;
- actual and lookalike separators;
- Windows reserved compatibility forms;
- trailing dot/space behavior;
- 240-byte portable extraction bound;
- 200 same-name collision allocations at the original 180-character failure boundary;
- ZIP validity/CRC and compatibility collisions;
- duplicate file-reference dedupe;
- interrupted-build cleanup;
- deterministic restart reallocation;
- concurrent independent ZIP builds;
- media JSON safety while message text remains unchanged;
- established search normalization plus controlled surrogate rejection;
- external send-file filename alignment.

## Cross-lane integration warning

This specialist branch started from the exact canonical parent requested by FINALWAVE-45. It must not overwrite newer specialist work.

At review time:

- DEV04 PR #50 contains newer archive/download crash-recovery and TOCTOU work but still has the old filename collision allocator. Integrate the FINALWAVE filename policy and bounded collision allocation into the selected DEV04 source rather than replacing DEV04 wholesale with this branch's `bridge/archive.py`.
- DEV05 PR #39 contains newer exactly-once/write-safety work but still has the old standalone `ops/file_send_policy.safe_filename()`. Apply the small shared-policy alignment to the selected DEV05 source without dropping its newer write logic.

After semantic integration, rerun the relevant DEV03 search, DEV04 media/archive/storage, DEV05 write/send-files, read-app/API, current-tree secret, full-history secret, and canonical provenance suites on the exact integrated SHA.

## Explicit non-claims

This lane does not close the unrelated canonical DEV08 recovery regression observed in Recovery Guard #529. It does not prove HOSTiQ runtime, production deployment identity, real Telegram behavior, ChatGPT end-to-end behavior, or K1-K5. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains authoritative unless fresh governance changes it.
