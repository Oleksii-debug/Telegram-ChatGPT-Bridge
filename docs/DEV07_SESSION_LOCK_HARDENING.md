# DEV07 Telegram session-lock topology hardening

Status: isolated security candidate. This document contains no credential/session value and does not authorize merge, deploy, Passenger restart, Telegram authorization, or live Telegram action.

## Finding

The canonical `TelegramSessionLock` validated `lock_path.parent` through a pathname `stat()` and then opened the lock leaf again through the complete pathname. `O_NOFOLLOW` on the leaf does not protect preceding directory components. A symlinked parent or a parent replacement between validation and leaf open could therefore redirect or split the lock namespace even though the final lock file itself passed regular-file, owner, link-count, size and mode checks.

## Hardening

The DEV07 candidate now:

- requires POSIX `O_DIRECTORY` and `O_NOFOLLOW` primitives;
- converts the configured lock path to a lexical absolute path without resolving symlinks;
- walks every parent component descriptor-relatively from `/`, rejecting symlink/non-directory components and binding each pathname observation to the opened directory inode;
- creates only the final private parent directory when missing, rather than recursively traversing/creating unknown missing ancestors;
- requires the final parent to be current-EUID owned, non-group/world-accessible, owner-writable and owner-searchable;
- opens the lock leaf relative to the validated parent descriptor with `O_NOFOLLOW`;
- preserves the inherited empty, regular, current-owner, single-link, exact-`0600` lock requirements and bounded `flock` timeout semantics;
- after obtaining the flock, reopens the public parent path through the same no-symlink walk and requires the same device/inode;
- also requires the named leaf inside the bound parent descriptor still to identify the exact inode held by the lock descriptor.

This closes the validation-to-open parent redirection and detects parent/leaf replacement races around acquisition. It does not claim that an unprivileged file lock can prevent a malicious same-UID process from renaming filesystem objects after all checks; the deployment/runtime trust model still requires owner-private state with no hostile same-account process.

## Adversarial tests

`tests/test_dev07_session_lock_security.py` covers:

- direct symlink parent rejection without creating a lock in the target;
- symlink ancestor rejection even when the final target parent is private;
- deterministic parent replacement between parent validation and leaf open;
- deterministic leaf replacement immediately around flock acquisition;
- preserved normal mutual exclusion and reacquisition.

The specialist Recovery Guard runs these tests before canonical provenance together with the inherited DEV4 session-lock suite.

## Truth boundary

This is source/synthetic security evidence only. It does not inspect or expose a Telegram session, does not prove live HOSTiQ private-directory permissions, and does not authorize Telegram authentication. `USER_TELEGRAM_AUTH_NOT_YET_REQUIRED` remains unchanged.
