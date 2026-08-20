# Recovery guardrail branch

Status: **DO NOT MERGE / DO NOT DEPLOY until the actual HOSTiQ production baseline is verified and independently reconciled.**

This branch was created from the repository's initial `main` baseline. It is a guardrail-only recovery branch. It does **not** contain the legacy v1.1 application source and it is not asserted to be the current production source of truth.

HOSTiQ support previously changed or repaired the live Python application after an HTTP 500 incident, and the exact current production source/diff has not yet been recovered. The legacy v1.1 application remains outside GitHub and is reference material only; it must not be imported or deployed until the live HOSTiQ baseline is recovered, sanitized and compared.

The purpose of this PR is limited to repository recovery controls:

- strengthen ignore rules for private/runtime artifacts;
- scan both the tracked tree and full Git history for project-policy secret leakage;
- regression-test secret scanning with synthetic temporary repositories;
- pin third-party GitHub Actions to reviewed immutable commit SHAs;
- preserve an explicit no-merge/no-deploy gate;
- provide a precise HOSTiQ production-baseline and setup-gate recovery request.

Any local tests previously run against a legacy candidate are evidence about that local reference only. They are not part of this PR and do not prove current production behavior.

No production deployment is authorized from this branch. Merge into `main` requires independent audit and evidence that the actual HOSTiQ production baseline has been recovered, sanitized and reconciled.
