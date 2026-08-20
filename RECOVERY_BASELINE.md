# Recovery baseline candidate

Status: **DO NOT MERGE / DO NOT DEPLOY until HOSTiQ production baseline is verified.**

This branch starts from the sanitized legacy v1.1 reference package. It is not asserted to be the current production source of truth. HOSTiQ support previously changed the live Python application after an HTTP 500 incident, and the exact server-side diff has not yet been recovered.

The purpose of this branch is to make the legacy candidate auditable while preserving production:

- remove private/runtime artifacts and a leaked legacy setup-route reference;
- add CI, secret scanning, security regression tests and OpenAPI checks;
- harden audit redaction and FloodWait handling;
- provide a deterministic recovery request for HOSTiQ support.

No production deployment is authorized from this branch. Merge into `main` requires independent audit and evidence that the candidate has been reconciled with the actual HOSTiQ production baseline.
