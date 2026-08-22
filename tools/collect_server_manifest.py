# -*- coding: utf-8 -*-
"""One-command hash-only HOSTiQ live-source manifest collector.

No secret values or source text are accepted/printed. Output is an owner-private
JSON file for later strict reconciliation and public-safe summarization.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ops.release_guard import SafetyError, write_json_atomic
from ops.server_manifest import collect_server_manifest


def main() -> int:
    app_root = ROOT
    out_dir = Path.home() / ".telegram_bridge_private_evidence"
    out = out_dir / "server_manifest.json"
    try:
        out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(out_dir, 0o700)
        payload = collect_server_manifest(app_root)
        write_json_atomic(out, payload, mode=0o600)
        os.chmod(out, 0o600)
        # Validate we can parse what was atomically written without emitting it.
        check = json.loads(out.read_text(encoding="utf-8"))
        if check != payload:
            raise SafetyError("server manifest write verification failed")
    except (OSError, UnicodeError, json.JSONDecodeError, SafetyError) as exc:
        print("SERVER_MANIFEST_BLOCKED:" + type(exc).__name__)
        return 2
    print("SERVER_MANIFEST_PRIVATE_REPORT_WRITTEN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
