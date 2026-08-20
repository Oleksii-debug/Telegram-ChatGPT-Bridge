# -*- coding: utf-8 -*-
"""Compatibility entrypoint: audited round-7 core plus round-8 deployment hardening."""
from __future__ import annotations

import sys

from ops import deploy_release_legacy as _core
from ops.deployment_hardening import install as _install

_install(_core)

if __name__ == "__main__":
    raise SystemExit(_core.main())

sys.modules[__name__] = _core
