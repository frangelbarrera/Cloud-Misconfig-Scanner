#!/usr/bin/env python3
"""Legacy CLI entry point.

The actual CLI implementation lives in :mod:`cms.cli` so that the same
code is exposed via ``python cms.py`` and the ``cloud-misconfig-scanner``
console script declared in ``pyproject.toml``.
"""
from __future__ import annotations

import sys

from cms.cli import main

if __name__ == "__main__":
    sys.exit(main())
