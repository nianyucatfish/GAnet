"""Filesystem locations owned by the movable GAnet installation."""
from __future__ import annotations

import os
from pathlib import Path


def package_root() -> Path:
    """Return the root of the GAnet source checkout."""
    configured = os.environ.get("GANET_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parent.parent


def package_entry() -> Path:
    return Path(__file__).resolve().parent / "host_entry.py"
