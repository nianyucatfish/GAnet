"""Filesystem locations owned by the movable GAnet installation."""
from __future__ import annotations

import os
from pathlib import Path


def package_root() -> Path:
    """Return the component root in source and bundled-runtime layouts."""
    configured = os.environ.get("GANET_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    package = Path(__file__).resolve().parent
    if package.parent.name.casefold() == "site-packages" and package.parent.parent.name.casefold() == "runtime":
        return package.parents[2]
    return package.parent


def package_entry() -> Path:
    return Path(__file__).resolve().parent / "host_entry.py"
