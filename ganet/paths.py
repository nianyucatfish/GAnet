"""Filesystem locations owned by the movable GAnet installation."""
from __future__ import annotations

from pathlib import Path


def package_root() -> Path:
    """Return the directory containing the movable GAnet package."""
    return Path(__file__).resolve().parent.parent


def package_entry() -> Path:
    return Path(__file__).resolve().parent / "host_entry.py"
