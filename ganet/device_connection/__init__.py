"""Trusted device connection: account, network, pairing, and user-center UI."""

from typing import Any

__all__ = ["open_user_center", "register_auth_lifecycle"]


def __getattr__(name: str) -> Any:
    """Avoid importing network before its ``python -m`` entry point runs."""
    if name == "open_user_center":
        from .user_center import open_user_center
        return open_user_center
    if name == "register_auth_lifecycle":
        from .pairing import register_auth_lifecycle
        return register_auth_lifecycle
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
