"""GAnet desktop user center and device interconnect component."""
from __future__ import annotations

__version__ = "0.1.1"
__all__ = ["open_user_center", "register_auth_lifecycle"]

def register_auth_lifecycle() -> None:
    from .device_connection import register_auth_lifecycle as register
    register()

def open_user_center() -> str:
    register_auth_lifecycle()
    from .device_connection import open_user_center as open_center
    return open_center()
