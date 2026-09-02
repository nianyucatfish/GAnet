"""Where the GAnet network component lives on each desktop platform.

The Go sidecar resolves its own data root as ``%LOCALAPPDATA%`` on Windows and
``os.UserConfigDir()`` elsewhere; the Python side must land on the very same
directory or the two halves stop seeing each other's state and host key.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

LAUNCHD_LABEL = "ai.gaagent.ganet-sidecar"


def is_windows() -> bool:
    return sys.platform == "win32"


def is_macos() -> bool:
    return sys.platform == "darwin"


def executable_name() -> str:
    return "ganet-sidecar.exe" if is_windows() else "ganet-sidecar"


def default_root() -> Path:
    if is_windows():
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return Path(base) / "GenericAgent" / "GAnet"
    if is_macos():
        # Mirrors Go's os.UserConfigDir() on darwin.
        return Path.home() / "Library" / "Application Support" / "GenericAgent" / "GAnet"
    xdg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(xdg) / "GenericAgent" / "GAnet"


def sidecar_root() -> Path:
    configured = os.environ.get("GANET_SIDECAR_DIR")
    return Path(configured) if configured else default_root()


def sidecar_executable() -> Path:
    configured = os.environ.get("GANET_SIDECAR_EXE")
    return Path(configured) if configured else sidecar_root() / executable_name()


def launchd_agent_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / (LAUNCHD_LABEL + ".plist")


def launchd_service_target() -> str:
    return f"gui/{os.getuid()}/{LAUNCHD_LABEL}"


def posix_terminate(pid: int, *, grace: float = 10.0) -> None:
    """SIGTERM, wait for exit, then SIGKILL as a last resort.

    Signal numbers are spelled out so the module also imports on Windows,
    where ``signal`` lacks SIGKILL; the function itself is POSIX-only.
    """
    import time
    for sig, wait in ((15, grace), (9, 3.0)):
        try:
            os.kill(pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError):
                return
            time.sleep(0.2)
