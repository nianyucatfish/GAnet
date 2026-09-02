"""Discovery record for the movable GAnet component."""
from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from . import paths

_SCHEMA_VERSION = 1
_STATE_ROOT = Path.home() / ".genericagent" / "ganet"
_LOCATION_PATH = _STATE_ROOT / "component.json"
# Both launchers ship in every checkout; the one the current desktop runs is
# what the discovery record advertises.
_LAUNCHER_NAMES = ("ganet.cmd", "ganet.sh")


def launcher_name() -> str:
    return "ganet.cmd" if sys.platform == "win32" else "ganet.sh"


def location_path() -> Path:
    return _LOCATION_PATH


def _resolved(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser().resolve()


def _git_commit(component_root: Path) -> str | None:
    """Best-effort HEAD commit of the checkout, without invoking git."""
    git_dir = component_root / ".git"
    try:
        head = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head[:12] or None
    ref = head[5:].strip()
    with contextlib.suppress(OSError):
        return (git_dir / Path(*ref.split("/"))).read_text(encoding="utf-8").strip()[:12] or None
    with contextlib.suppress(OSError):
        for line in (git_dir / "packed-refs").read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[1] == ref:
                return parts[0][:12]
    return None


def inspect_component(root: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Validate the git-source component layout at ``root``.

    The official component is a git checkout of the GAnet repository running
    under the bound GenericAgent Python; there is no bundled runtime.
    """
    component_root = _resolved(root or paths.package_root())
    launcher = component_root / launcher_name()
    required = {
        **{name: component_root / name for name in _LAUNCHER_NAMES},
        "pyproject.toml": component_root / "pyproject.toml",
        "ganet/__init__.py": component_root / "ganet" / "__init__.py",
    }
    missing = [name for name, path in required.items() if not path.is_file()]
    result: dict[str, Any] = {
        "ok": not missing,
        "schema": _SCHEMA_VERSION,
        "packageRoot": str(component_root),
        "launcher": str(launcher),
        "layout": "source",
        "git": (component_root / ".git").exists(),
        "commit": _git_commit(component_root),
    }
    if missing:
        result["status"] = "incomplete"
        result["missing"] = missing
    else:
        result["status"] = "ready"
    return result


def load_location() -> dict[str, Any] | None:
    try:
        value = json.loads(location_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict) or value.get("schema") != _SCHEMA_VERSION:
        return None
    return value


def record_component(result: dict[str, Any]) -> Path:
    if result.get("ok") is not True or result.get("layout") != "source":
        raise ValueError("只能登记完整的 GAnet 组件")
    record = {
        "schema": _SCHEMA_VERSION,
        "package_root": result["packageRoot"],
        "launcher": result["launcher"],
        "commit": result["commit"],
        "updated_at": int(time.time()),
    }
    destination = location_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, indent=2) + "\n")
        with contextlib.suppress(OSError):
            os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
    return destination


def refresh_location() -> dict[str, Any]:
    result = inspect_component()
    if result.get("ok"):
        if sys.platform != "win32":
            # A checkout copied without mode bits would leave the launcher inert.
            for name in ("ganet.sh", "ganet.command"):
                with contextlib.suppress(OSError):
                    path = Path(result["packageRoot"]) / name
                    path.chmod(path.stat().st_mode | 0o111)
        record_component(result)
    return result
