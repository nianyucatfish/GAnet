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

from . import __version__, paths

_SCHEMA_VERSION = 1
_STATE_ROOT = Path.home() / ".genericagent" / "ganet"
_LOCATION_PATH = _STATE_ROOT / "component.json"


def location_path() -> Path:
    return _LOCATION_PATH


def default_install_root() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local).expanduser() / "GenericAgent" / "GAnet" / "Component"
    return Path.home() / ".local" / "share" / "GenericAgent" / "GAnet" / "Component"


def _resolved(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser().resolve()


def inspect_component(
    root: str | os.PathLike[str] | None = None,
    python_executable: str | os.PathLike[str] | None = None,
) -> dict[str, Any]:
    component_root = _resolved(root or paths.package_root())
    launcher = component_root / "ganet.cmd"
    bundled_python = component_root / "runtime" / "python" / "python.exe"
    bundled_package = component_root / "runtime" / "site-packages" / "ganet" / "__init__.py"
    source_package = component_root / "ganet" / "__init__.py"
    bundled = bundled_python.is_file() and bundled_package.is_file()
    development = (component_root / "pyproject.toml").is_file() and source_package.is_file()
    missing = []
    if not launcher.is_file():
        missing.append("ganet.cmd")
    if not bundled and not development:
        missing.extend(("runtime/python/python.exe", "runtime/site-packages/ganet/__init__.py"))
    expected_python = bundled_python if bundled else _resolved(python_executable or sys.executable)
    result: dict[str, Any] = {
        "ok": not missing,
        "schema": _SCHEMA_VERSION,
        "version": __version__,
        "packageRoot": str(component_root),
        "launcher": str(launcher),
        "pythonExecutable": str(expected_python),
        "layout": "bundled" if bundled else "source",
        "defaultInstallRoot": str(default_install_root().resolve()),
    }
    if missing:
        result["status"] = "incomplete"
        result["missing"] = missing
        return result

    actual_python = _resolved(python_executable or sys.executable)
    if bundled and os.path.normcase(str(actual_python)) != os.path.normcase(str(bundled_python.resolve())):
        result["ok"] = False
        result["status"] = "wrong_runtime"
        result["error"] = "GAnet 未使用组件自带 Python 运行"
        return result
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
    if result.get("ok") is not True or result.get("layout") != "bundled":
        raise ValueError("只能登记完整的正式 GAnet 组件")
    record = {
        "schema": _SCHEMA_VERSION,
        "package_root": result["packageRoot"],
        "launcher": result["launcher"],
        "version": result["version"],
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
    if result.get("ok") and result.get("layout") == "bundled":
        record_component(result)
    return result
