"""The only boundary allowed to load a bound GenericAgent runtime."""
from __future__ import annotations

import contextlib
import importlib
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

from .. import paths
from ..device_connection import network as state
from . import tools

_BINDING_VERSION = 1
_LAUNCHER_NAME = "atomic-bridge.cmd" if os.name == "nt" else "atomic-bridge"
_PYTHON_SHIM_NAME = "ga_python.cmd" if os.name == "nt" else "ga_python.sh"
_REQUIRED_FILES = (
    "ga.py",
    "agent_loop.py",
    "TMWebDriver.py",
    "assets/tools_schema.json",
)
_PROCESS_GA_ROOT: Path | None = None


def _resolved(value: str | os.PathLike[str]) -> Path:
    return Path(value).expanduser().resolve()


def _same_path(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
    try:
        return os.path.normcase(str(_resolved(left))) == os.path.normcase(str(_resolved(right)))
    except (OSError, RuntimeError, ValueError):
        return False


def _inside(path: str | os.PathLike[str], root: Path) -> bool:
    try:
        _resolved(path).relative_to(root)
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def _binding_record() -> dict[str, Any] | None:
    config = state.load_config() or {}
    value = config.get("host_binding")
    return value if isinstance(value, dict) else None


def launcher_path() -> Path:
    return Path(state._RECEIPT_DIR) / _LAUNCHER_NAME


def python_shim_path() -> Path:
    """Where ganet.cmd reads the bound GenericAgent Python from."""
    return Path(state._RECEIPT_DIR) / _PYTHON_SHIM_NAME


def package_root() -> Path:
    return paths.package_root()


def configure_process_root(ga_root: str | os.PathLike[str] | None) -> None:
    global _PROCESS_GA_ROOT
    if ga_root is None:
        return
    _PROCESS_GA_ROOT = _resolved(ga_root)


def bound_ga_root() -> Path:
    if _PROCESS_GA_ROOT is not None:
        return _PROCESS_GA_ROOT
    record = _binding_record()
    if not record or record.get("version") != _BINDING_VERSION:
        raise RuntimeError("电脑工具运行环境尚未配置")
    value = record.get("ga_root")
    if not isinstance(value, str) or not value:
        raise RuntimeError("电脑工具运行环境记录无效")
    return _resolved(value)


def bound_ga_python() -> Path:
    record = _binding_record()
    value = record.get("ga_python") if record else None
    if not isinstance(value, str) or not value:
        raise RuntimeError("电脑工具 Python 尚未配置")
    return _resolved(value)


def inspect_binding() -> dict[str, Any]:
    record = _binding_record()
    if not record or record.get("version") != _BINDING_VERSION:
        return {"ok": False, "status": "missing", "error": "设备访问环境尚未配置"}
    root_value, python_value = record.get("ga_root"), record.get("ga_python")
    if not isinstance(root_value, str) or not isinstance(python_value, str):
        return {"ok": False, "status": "invalid", "error": "设备访问环境记录无效"}
    root, python = _resolved(root_value), _resolved(python_value)
    missing = [relative for relative in _REQUIRED_FILES if not (root / relative).is_file()]
    if missing:
        return {"ok": False, "status": "unavailable", "error": "GenericAgent 目录已移动或不完整"}
    if not python.is_file():
        return {"ok": False, "status": "unavailable", "error": "GenericAgent Python 已移动或不可用"}
    return {"ok": True, "status": "ready", "gaRoot": str(root), "gaPython": str(python)}


def _module_from_root(module: ModuleType, root: Path, label: str) -> Path:
    source = getattr(module, "__file__", None)
    if not source or not _inside(source, root):
        raise RuntimeError(f"{label} 未从已配置的 GenericAgent 目录加载")
    return _resolved(source)


@dataclass(frozen=True)
class GenericAgentHostAdapter:
    ga_root: Path
    ga: ModuleType
    agent_loop: ModuleType
    tm_webdriver: ModuleType
    schemas: dict[str, dict[str, Any]]

    @classmethod
    def load(cls, ga_root: str | os.PathLike[str] | None = None) -> "GenericAgentHostAdapter":
        root = _resolved(ga_root) if ga_root is not None else bound_ga_root()
        missing = [relative for relative in _REQUIRED_FILES if not (root / relative).is_file()]
        if missing:
            raise RuntimeError("GenericAgent 运行目录不完整：" + ", ".join(missing))

        root_text = str(root)
        sys.path[:] = [item for item in sys.path if not _same_path(item or Path.cwd(), root)]
        sys.path.insert(0, root_text)
        importlib.invalidate_caches()
        for name in ("ga", "agent_loop", "TMWebDriver"):
            sys.modules.pop(name, None)

        agent_loop = importlib.import_module("agent_loop")
        tm_webdriver = importlib.import_module("TMWebDriver")
        ga = importlib.import_module("ga")
        _module_from_root(agent_loop, root, "agent_loop")
        _module_from_root(tm_webdriver, root, "TMWebDriver")
        _module_from_root(ga, root, "ga")

        handler = getattr(ga, "GenericAgentHandler", None)
        missing_tools = [name for name in tools.BRIDGE_NATIVE_TOOL_NAMES
                         if not callable(getattr(handler, "do_" + name, None))]
        if missing_tools:
            raise RuntimeError("GenericAgent 电脑工具不完整：" + ", ".join(missing_tools))
        if not callable(getattr(agent_loop, "exhaust", None)):
            raise RuntimeError("GenericAgent agent_loop.exhaust 不可用")
        if not callable(getattr(tm_webdriver, "TMWebDriver", None)):
            raise RuntimeError("GenericAgent TMWebDriver 不可用")

        raw = json.loads((root / "assets" / "tools_schema.json").read_text(encoding="utf-8"))
        schemas: dict[str, dict[str, Any]] = {}
        for entry in raw:
            function = entry.get("function") if isinstance(entry, dict) else None
            if isinstance(function, dict) and function.get("name") in tools.BRIDGE_NATIVE_TOOL_NAMES:
                schemas[function["name"]] = function
        if set(schemas) != set(tools.BRIDGE_NATIVE_TOOL_NAMES):
            raise RuntimeError("GenericAgent 电脑工具 schema 不完整")
        overlap = set(tools.BRIDGE_DEVICE_TOOL_SCHEMAS) & {
            entry.get("function", {}).get("name") for entry in raw if isinstance(entry, dict)
        }
        if overlap:
            raise RuntimeError("设备互联工具不得注册到 GenericAgent 工具 schema")
        return cls(root, ga, agent_loop, tm_webdriver, schemas)

    @property
    def tool_cwd(self) -> Path:
        return self.ga_root / "temp"

    def handler(self):
        parent = SimpleNamespace(get_ctx_multiplier=lambda: 1, verbose=False)
        return self.ga.GenericAgentHandler(parent, cwd=str(self.tool_cwd))

    def exhaust(self, generator):
        return self.agent_loop.exhaust(generator)


_ADAPTER: GenericAgentHostAdapter | None = None


def current_adapter() -> GenericAgentHostAdapter:
    global _ADAPTER
    root = bound_ga_root()
    if _ADAPTER is None or not _same_path(_ADAPTER.ga_root, root):
        _ADAPTER = GenericAgentHostAdapter.load(root)
    return _ADAPTER


def _host_command(python: Path, root: Path, *arguments: str) -> list[str]:
    return [str(python), str(paths.package_entry()), "--ga-root", str(root), *arguments]


def probe_target(ga_root: str | os.PathLike[str], ga_python: str | os.PathLike[str],
                 timeout: int = 20) -> dict[str, Any]:
    root, python = _resolved(ga_root), _resolved(ga_python)
    missing = [relative for relative in _REQUIRED_FILES if not (root / relative).is_file()]
    if missing:
        return {"ok": False, "error": "GenericAgent 运行目录不完整：" + ", ".join(missing)}
    if not python.is_file():
        return {"ok": False, "error": "GenericAgent Python 不存在"}
    try:
        completed = subprocess.run(
            _host_command(python, root, "--check"), cwd=Path.home(),
            stdin=subprocess.DEVNULL, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
    except Exception as exc:
        return {"ok": False, "error": f"设备访问环境无法启动：{exc}"}
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    try:
        payload = json.loads(lines[-1]) if lines else None
    except json.JSONDecodeError:
        payload = None
    if completed.returncode or not isinstance(payload, dict) or payload.get("ok") is not True:
        error = payload.get("error") if isinstance(payload, dict) else completed.stderr.strip()
        return {"ok": False, "error": str(error or "设备访问环境验证失败")[:500]}
    if not _same_path(payload.get("pythonExecutable", ""), python):
        return {"ok": False, "error": "设备访问入口使用了其他 Python 环境"}
    if not _same_path(payload.get("projectRoot", ""), root):
        return {"ok": False, "error": "设备访问入口使用了其他 GenericAgent 目录"}
    return payload


def _launcher_content(root: Path, python: Path) -> str:
    entry = paths.package_entry()
    if os.name == "nt":
        return ("@echo off\r\n"
                f'"{python}" "{entry}" --ga-root "{root}" %*\r\n')
    return ("#!/bin/sh\n"
            f"exec {shlex.quote(str(python))} {shlex.quote(str(entry))} "
            f"--ga-root {shlex.quote(str(root))} \"$@\"\n")


def _write_launcher(root: Path, python: Path) -> Path:
    launcher = launcher_path()
    launcher.parent.mkdir(parents=True, exist_ok=True)
    temporary = launcher.with_suffix(launcher.suffix + ".tmp")
    temporary.write_text(_launcher_content(root, python), encoding="utf-8", newline="")
    if os.name != "nt":
        os.chmod(temporary, 0o700)
    os.replace(temporary, launcher)
    return launcher


def _write_python_shim(python: Path) -> Path:
    shim = python_shim_path()
    shim.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        # cmd.exe parses batch files in the OEM code page, so a non-ASCII
        # interpreter path must be written the same way for `call` to work.
        content, encoding = f'@set "GANET_PYTHON={python}"\r\n', "oem"
    else:
        content, encoding = f"GANET_PYTHON={shlex.quote(str(python))}\n", "utf-8"
    temporary = shim.with_suffix(shim.suffix + ".tmp")
    temporary.write_text(content, encoding=encoding, newline="")
    if os.name != "nt":
        os.chmod(temporary, 0o700)
    os.replace(temporary, shim)
    return shim


def refresh_launcher() -> Path | None:
    status = inspect_binding()
    if not status.get("ok"):
        return None
    _write_python_shim(_resolved(status["gaPython"]))
    return _write_launcher(_resolved(status["gaRoot"]), _resolved(status["gaPython"]))


def _restore_file(path: Path, data: bytes | None) -> None:
    if data is None:
        with contextlib.suppress(OSError):
            path.unlink()
        return
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _check_launcher(launcher: Path, root: Path, python: Path,
                    timeout: int) -> dict[str, Any]:
    command = (["cmd.exe", "/d", "/c", str(launcher), "--check"] if os.name == "nt"
               else [str(launcher), "--check"])
    try:
        completed = subprocess.run(command, cwd=Path.home(), stdin=subprocess.DEVNULL,
                                   capture_output=True, text=True, encoding="utf-8",
                                   errors="replace", timeout=timeout)
    except Exception as exc:
        return {"ok": False, "error": f"设备访问入口无法启动：{exc}"}
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    try:
        payload = json.loads(lines[-1]) if lines else None
    except json.JSONDecodeError:
        payload = None
    if completed.returncode or not isinstance(payload, dict) or payload.get("ok") is not True:
        error = payload.get("error") if isinstance(payload, dict) else completed.stderr.strip()
        return {"ok": False, "error": str(error or "设备访问入口验证失败")[:500]}
    if not _same_path(payload.get("pythonExecutable", ""), python):
        return {"ok": False, "error": "设备访问入口使用了其他 Python 环境"}
    if not _same_path(payload.get("projectRoot", ""), root):
        return {"ok": False, "error": "设备访问入口使用了其他 GenericAgent 目录"}
    return payload


def configure_host(ga_root: str | os.PathLike[str], ga_python: str | os.PathLike[str],
                   *, replace: bool = False, timeout: int = 20) -> dict[str, Any]:
    root, python = _resolved(ga_root), _resolved(ga_python)
    current = _binding_record()
    if current and current.get("version") == _BINDING_VERSION:
        same = _same_path(current.get("ga_root", ""), root) and _same_path(current.get("ga_python", ""), python)
        if not same and not replace:
            raise RuntimeError("设备访问环境已配置；只有明确修复时才能替换")

    result = probe_target(root, python, timeout=timeout)
    if not result.get("ok"):
        raise RuntimeError(str(result.get("error") or "设备访问环境验证失败"))

    launcher, shim = launcher_path(), python_shim_path()
    previous_launcher = launcher.read_bytes() if launcher.is_file() else None
    previous_shim = shim.read_bytes() if shim.is_file() else None
    try:
        _write_launcher(root, python)
        _write_python_shim(python)
        verified = _check_launcher(launcher, root, python, timeout)
        if not verified.get("ok"):
            raise RuntimeError(str(verified.get("error") or "设备访问入口验证失败"))
        record = {"version": _BINDING_VERSION, "ga_root": str(root), "ga_python": str(python)}
        state.save_config(host_binding=record)
    except Exception:
        _restore_file(launcher, previous_launcher)
        _restore_file(shim, previous_shim)
        raise
    return verified


def validate_binding(timeout: int = 20) -> dict[str, Any]:
    status = inspect_binding()
    if not status.get("ok"):
        return status
    launcher = refresh_launcher()
    if launcher is None or not launcher.is_file():
        return {"ok": False, "error": "设备访问入口不存在"}
    return _check_launcher(
        launcher, _resolved(status["gaRoot"]), _resolved(status["gaPython"]), timeout
    )
