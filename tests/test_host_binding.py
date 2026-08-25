from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from ganet.device_access import host_adapter
from ganet.device_connection import network


TOOL_NAMES = (
    "code_run",
    "file_read",
    "file_patch",
    "file_write",
    "web_scan",
    "web_execute_js",
)


def _write_fake_ga(root: Path) -> None:
    (root / "assets").mkdir(parents=True)
    (root / "agent_loop.py").write_text(
        "class BaseHandler:\n"
        "    def __init__(self, parent, cwd=None): self.cwd = cwd\n"
        "    def dispatch(self, name, args, response):\n"
        "        yield 'running'\n"
        "        return type('Outcome', (), {'data': {'tool': name, 'cwd': self.cwd}})()\n"
        "def exhaust(value):\n"
        "    try:\n"
        "        while True: next(value)\n"
        "    except StopIteration as exc: return exc.value\n",
        encoding="utf-8",
    )
    (root / "TMWebDriver.py").write_text("class TMWebDriver: pass\n", encoding="utf-8")
    methods = "\n".join(
        f"    def do_{name}(self, args, response): return None" for name in TOOL_NAMES
    )
    (root / "ga.py").write_text(
        "from agent_loop import BaseHandler\n"
        "class GenericAgentHandler(BaseHandler):\n" + methods + "\n",
        encoding="utf-8",
    )
    schemas = [
        {"type": "function", "function": {
            "name": name,
            "description": name,
            "parameters": {"type": "object", "properties": {}},
        }}
        for name in TOOL_NAMES
    ]
    (root / "assets" / "tools_schema.json").write_text(
        json.dumps(schemas), encoding="utf-8"
    )


@pytest.fixture
def isolated_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    state_root = tmp_path / "state"
    monkeypatch.setattr(network, "_RECEIPT_DIR", str(state_root))
    monkeypatch.setattr(network, "_CONFIG_PATH", str(state_root / "config.json"))
    monkeypatch.setattr(host_adapter, "_ADAPTER", None)
    monkeypatch.setattr(host_adapter, "_PROCESS_GA_ROOT", None)
    return state_root


def test_configure_host_validates_and_records_explicit_runtime(
    tmp_path: Path, isolated_state: Path
) -> None:
    ga_root = tmp_path / "GenericAgent"
    _write_fake_ga(ga_root)

    result = host_adapter.configure_host(ga_root, sys.executable)

    assert result["ok"] is True
    assert Path(result["projectRoot"]) == ga_root.resolve()
    config = network.load_config()
    assert config["host_binding"] == {
        "version": 1,
        "ga_root": str(ga_root.resolve()),
        "ga_python": str(Path(sys.executable).resolve()),
    }
    launcher = host_adapter.launcher_path()
    assert launcher.is_file()
    assert str(Path(__file__).resolve().parents[1] / "ganet" / "host_entry.py") in launcher.read_text(encoding="utf-8")
    shim = host_adapter.python_shim_path()
    encoding = "oem" if os.name == "nt" else "utf-8"
    assert str(Path(sys.executable).resolve()) in shim.read_text(encoding=encoding)


def test_configure_host_is_idempotent_for_the_same_binding(
    tmp_path: Path, isolated_state: Path
) -> None:
    ga_root = tmp_path / "GenericAgent"
    _write_fake_ga(ga_root)

    first = host_adapter.configure_host(ga_root, sys.executable)
    second = host_adapter.configure_host(ga_root, sys.executable)

    assert first["projectRoot"] == second["projectRoot"] == str(ga_root.resolve())


def test_configure_host_does_not_silently_replace_binding(
    tmp_path: Path, isolated_state: Path
) -> None:
    first, second = tmp_path / "GA-one", tmp_path / "GA-two"
    _write_fake_ga(first)
    _write_fake_ga(second)
    host_adapter.configure_host(first, sys.executable)

    with pytest.raises(RuntimeError, match="明确修复"):
        host_adapter.configure_host(second, sys.executable)

    assert network.load_config()["host_binding"]["ga_root"] == str(first.resolve())


def test_repair_explicitly_replaces_binding(
    tmp_path: Path, isolated_state: Path
) -> None:
    first, second = tmp_path / "GA-one", tmp_path / "GA-two"
    _write_fake_ga(first)
    _write_fake_ga(second)
    host_adapter.configure_host(first, sys.executable)

    result = host_adapter.configure_host(second, sys.executable, replace=True)

    assert result["projectRoot"] == str(second.resolve())
    assert network.load_config()["host_binding"]["ga_root"] == str(second.resolve())


def test_failed_repair_preserves_binding_and_launcher(
    tmp_path: Path, isolated_state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, second = tmp_path / "GA-one", tmp_path / "GA-two"
    _write_fake_ga(first)
    _write_fake_ga(second)
    host_adapter.configure_host(first, sys.executable)
    launcher = host_adapter.launcher_path()
    shim = host_adapter.python_shim_path()
    before = launcher.read_bytes()
    shim_before = shim.read_bytes()
    monkeypatch.setattr(
        host_adapter,
        "_check_launcher",
        lambda *args, **kwargs: {"ok": False, "error": "synthetic failure"},
    )

    with pytest.raises(RuntimeError, match="synthetic failure"):
        host_adapter.configure_host(second, sys.executable, replace=True)

    assert network.load_config()["host_binding"]["ga_root"] == str(first.resolve())
    assert launcher.read_bytes() == before
    assert shim.read_bytes() == shim_before


def test_refresh_launcher_tracks_component_location_without_rebinding(
    tmp_path: Path, isolated_state: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ga_root = tmp_path / "GenericAgent"
    _write_fake_ga(ga_root)
    host_adapter.configure_host(ga_root, sys.executable)
    moved_entry = tmp_path / "moved" / "ganet" / "host_entry.py"
    moved_entry.parent.mkdir(parents=True)
    moved_entry.write_text("", encoding="utf-8")
    monkeypatch.setattr(host_adapter.paths, "package_entry", lambda: moved_entry)

    host_adapter.refresh_launcher()

    content = host_adapter.launcher_path().read_text(encoding="utf-8")
    assert str(moved_entry) in content
    assert network.load_config()["host_binding"]["ga_root"] == str(ga_root.resolve())


def test_invalid_binding_fails_closed_without_rewriting_state(
    tmp_path: Path, isolated_state: Path
) -> None:
    missing = tmp_path / "missing-ga"
    network.save_config(host_binding={
        "version": 1,
        "ga_root": str(missing),
        "ga_python": sys.executable,
    })
    before = Path(network._CONFIG_PATH).read_text(encoding="utf-8")

    status = host_adapter.validate_binding()

    assert status["ok"] is False
    assert status["status"] == "unavailable"
    assert Path(network._CONFIG_PATH).read_text(encoding="utf-8") == before
