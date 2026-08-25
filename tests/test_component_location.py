from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ganet import component_location, paths


def _write_component(root: Path) -> Path:
    (root / "runtime" / "python").mkdir(parents=True)
    (root / "runtime" / "site-packages" / "ganet").mkdir(parents=True)
    (root / "ganet.cmd").write_text("@echo off\n", encoding="utf-8")
    python = root / "runtime" / "python" / "python.exe"
    python.write_bytes(b"python")
    (root / "runtime" / "site-packages" / "ganet" / "__init__.py").write_text(
        "", encoding="utf-8"
    )
    return python


@pytest.fixture
def isolated_location(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    location = tmp_path / "state" / "component.json"
    monkeypatch.setattr(component_location, "_STATE_ROOT", location.parent)
    monkeypatch.setattr(component_location, "_LOCATION_PATH", location)
    return location


def test_inspect_bundled_component_reports_stable_identity(
    tmp_path: Path, isolated_location: Path
) -> None:
    root = tmp_path / "Component"
    python = _write_component(root)

    result = component_location.inspect_component(root, python)

    assert result["ok"] is True
    assert result["status"] == "ready"
    assert result["layout"] == "bundled"
    assert Path(result["packageRoot"]) == root.resolve()
    assert Path(result["launcher"]) == (root / "ganet.cmd").resolve()
    assert Path(result["pythonExecutable"]) == python.resolve()
    assert not isolated_location.exists()


def test_source_refresh_does_not_register_development_tree(
    tmp_path: Path, isolated_location: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "source"
    (root / "ganet").mkdir(parents=True)
    (root / "ganet.cmd").write_text("@echo off\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("", encoding="utf-8")
    (root / "ganet" / "__init__.py").write_text("", encoding="utf-8")
    monkeypatch.setattr(paths, "package_root", lambda: root)

    result = component_location.refresh_location()

    assert result["ok"] is True
    assert result["layout"] == "source"
    assert not isolated_location.exists()


def test_inspect_rejects_incomplete_component(tmp_path: Path) -> None:
    root = tmp_path / "incomplete"
    root.mkdir()
    (root / "ganet.cmd").write_text("", encoding="utf-8")

    result = component_location.inspect_component(root, sys.executable)

    assert result["ok"] is False
    assert result["status"] == "incomplete"
    assert "runtime/python/python.exe" in result["missing"]


def test_bundled_component_rejects_other_python(tmp_path: Path) -> None:
    root = tmp_path / "Component"
    _write_component(root)

    result = component_location.inspect_component(root, sys.executable)

    assert result["ok"] is False
    assert result["status"] == "wrong_runtime"


def test_refresh_records_current_location_atomically(
    tmp_path: Path, isolated_location: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Component"
    python = _write_component(root)
    monkeypatch.setattr(paths, "package_root", lambda: root)
    monkeypatch.setattr(component_location.sys, "executable", str(python))

    result = component_location.refresh_location()

    assert result["ok"] is True
    record = json.loads(isolated_location.read_text(encoding="utf-8"))
    assert record["schema"] == 1
    assert Path(record["package_root"]) == root.resolve()
    assert Path(record["launcher"]) == (root / "ganet.cmd").resolve()
    assert record["version"] == result["version"]
    assert not isolated_location.with_suffix(".json.tmp").exists()


def test_moved_component_refreshes_location_without_old_path(
    tmp_path: Path, isolated_location: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first_python = _write_component(first)
    second_python = _write_component(second)
    monkeypatch.setattr(paths, "package_root", lambda: first)
    monkeypatch.setattr(component_location.sys, "executable", str(first_python))
    component_location.refresh_location()

    monkeypatch.setattr(paths, "package_root", lambda: second)
    monkeypatch.setattr(component_location.sys, "executable", str(second_python))
    component_location.refresh_location()

    record = component_location.load_location()
    assert Path(record["package_root"]) == second.resolve()
    assert str(first.resolve()) not in isolated_location.read_text(encoding="utf-8")


def test_invalid_component_does_not_replace_last_location(
    tmp_path: Path, isolated_location: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid = tmp_path / "valid"
    python = _write_component(valid)
    monkeypatch.setattr(paths, "package_root", lambda: valid)
    monkeypatch.setattr(component_location.sys, "executable", str(python))
    component_location.refresh_location()
    before = isolated_location.read_bytes()
    broken = tmp_path / "broken"
    broken.mkdir()
    monkeypatch.setattr(paths, "package_root", lambda: broken)

    result = component_location.refresh_location()

    assert result["ok"] is False
    assert isolated_location.read_bytes() == before


def test_package_root_detects_bundled_layout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "Component"
    package_file = root / "runtime" / "site-packages" / "ganet" / "paths.py"
    package_file.parent.mkdir(parents=True)
    package_file.write_text("", encoding="utf-8")
    monkeypatch.delenv("GANET_ROOT", raising=False)
    monkeypatch.setattr(paths, "__file__", str(package_file))

    assert paths.package_root() == root.resolve()


def test_package_root_prefers_launcher_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "moved-component"
    monkeypatch.setenv("GANET_ROOT", str(root))

    assert paths.package_root() == root.resolve()


@pytest.mark.skipif(os.name != "nt", reason="ganet.cmd is a Windows launcher")
def test_launcher_requires_bundled_runtime(tmp_path: Path) -> None:
    source = Path(__file__).resolve().parents[1] / "ganet.cmd"
    launcher = tmp_path / "component" / "ganet.cmd"
    launcher.parent.mkdir()
    shutil.copyfile(source, launcher)

    completed = subprocess.run(
        [str(launcher), "inspect-component", "--json"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "component runtime is missing" in completed.stderr
