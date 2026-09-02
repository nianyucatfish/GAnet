from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from ganet import component_location, paths

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _write_component(root: Path) -> Path:
    (root / "ganet").mkdir(parents=True)
    (root / "ganet.cmd").write_text("@echo off\n", encoding="utf-8")
    (root / "ganet.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("", encoding="utf-8")
    (root / "ganet" / "__init__.py").write_text("", encoding="utf-8")
    return root


@pytest.fixture
def isolated_location(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    location = tmp_path / "state" / "component.json"
    monkeypatch.setattr(component_location, "_STATE_ROOT", location.parent)
    monkeypatch.setattr(component_location, "_LOCATION_PATH", location)
    return location


def test_inspect_source_component_reports_stable_identity(
    tmp_path: Path, isolated_location: Path
) -> None:
    root = _write_component(tmp_path / "Component")

    result = component_location.inspect_component(root)

    assert result["ok"] is True
    assert result["status"] == "ready"
    assert result["layout"] == "source"
    assert result["git"] is False
    assert result["commit"] is None
    assert Path(result["packageRoot"]) == root.resolve()
    assert Path(result["launcher"]) == (root / component_location.launcher_name()).resolve()
    assert not isolated_location.exists()


def test_launcher_name_follows_desktop_platform(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(component_location.sys, "platform", "win32")
    assert component_location.launcher_name() == "ganet.cmd"
    monkeypatch.setattr(component_location.sys, "platform", "darwin")
    assert component_location.launcher_name() == "ganet.sh"


def test_inspect_requires_both_launchers(tmp_path: Path) -> None:
    root = _write_component(tmp_path / "Component")
    (root / "ganet.sh").unlink()

    result = component_location.inspect_component(root)

    assert result["ok"] is False
    assert result["missing"] == ["ganet.sh"]


def test_inspect_reports_commit_from_loose_ref(tmp_path: Path) -> None:
    root = _write_component(tmp_path / "Component")
    (root / ".git" / "refs" / "heads").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (root / ".git" / "refs" / "heads" / "main").write_text("a" * 40 + "\n", encoding="utf-8")

    result = component_location.inspect_component(root)

    assert result["ok"] is True
    assert result["git"] is True
    assert result["commit"] == "a" * 12


def test_inspect_reports_commit_from_packed_refs(tmp_path: Path) -> None:
    root = _write_component(tmp_path / "Component")
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (root / ".git" / "packed-refs").write_text(
        "# pack-refs with: peeled fully-peeled sorted\n" + "b" * 40 + " refs/heads/main\n",
        encoding="utf-8",
    )

    result = component_location.inspect_component(root)

    assert result["ok"] is True
    assert result["git"] is True
    assert result["commit"] == "b" * 12


def test_inspect_rejects_incomplete_component(tmp_path: Path) -> None:
    root = tmp_path / "incomplete"
    root.mkdir()
    (root / "ganet.cmd").write_text("", encoding="utf-8")

    result = component_location.inspect_component(root)

    assert result["ok"] is False
    assert result["status"] == "incomplete"
    assert "pyproject.toml" in result["missing"]
    assert "ganet/__init__.py" in result["missing"]


def test_refresh_records_current_location_atomically(
    tmp_path: Path, isolated_location: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _write_component(tmp_path / "Component")
    monkeypatch.setattr(paths, "package_root", lambda: root)

    result = component_location.refresh_location()

    assert result["ok"] is True
    record = json.loads(isolated_location.read_text(encoding="utf-8"))
    assert record["schema"] == 1
    assert Path(record["package_root"]) == root.resolve()
    assert Path(record["launcher"]) == (root / "ganet.cmd").resolve()
    assert record["commit"] == result["commit"]
    assert not isolated_location.with_suffix(".json.tmp").exists()


def test_moved_component_refreshes_location_without_old_path(
    tmp_path: Path, isolated_location: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = _write_component(tmp_path / "first")
    second = _write_component(tmp_path / "second")
    monkeypatch.setattr(paths, "package_root", lambda: first)
    component_location.refresh_location()

    monkeypatch.setattr(paths, "package_root", lambda: second)
    component_location.refresh_location()

    record = component_location.load_location()
    assert Path(record["package_root"]) == second.resolve()
    assert str(first.resolve()) not in isolated_location.read_text(encoding="utf-8")


def test_invalid_component_does_not_replace_last_location(
    tmp_path: Path, isolated_location: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    valid = _write_component(tmp_path / "valid")
    monkeypatch.setattr(paths, "package_root", lambda: valid)
    component_location.refresh_location()
    before = isolated_location.read_bytes()
    broken = tmp_path / "broken"
    broken.mkdir()
    monkeypatch.setattr(paths, "package_root", lambda: broken)

    result = component_location.refresh_location()

    assert result["ok"] is False
    assert isolated_location.read_bytes() == before


def test_package_root_is_the_checkout_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GANET_ROOT", raising=False)

    assert paths.package_root() == _REPO_ROOT


def test_package_root_prefers_launcher_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "moved-component"
    monkeypatch.setenv("GANET_ROOT", str(root))

    assert paths.package_root() == root.resolve()


def _run_launcher(home: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = {**os.environ, "USERPROFILE": str(home)}
    environment.pop("GANET_PYTHON", None)
    environment.pop("PYTHONPATH", None)
    return subprocess.run(
        [str(_REPO_ROOT / "ganet.cmd"), *arguments],
        cwd=home,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )


@pytest.mark.skipif(os.name != "nt", reason="ganet.cmd is a Windows launcher")
def test_launcher_requires_host_binding(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()

    completed = _run_launcher(home, "inspect-component", "--json")

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert "host binding is missing" in completed.stderr


@pytest.mark.skipif(os.name != "nt", reason="ganet.cmd is a Windows launcher")
def test_launcher_rejects_stale_bound_python(tmp_path: Path) -> None:
    home = tmp_path / "home"
    shim = home / ".genericagent" / "ganet" / "ga_python.cmd"
    shim.parent.mkdir(parents=True)
    shim.write_text(
        f'@set "GANET_PYTHON={tmp_path / "gone" / "python.exe"}"\r\n', encoding="ascii"
    )

    completed = _run_launcher(home, "inspect-component", "--json")

    assert completed.returncode == 1
    assert "no longer exists" in completed.stderr


@pytest.mark.skipif(os.name != "nt", reason="ganet.cmd is a Windows launcher")
def test_launcher_runs_ganet_under_bound_python(tmp_path: Path) -> None:
    home = tmp_path / "home"
    shim = home / ".genericagent" / "ganet" / "ga_python.cmd"
    shim.parent.mkdir(parents=True)
    shim.write_text(f'@set "GANET_PYTHON={sys.executable}"\r\n', encoding="ascii")

    completed = _run_launcher(home, "inspect-component", "--json")

    assert completed.returncode == 0, completed.stderr
    result = json.loads(completed.stdout)
    assert result["ok"] is True
    assert result["layout"] == "source"
    assert Path(result["packageRoot"]) == _REPO_ROOT
