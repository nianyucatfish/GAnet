from __future__ import annotations

import os
import subprocess
import sys
import types

import ganet.device_access as device_access_pkg
from ganet.device_connection import network, pairing, sidecar_manager

_WORKER_MODULE = "ganet.device_access.interactive_worker"


def _stub_worker_module(monkeypatch, calls):
    """Replace the worker module before import: the real one resolves the host
    binding at import time and would fail on an unconfigured test machine."""
    stub = types.ModuleType(_WORKER_MODULE)
    stub.stop_worker = lambda: (calls.__setitem__("worker", calls["worker"] + 1)
                                or {"ok": True, "stopped": True, "detail": ""})
    monkeypatch.setitem(sys.modules, _WORKER_MODULE, stub)
    monkeypatch.setattr(device_access_pkg, "interactive_worker", stub, raising=False)


def _prepare(monkeypatch, tmp_path, *, token):
    config_dir = tmp_path / "home" / ".genericagent" / "ganet"
    config_dir.mkdir(parents=True)
    (config_dir / "authorized_keys").write_text("ssh-ed25519 AAA phone", encoding="utf-8")
    (config_dir / "paired_devices.json").write_text("{}", encoding="utf-8")
    (config_dir / "config.json").write_text("{}", encoding="utf-8")
    sidecar_dir = tmp_path / "sidecar"
    (sidecar_dir / "state").mkdir(parents=True)
    executable = sidecar_dir / "ganet-sidecar.exe"
    executable.write_bytes(b"stub")

    calls = {"remote": [], "worker": 0, "service": 0, "commands": []}
    _stub_worker_module(monkeypatch, calls)
    monkeypatch.setattr(pairing.login, "get_token", lambda: token)
    monkeypatch.setattr(network, "load_receipt", lambda: {"hostname": "ga-pc-test"})
    monkeypatch.setattr(network, "_retire_remote",
                        lambda tok, host: calls["remote"].append((tok, host)))
    monkeypatch.setattr(network, "managed_authorized_keys_path",
                        lambda: config_dir / "authorized_keys")
    monkeypatch.setattr(sidecar_manager, "_stop_running",
                        lambda: calls.__setitem__("service", calls["service"] + 1))
    monkeypatch.setattr(sidecar_manager, "_ROOT", sidecar_dir)
    monkeypatch.setattr(sidecar_manager, "_EXECUTABLE", executable)

    def fake_run(command, **kwargs):
        calls["commands"].append([str(part) for part in command])
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(pairing.subprocess, "run", fake_run)
    return config_dir, sidecar_dir, executable, calls


def test_remove_environment_requires_approval(monkeypatch, tmp_path):
    config_dir, sidecar_dir, _executable, calls = _prepare(monkeypatch, tmp_path, token="tok")
    result = pairing.remove_environment()
    assert result["status"] == "needs_approval"
    assert result["changed"] is False
    assert result["steps"]
    assert calls["remote"] == []
    assert calls["worker"] == 0
    assert calls["service"] == 0
    assert config_dir.exists()
    assert sidecar_dir.exists()


def test_remove_environment_runs_fixed_sequence(monkeypatch, tmp_path):
    config_dir, sidecar_dir, executable, calls = _prepare(monkeypatch, tmp_path, token="tok")
    result = pairing.remove_environment(approved=True)
    assert result["status"] == "removed"
    assert result["changed"] is True
    assert calls["remote"] == [("tok", "ga-pc-test")]
    assert calls["worker"] == 1
    assert calls["service"] == 1
    assert not sidecar_dir.exists()
    assert not config_dir.exists()
    if os.name == "nt":
        assert [str(executable), "autostart", "remove"] in calls["commands"]


def test_remove_environment_without_login_skips_remote(monkeypatch, tmp_path):
    config_dir, sidecar_dir, _executable, calls = _prepare(monkeypatch, tmp_path, token=None)
    result = pairing.remove_environment(approved=True)
    assert result["status"] == "removed"
    assert calls["remote"] == []
    assert result["steps"]["remote"] == "skipped"
    assert not config_dir.exists()
    assert not sidecar_dir.exists()


def test_remove_environment_remote_failure_does_not_block_local(monkeypatch, tmp_path):
    config_dir, sidecar_dir, _executable, _calls = _prepare(monkeypatch, tmp_path, token="tok")

    def boom(tok, host):
        raise RuntimeError("registry unreachable")

    monkeypatch.setattr(network, "_retire_remote", boom)
    result = pairing.remove_environment(approved=True)
    assert result["status"] == "removed"
    assert result["steps"]["remote"].startswith("failed")
    assert not config_dir.exists()
    assert not sidecar_dir.exists()


def test_remove_environment_skips_worker_when_runtime_unbound(monkeypatch, tmp_path):
    config_dir, sidecar_dir, _executable, calls = _prepare(monkeypatch, tmp_path, token=None)
    # An unbound machine cannot even import the worker module; a None entry in
    # sys.modules makes both import forms raise ImportError the same way.
    monkeypatch.setitem(sys.modules, _WORKER_MODULE, None)
    monkeypatch.delattr(device_access_pkg, "interactive_worker", raising=False)
    result = pairing.remove_environment(approved=True)
    assert result["status"] == "removed"
    assert result["steps"]["worker"] == "skipped"
    assert calls["worker"] == 0
    assert not config_dir.exists()
    assert not sidecar_dir.exists()


def test_remove_environment_second_run_reports_removed(monkeypatch, tmp_path):
    _config_dir, _sidecar_dir, _executable, calls = _prepare(monkeypatch, tmp_path, token=None)
    first = pairing.remove_environment(approved=True)
    second = pairing.remove_environment(approved=True)
    assert first["status"] == "removed"
    assert second["status"] == "removed"
    assert calls["worker"] == 2
    if os.name == "nt":
        # Binary gone on the second pass: the registry fallback must be used.
        assert any(command[0] == "reg.exe" for command in calls["commands"])
