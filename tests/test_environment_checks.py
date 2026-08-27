from __future__ import annotations

import os
import subprocess

import pytest

from ganet.device_connection import network, pairing, sidecar_manager


class _FakeProvider:
    name = "embedded-tsnet"

    def __init__(self, status):
        self._status = status

    def binary_ok(self):
        return True

    def available(self):
        return True

    def status(self):
        return dict(self._status)


_PROBE = {"ok": True, "detail": "GAnet sidecar Tailnet 监听正常，内嵌 SSH 公钥认证通过",
          "checked_at": 1786592849}


def _patch_environment(monkeypatch, tmp_path, *, service_up):
    runtime = {"responsive": True, "online": service_up, "on_ga_control": service_up,
               "running": service_up, "listening": service_up, "ssh_loopback": service_up}
    monkeypatch.setattr(network, "get_provider", lambda: _FakeProvider(runtime))
    monkeypatch.setattr(network, "load_config",
                        lambda: {"ssh": {"port": 48222}, "ssh_probe": dict(_PROBE)})
    monkeypatch.setattr(network, "load_receipt", lambda: {})
    monkeypatch.setattr(network, "_port_listening", lambda port: service_up)
    monkeypatch.setattr(network, "managed_authorized_keys_path",
                        lambda: tmp_path / "authorized_keys")
    monkeypatch.setattr(network, "_managed_keys_acl_ok", lambda: False)
    monkeypatch.setattr(network, "_read_sidecar_host_key", lambda: "")
    monkeypatch.setattr(sidecar_manager, "inspect",
                        lambda: {"version_state": "current", "reason": ""})


def test_check_env_marks_cached_probe_stale_when_service_down(monkeypatch, tmp_path):
    """A green probe verdict must not survive the SSH service going down."""
    _patch_environment(monkeypatch, tmp_path, service_up=False)
    report = network.check_env()
    assert report["checks"]["ssh_probe"] is None
    assert "需重新验证" in report["ssh_probe"]["detail"]
    assert report["ssh_probe"]["checked_at"] == _PROBE["checked_at"]


def test_check_env_keeps_cached_probe_while_service_up(monkeypatch, tmp_path):
    _patch_environment(monkeypatch, tmp_path, service_up=True)
    report = network.check_env()
    assert report["checks"]["ssh_probe"] is True
    assert report["ssh_probe"]["detail"] == _PROBE["detail"]


def _fake_env_report(*, installed, version_state):
    return {"status": "need_install" if not installed else "need_repair",
            "provider": "embedded-tsnet", "version_state": version_state,
            "checks": {"qr_component": True, "screenshot_media": True,
                       "network_provider": installed},
            "receipt": {}, "runtime": {}}


def _forbid_install(monkeypatch):
    calls = []
    for name in ("list_releases", "select_release", "download_release",
                 "verify_release", "install_release"):
        monkeypatch.setattr(sidecar_manager, name,
                            lambda *args, _name=name, **kwargs: calls.append(_name))
    return calls


def test_configure_environment_reports_missing_component_without_installing(monkeypatch):
    """configure_environment must not fetch the sidecar itself; installing is
    the staged section-3 flow, so a missing component is only reported."""
    calls = _forbid_install(monkeypatch)
    monkeypatch.setattr(network, "check_env",
                        lambda: _fake_env_report(installed=False, version_state="required"))
    monkeypatch.setattr(network, "initial_network_defaults_pending", lambda: False)
    result = pairing.configure_environment(approved=True)
    assert result["status"] == "needs_system_setup"
    assert "GAnet 网络组件" in result["message"]
    assert not calls


def test_configure_environment_reports_required_update_without_installing(monkeypatch):
    calls = _forbid_install(monkeypatch)
    monkeypatch.setattr(network, "check_env",
                        lambda: _fake_env_report(installed=True, version_state="required"))
    monkeypatch.setattr(network, "initial_network_defaults_pending", lambda: False)
    result = pairing.configure_environment(approved=True)
    assert result["status"] == "needs_system_setup"
    assert "更新" in result["message"]
    assert not calls


@pytest.mark.skipif(os.name != "nt", reason="Windows process sweep")
def test_stop_running_sweeps_wedged_process_by_path(monkeypatch):
    """A sidecar whose status reports no pid must still be stopped by image path,
    or the installer cannot replace the locked executable."""
    calls = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(sidecar_manager.subprocess, "run", fake_run)
    monkeypatch.setattr(sidecar_manager, "_status",
                        lambda *args, **kwargs: {"installed": True, "running": False})
    sidecar_manager._stop_running()
    assert not [command for command in calls if command[0] == "taskkill"]
    sweep = [command for command in calls if command[0] == "powershell"]
    assert len(sweep) == 1
    script = sweep[0][-1]
    assert str(sidecar_manager._EXECUTABLE) in script
    assert "Stop-Process" in script
