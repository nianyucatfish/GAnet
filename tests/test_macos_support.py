"""Platform contracts that let the same component run on Windows and macOS."""
from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path

import pytest

from ganet.device_access import bridge
from ganet.device_connection import network, pairing, sidecar_manager, sidecar_paths


def _pretend(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(sidecar_paths.sys, "platform", platform)
    monkeypatch.delenv("GANET_SIDECAR_DIR", raising=False)
    monkeypatch.delenv("GANET_SIDECAR_EXE", raising=False)


def test_sidecar_root_matches_go_data_root(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(sidecar_paths.Path, "home", classmethod(lambda cls: tmp_path))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "AppData" / "Local"))

    _pretend(monkeypatch, "win32")
    assert sidecar_paths.sidecar_root() == tmp_path / "AppData" / "Local" / "GenericAgent" / "GAnet"
    assert sidecar_paths.sidecar_executable().name == "ganet-sidecar.exe"

    _pretend(monkeypatch, "darwin")
    assert sidecar_paths.sidecar_root() == \
        tmp_path / "Library" / "Application Support" / "GenericAgent" / "GAnet"
    assert sidecar_paths.sidecar_executable().name == "ganet-sidecar"
    assert sidecar_paths.launchd_agent_path() == \
        tmp_path / "Library" / "LaunchAgents" / "ai.gaagent.ganet-sidecar.plist"


def test_environment_overrides_win_on_every_platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for platform in ("win32", "darwin"):
        _pretend(monkeypatch, platform)
        monkeypatch.setenv("GANET_SIDECAR_DIR", str(tmp_path / "custom"))
        monkeypatch.setenv("GANET_SIDECAR_EXE", str(tmp_path / "custom" / "bin"))
        assert sidecar_paths.sidecar_root() == tmp_path / "custom"
        assert sidecar_paths.sidecar_executable() == tmp_path / "custom" / "bin"


def test_provider_is_the_sidecar_on_windows_and_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GANET_USE_SYSTEM_TAILSCALE", raising=False)
    for is_win, is_mac in ((True, False), (False, True)):
        monkeypatch.setattr(network, "_IS_WIN", is_win)
        monkeypatch.setattr(network, "_IS_MAC", is_mac)
        assert isinstance(network.get_provider(), network.TsnetSidecarProvider)
    monkeypatch.setattr(network, "_IS_WIN", False)
    monkeypatch.setattr(network, "_IS_MAC", False)
    assert isinstance(network.get_provider(), network.SystemTailscaleProvider)
    # The historical name still resolves for callers written against it.
    assert network.WindowsTsnetSidecarProvider is network.TsnetSidecarProvider


def test_default_hostname_prefers_macos_local_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network, "_IS_MAC", True)
    monkeypatch.setattr(network.socket, "gethostname", lambda: "192.168.5.130")
    monkeypatch.setattr(network, "_run", lambda cmd, timeout=30: subprocess.CompletedProcess(
        cmd, 0, "catfish-MacBook-Air\n", ""))
    assert network.default_hostname() == "catfish-macbook-air"


def test_default_hostname_never_uses_an_ip_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network, "_IS_MAC", False)
    monkeypatch.setattr(network.socket, "gethostname", lambda: "192.168.5.130")
    name = network.default_hostname()
    assert name.startswith("ga-pc-") and len(name) == len("ga-pc-") + 8
    monkeypatch.setattr(network.socket, "gethostname", lambda: "fe80::1")
    assert network.default_hostname().startswith("ga-pc-")
    monkeypatch.setattr(network.socket, "gethostname", lambda: "Studio.local")
    assert network.default_hostname() == "studio"


def _macho(magic: int, cpu_type: int, *, big_endian: bool = False) -> bytes:
    order = ">" if big_endian else "<"
    return struct.pack(order + "II", magic, cpu_type) + b"\0" * 24


def test_macho_architecture_detection(tmp_path: Path) -> None:
    arm = tmp_path / "arm"
    arm.write_bytes(_macho(0xFEEDFACF, 0x0100000C))
    assert sidecar_manager._macho_architecture(arm) == "arm64"

    intel = tmp_path / "intel"
    intel.write_bytes(_macho(0xFEEDFACF, 0x01000007))
    assert sidecar_manager._macho_architecture(intel) == "amd64"

    fat = tmp_path / "fat"
    fat.write_bytes(_macho(0xCAFEBABE, 2, big_endian=True))
    with pytest.raises(RuntimeError, match="fat"):
        sidecar_manager._macho_architecture(fat)

    pe = tmp_path / "pe"
    pe.write_bytes(b"MZ" + b"\0" * 30)
    with pytest.raises(RuntimeError, match="Mach-O"):
        sidecar_manager._macho_architecture(pe)


def _release(platform: str, architecture: str, path: Path) -> dict:
    import hashlib
    return {"platform": platform, "architecture": architecture, "version": "9.9.9",
            "protocol_version": 1, "url": "https://ganet.gaagent.ai/releases/sidecar/x",
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size,
            "update_level": "available", "manifest_verified": True}


def test_verify_release_accepts_matching_macos_binary(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "ganet-sidecar"
    binary.write_bytes(_macho(0xFEEDFACF, 0x0100000C))
    release = _release("darwin", "arm64", binary)
    monkeypatch.setattr(sidecar_manager, "current_platform", lambda: "darwin")
    monkeypatch.setattr(sidecar_manager, "current_architecture", lambda: "arm64")

    verified = sidecar_manager.verify_release(sidecar_manager.DownloadedRelease(binary, release))

    assert verified.path == binary


def test_verify_release_rejects_foreign_platform(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "ganet-sidecar"
    binary.write_bytes(_macho(0xFEEDFACF, 0x0100000C))
    release = _release("darwin", "arm64", binary)
    monkeypatch.setattr(sidecar_manager, "current_platform", lambda: "windows")
    monkeypatch.setattr(sidecar_manager, "current_architecture", lambda: "amd64")

    with pytest.raises(RuntimeError, match="不适用于当前电脑"):
        sidecar_manager.verify_release(sidecar_manager.DownloadedRelease(binary, release))

    release["platform"] = "linux"
    with pytest.raises(RuntimeError, match="不支持该平台"):
        sidecar_manager.verify_release(sidecar_manager.DownloadedRelease(binary, release))


def test_macos_stop_running_unloads_agent_then_signals(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []
    signals: list[tuple[int, int]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    alive = {"value": True}

    def fake_kill(pid, sig):
        if sig == 0:
            if alive["value"]:
                return None
            raise ProcessLookupError
        signals.append((pid, sig))
        alive["value"] = False

    states = iter([{"installed": True, "running": True, "pid": 4242},
                   {"installed": True, "running": False}])
    monkeypatch.setattr(sidecar_manager, "_IS_MAC", True)
    monkeypatch.setattr(sidecar_manager.os, "name", "posix")
    monkeypatch.setattr(sidecar_paths.os, "getuid", lambda: 501, raising=False)
    monkeypatch.setattr(sidecar_paths.os, "kill", fake_kill, raising=False)
    monkeypatch.setattr(sidecar_manager.subprocess, "run", fake_run)
    monkeypatch.setattr(sidecar_manager, "_status", lambda *args, **kwargs: next(states, {"running": False}))

    sidecar_manager._stop_running()

    assert calls[0][:2] == ["launchctl", "bootout"]
    assert calls[0][2] == "gui/501/ai.gaagent.ganet-sidecar"
    assert signals and signals[0][0] == 4242
    assert not [command for command in calls if command[0] in ("taskkill", "powershell")]


def test_macos_remove_autostart_without_binary_cleans_launchd(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):
        calls.append(list(command))
        return subprocess.CompletedProcess(command, 0, stdout=b"", stderr=b"")

    plist = tmp_path / "LaunchAgents" / "ai.gaagent.ganet-sidecar.plist"
    plist.parent.mkdir()
    plist.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(pairing.sys, "platform", "darwin")
    monkeypatch.setattr(sidecar_paths.os, "getuid", lambda: 501, raising=False)
    monkeypatch.setattr(pairing.subprocess, "run", fake_run)
    monkeypatch.setattr(sidecar_paths, "launchd_agent_path", lambda: plist)

    assert pairing._remove_autostart(tmp_path / "missing-sidecar") == "ok"
    assert calls == [["launchctl", "bootout", "gui/501/ai.gaagent.ganet-sidecar"]]
    assert not plist.exists()


def test_screen_access_probe_is_a_noop_outside_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bridge.sys, "platform", "win32")
    result = bridge._screen_access()
    assert result["ok"] is True and result["granted"] is True and result["prompted"] is False


def test_screen_access_probe_requests_on_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    from ganet.device_access import screenshot

    monkeypatch.setattr(bridge.sys, "platform", "darwin")
    monkeypatch.setattr(screenshot, "_macos_screen_capture_allowed", lambda: False)
    result = bridge._screen_access()
    assert result["granted"] is False and result["prompted"] is True
    assert "屏幕录制" in result["hint"]


def test_setup_requests_screen_access_through_the_phone_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """The prompt must be attributed to the sidecar, so the request rides the same
    loopback SSH + atomic-bridge chain the phone uses -- never a direct call."""
    commands: list[str] = []

    @__import__("contextlib").contextmanager
    def fake_session(host, port):
        assert host == "127.0.0.1" and port == 48222

        def run_remote(command, timeout=25):
            commands.append(command)
            return subprocess.CompletedProcess(command, 0, json.dumps(
                {"ok": True, "protocol": 1, "platform": "darwin", "granted": False, "prompted": True}), "")
        yield run_remote

    saved = {}
    monkeypatch.setattr(network, "_IS_MAC", True)
    monkeypatch.setattr(network, "load_config", lambda: {"ssh": {"port": 48222}})
    monkeypatch.setattr(network, "save_config", lambda **fields: saved.update(fields))
    monkeypatch.setattr(network, "get_provider", lambda: type("P", (), {
        "binary_ok": lambda self: True,
        "status": lambda self: {"running": True, "ssh_loopback": True}})())
    monkeypatch.setattr(network, "_phone_emulation_session", fake_session)

    result = network.request_screen_access()

    assert commands == ["~/.genericagent/ganet/atomic-bridge --screen-access"]
    assert result["granted"] is False and result["prompted"] is True
    assert "允许" in result["detail"]
    assert saved["screen_access"]["granted"] is False


def test_request_screen_access_is_skipped_off_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(network, "_IS_MAC", False)
    assert network.request_screen_access()["granted"] is True


def test_finish_setup_attaches_screen_access_without_changing_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pairing, "probe_phone_ssh", lambda: {"ok": True, "detail": "ok"})
    monkeypatch.setattr(network, "request_screen_access",
                        lambda: {"granted": False, "prompted": True, "detail": "请点击允许"})
    result = pairing._finish_setup({"status": "ok", "checks": {}}, changed=False)
    assert result["status"] == "ok"
    assert result["screen_access"]["granted"] is False
    assert result["message"] == "请点击允许"


def test_bridge_dispatches_in_process_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only Windows needs the desktop-session worker; elsewhere the reply must be
    produced in this process with tool output kept off stdout."""
    seen = {}

    def fake_handle(request, *, capture_output):
        seen["request"] = request
        seen["capture_output"] = capture_output
        return {"ok": True}

    # interactive_worker resolves the host binding at import time, so it must
    # not be imported here (CI has no binding); the dispatch decision is what
    # is under test, and the worker path is only taken on Windows.
    monkeypatch.setattr(bridge.os, "name", "posix")
    monkeypatch.setattr(bridge, "handle", fake_handle)
    assert bridge._uses_interactive_worker() is False

    response = bridge._dispatch_request({"tool": "file_read", "requestId": "req_1"})

    assert response == {"ok": True}
    assert seen["capture_output"] is True
    assert json.dumps(seen["request"])

    monkeypatch.setattr(bridge.os, "name", "nt")
    assert bridge._uses_interactive_worker() is True
