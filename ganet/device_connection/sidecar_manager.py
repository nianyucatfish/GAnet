"""Signed release discovery and transactional Windows GAnet component installs."""
from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import platform
import secrets
import shutil
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

RELEASES_URL = os.environ.get(
    "GANET_SIDECAR_RELEASES_URL",
    "https://ganet.gaagent.ai/releases/sidecar/manifest.json",
)
_ROOT = Path(os.environ.get(
    "GANET_SIDECAR_DIR",
    os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                 "GenericAgent", "GAnet"),
))
_EXECUTABLE = Path(os.environ.get("GANET_SIDECAR_EXE", str(_ROOT / "ganet-sidecar.exe")))
_CACHE = _ROOT / "release-cache.json"
_CACHE_SECONDS = 6 * 60 * 60
_MAX_MANIFEST_BYTES = 256 * 1024
_MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA8CvZa12oPrXKSoAeIJVOWq0q7pBvPkGjnZFVjtVa6cY=
-----END PUBLIC KEY-----
"""


@dataclass(frozen=True)
class DownloadedRelease:
    path: Path
    release: dict[str, Any]


@dataclass(frozen=True)
class VerifiedRelease:
    path: Path
    release: dict[str, Any]


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _verify_signature(signed: dict[str, Any], signature: str) -> None:
    try:
        raw = base64.b64decode(signature, validate=True)
    except Exception as exc:
        raise RuntimeError("GAnet 组件发布清单签名格式无效") from exc
    try:
        from cryptography.hazmat.primitives import serialization
        public_key = serialization.load_pem_public_key(_PUBLIC_KEY_PEM)
        public_key.verify(raw, _canonical(signed))
    except ImportError as exc:
        raise RuntimeError("当前 GA 缺少组件发布签名验证能力") from exc
    except Exception as exc:
        raise RuntimeError("GAnet 组件发布清单签名验证失败") from exc


def _validate_manifest(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"signed", "signature"}:
        raise RuntimeError("GAnet 组件发布清单格式无效")
    signed, signature = value["signed"], value["signature"]
    if not isinstance(signed, dict) or not isinstance(signature, str):
        raise RuntimeError("GAnet 组件发布清单格式无效")
    _verify_signature(signed, signature)
    if signed.get("schema") != 1 or signed.get("component") != "ganet-sidecar":
        raise RuntimeError("GAnet 组件发布清单版本不受支持")
    releases = signed.get("releases")
    if not isinstance(releases, list) or not releases:
        raise RuntimeError("GAnet 组件发布清单没有可用文件")
    result = []
    required = {"platform", "architecture", "version", "protocol_version",
                "url", "sha256", "size", "update_level"}
    base = urllib.parse.urlsplit(RELEASES_URL)
    for entry in releases:
        if not isinstance(entry, dict) or not required.issubset(entry):
            raise RuntimeError("GAnet 组件发布条目格式无效")
        parsed = urllib.parse.urlsplit(str(entry["url"]))
        if (parsed.scheme, parsed.netloc) != ("https", base.netloc) or \
                not parsed.path.startswith("/releases/sidecar/"):
            raise RuntimeError("GAnet 组件发布地址超出允许范围")
        digest = str(entry["sha256"]).lower()
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise RuntimeError("GAnet 组件发布摘要格式无效")
        if not isinstance(entry["size"], int) or not 0 < entry["size"] <= _MAX_ARTIFACT_BYTES:
            raise RuntimeError("GAnet 组件发布文件大小无效")
        if entry["update_level"] not in ("available", "required"):
            raise RuntimeError("GAnet 组件更新级别无效")
        result.append({**entry, "manifest_verified": True})
    # 从新到旧排列,拿“第一条匹配”的调用方也会得到最新版本。
    result.sort(key=lambda entry: _version_tuple(str(entry["version"])), reverse=True)
    return result


def _tls_context() -> ssl.SSLContext:
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def _request_bytes(url: str, limit: int, timeout: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "GenericAgent-GAnet/1"})
    try:
        with urllib.request.urlopen(request, timeout=timeout,
                                    context=_tls_context()) as response:
            final = urllib.parse.urlsplit(response.geturl())
            expected = urllib.parse.urlsplit(RELEASES_URL)
            if final.scheme != "https" or final.netloc != expected.netloc:
                raise RuntimeError("GAnet 组件下载发生了不允许的重定向")
            length = response.headers.get("Content-Length")
            if length and int(length) > limit:
                raise RuntimeError("GAnet 组件下载文件超出大小限制")
            value = response.read(limit + 1)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise RuntimeError("无法读取 GAnet 组件发布服务") from exc
    if len(value) > limit:
        raise RuntimeError("GAnet 组件下载文件超出大小限制")
    return value


def _save_cache(value: dict[str, Any]) -> None:
    _ROOT.mkdir(parents=True, exist_ok=True)
    temporary = _CACHE.with_suffix(".tmp")
    temporary.write_text(json.dumps({"checked_at": int(time.time()), "manifest": value},
                                    ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, _CACHE)


def _read_cache() -> tuple[dict[str, Any] | None, int]:
    try:
        value = json.loads(_CACHE.read_text(encoding="utf-8"))
        manifest = value.get("manifest")
        checked_at = int(value.get("checked_at") or 0)
        if isinstance(manifest, dict):
            _validate_manifest(manifest)
            return manifest, checked_at
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        pass
    return None, 0


def list_releases(*, refresh: bool = True) -> list[dict[str, Any]]:
    """Return only entries covered by the signed release manifest."""
    cached, checked_at = _read_cache()
    if cached is not None and not refresh and time.time() - checked_at < _CACHE_SECONDS:
        return _validate_manifest(cached)
    try:
        value = json.loads(_request_bytes(RELEASES_URL, _MAX_MANIFEST_BYTES, 10).decode("utf-8"))
        releases = _validate_manifest(value)
        _save_cache(value)
        return releases
    except (UnicodeDecodeError, json.JSONDecodeError, RuntimeError):
        if cached is not None:
            return _validate_manifest(cached)
        raise


def current_architecture() -> str:
    machine = platform.machine().lower()
    aliases = {"x86_64": "amd64", "amd64": "amd64", "arm64": "arm64", "aarch64": "arm64"}
    return aliases.get(machine, machine)


def select_release(releases: list[dict[str, Any]], *, system: str | None = None,
                   architecture: str | None = None) -> dict[str, Any]:
    system = (system or platform.system()).lower()
    architecture = architecture or current_architecture()
    matches = [release for release in releases
               if release.get("platform") == system and release.get("architecture") == architecture]
    if not matches:
        raise RuntimeError(f"发布服务没有适用于 {system}/{architecture} 的 GAnet 组件")
    return max(matches, key=lambda item: _version_tuple(str(item.get("version") or "")))


def download_release(release: dict[str, Any]) -> DownloadedRelease:
    if not release.get("manifest_verified"):
        raise RuntimeError("拒绝下载未经发布清单验证的组件")
    data = _request_bytes(str(release["url"]), int(release["size"]), 60)
    if len(data) != int(release["size"]):
        raise RuntimeError("GAnet 组件下载大小与发布清单不一致")
    directory = Path(tempfile.mkdtemp(prefix="ganet-sidecar-download-"))
    path = directory / "ganet-sidecar.exe"
    path.write_bytes(data)
    return DownloadedRelease(path, dict(release))


def _pe_architecture(path: Path) -> str:
    with path.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise RuntimeError("下载文件不是 Windows PE 程序")
        stream.seek(0x3C)
        offset_data = stream.read(4)
        if len(offset_data) != 4:
            raise RuntimeError("Windows PE 文件头不完整")
        stream.seek(struct.unpack("<I", offset_data)[0])
        if stream.read(4) != b"PE\0\0":
            raise RuntimeError("Windows PE 签名无效")
        machine_data = stream.read(2)
    machine = struct.unpack("<H", machine_data)[0] if len(machine_data) == 2 else 0
    architectures = {0x8664: "amd64", 0xAA64: "arm64", 0x014C: "386"}
    if machine not in architectures:
        raise RuntimeError("Windows PE 架构不受支持")
    return architectures[machine]


def verify_release(artifact: DownloadedRelease, release: dict[str, Any] | None = None) -> VerifiedRelease:
    release = dict(release or artifact.release)
    if artifact.release != release or not release.get("manifest_verified"):
        raise RuntimeError("组件文件与已验证发布条目不匹配")
    digest = hashlib.sha256(artifact.path.read_bytes()).hexdigest()
    if digest != release["sha256"]:
        raise RuntimeError("GAnet 组件 SHA-256 校验失败")
    if _pe_architecture(artifact.path) != release["architecture"]:
        raise RuntimeError("GAnet 组件文件架构与发布清单不一致")
    if release["platform"] != "windows" or release["architecture"] != current_architecture():
        raise RuntimeError("GAnet 组件不适用于当前电脑")
    return VerifiedRelease(artifact.path, release)


def _run_json_command(executable: Path, command: str) -> dict[str, Any]:
    completed = subprocess.run([str(executable), command], capture_output=True, text=True,
                               encoding="utf-8", errors="replace", timeout=5)
    value = json.loads(completed.stdout) if completed.returncode == 0 else {}
    return value if isinstance(value, dict) else {}


def _status(executable: Path = _EXECUTABLE) -> dict[str, Any]:
    if not executable.is_file():
        return {"installed": False, "running": False, "online": False, "listening": False}
    try:
        value = _run_json_command(executable, "status")
        if value:
            return {"installed": True, **value}
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        pass
    return {"installed": True, "running": False, "online": False, "listening": False}


def _binary_version(executable: Path = _EXECUTABLE) -> dict[str, Any]:
    try:
        return _run_json_command(executable, "version")
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return {}


def _version_tuple(value: str) -> tuple[int, ...]:
    core = value.split("-", 1)[0]
    try:
        return tuple(int(part) for part in core.split("."))
    except ValueError:
        return ()


def inspect(*, refresh: bool = True) -> dict[str, Any]:
    local = _status()
    version_state, reason = "unknown", "发布状态暂不可用"
    try:
        release = select_release(list_releases(refresh=refresh))
        current = _version_tuple(str(local.get("version") or ""))
        latest = _version_tuple(str(release["version"]))
        if not local.get("installed"):
            version_state, reason = "required", "网络组件尚未安装"
        elif not current or current < latest:
            version_state = str(release["update_level"])
            reason = "有兼容的新组件可用" if version_state == "available" else "网络组件需要更新"
        else:
            version_state, reason = "current", ""
    except RuntimeError:
        if not local.get("installed"):
            reason = "网络组件尚未安装，且暂时无法读取发布服务"
    return {**local, "version_state": version_state, "reason": reason}


def _stop_running() -> None:
    state = _status()
    pid = state.get("pid")
    if pid and os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True,
                       timeout=20)
    if os.name == "nt":
        # A wedged sidecar can hold the executable lock while its own status
        # command reports no pid; sweep by image path so an upgrade can still
        # replace the file. Matching on the full path spares unrelated builds.
        path = str(_EXECUTABLE).replace("'", "''")
        subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-CimInstance Win32_Process | "
             "Where-Object { $_.ExecutablePath -eq '" + path + "' } | "
             "ForEach-Object { Stop-Process -Id $_.ProcessId -Force }"],
            capture_output=True, timeout=30)
    deadline = time.monotonic() + 15
    while _status().get("running") and time.monotonic() < deadline:
        time.sleep(0.25)
    if _status().get("running"):
        raise RuntimeError("无法停止当前 GAnet 网络组件")


def _run_interactive_task() -> None:
    task_name = "GenericAgent-GAnet-Start-" + secrets.token_hex(12)
    descriptor, name = tempfile.mkstemp(prefix="ganet-sidecar-task-", suffix=".xml")
    os.close(descriptor)
    task_xml = Path(name)
    try:
        task_xml.write_text(
            '<?xml version="1.0" encoding="UTF-16"?>\n'
            '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
            '<Triggers><TimeTrigger><StartBoundary>2030-01-01T00:00:00</StartBoundary>'
            '<Enabled>true</Enabled></TimeTrigger></Triggers>'
            '<Principals><Principal id="Author"><UserId>{}</UserId>'
            '<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel>'
            '</Principal></Principals><Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>'
            '<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
            '<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
            '<StartWhenAvailable>true</StartWhenAvailable><Hidden>true</Hidden>'
            '<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>'
            '</Settings><Actions Context="Author"><Exec><Command>{}</Command>'
            '<Arguments>run</Arguments><WorkingDirectory>{}</WorkingDirectory>'
            '</Exec></Actions></Task>'.format(
                xml_escape(os.environ["USERNAME"]), xml_escape(str(_EXECUTABLE)),
                xml_escape(str(_EXECUTABLE.parent))),
            encoding="utf-16")
        created = subprocess.run(
            ["schtasks.exe", "/Create", "/TN", task_name, "/XML", str(task_xml), "/F"],
            capture_output=True, timeout=30)
        if created.returncode:
            raise RuntimeError("GAnet 网络组件交互会话启动任务创建失败")
        started = subprocess.run(["schtasks.exe", "/Run", "/TN", task_name],
                                 capture_output=True, timeout=30)
        if started.returncode:
            raise RuntimeError("GAnet 网络组件交互会话启动失败")
    finally:
        with contextlib.suppress(Exception):
            subprocess.run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"],
                           capture_output=True, timeout=15)
        with contextlib.suppress(OSError):
            task_xml.unlink()


def _start() -> None:
    if os.name == "nt":
        _run_interactive_task()
        return
    subprocess.Popen([str(_EXECUTABLE), "run"], stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     close_fds=True)


def _wait_for_stable_start(version: str, *, require_online: bool = False,
                           require_listening: bool = False, timeout: float = 30,
                           stable_seconds: float = 3) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    stable_since: float | None = None
    stable_pid: Any = None
    state = _status()
    while time.monotonic() < deadline:
        healthy = bool(state.get("running") and state.get("version") == version
                       and state.get("pid")
                       and (not require_online or state.get("online"))
                       and (not require_listening or state.get("listening")))
        if healthy:
            if state.get("pid") != stable_pid:
                stable_pid = state.get("pid")
                stable_since = time.monotonic()
            elif stable_since is not None and time.monotonic() - stable_since >= stable_seconds:
                return state
        else:
            stable_pid = None
            stable_since = None
        time.sleep(0.5)
        state = _status()
    raise RuntimeError("新 GAnet 网络组件健康检查未通过")


def _install_autostart() -> None:
    completed = subprocess.run([str(_EXECUTABLE), "autostart", "install"], capture_output=True,
                               text=True, encoding="utf-8", errors="replace", timeout=30)
    if completed.returncode:
        raise RuntimeError("GAnet 网络组件登录自启动配置失败")


def _replace_with_retry(source: Path, destination: Path, *, timeout: float = 15) -> None:
    """Wait out Windows' delayed executable-handle release before replacing."""
    deadline = time.monotonic() + timeout
    while True:
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            retryable = isinstance(exc, PermissionError) or \
                getattr(exc, "winerror", None) in (5, 32)
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def _protect_windows_directory() -> None:
    if os.name != "nt":
        return
    quoted = str(_ROOT).replace("'", "''")
    script = (
        "$ErrorActionPreference='Stop';$p='" + quoted + "';"
        "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;"
        "& icacls $p /inheritance:r /grant:r \"*${sid}:(OI)(CI)(F)\" "
        "'*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' | Out-Null;"
        "if($LASTEXITCODE){exit $LASTEXITCODE};"
        "$a=Get-Acl -LiteralPath $p; if(-not $a.AreAccessRulesProtected){exit 9}"
    )
    completed = subprocess.run(["powershell", "-NoProfile", "-Command", script],
                               capture_output=True, timeout=60)
    if completed.returncode:
        raise RuntimeError("GAnet 网络组件目录权限配置失败")


def install_release(verified: VerifiedRelease) -> dict[str, Any]:
    if os.name != "nt" and os.environ.get("GANET_ALLOW_NONWINDOWS_INSTALL") != "1":
        raise RuntimeError("GAnet Windows 组件只能在 Windows 上安装")
    _ROOT.mkdir(parents=True, exist_ok=True)
    backup = _EXECUTABLE.with_suffix(".exe.rollback")
    staged = _EXECUTABLE.with_suffix(".exe.new")
    had_old = _EXECUTABLE.is_file()
    previous_state = _status()
    replaced = False
    try:
        # Unconditional: a wedged process may not report as running yet still
        # hold the executable lock that would break the replace below.
        _stop_running()
        shutil.copy2(verified.path, staged)
        if had_old:
            shutil.copy2(_EXECUTABLE, backup)
        _replace_with_retry(staged, _EXECUTABLE)
        replaced = True
        _protect_windows_directory()
        _install_autostart()
        binary = _binary_version()
        if binary.get("version") != verified.release["version"] or \
                str(binary.get("protocolVersion")) != str(verified.release["protocol_version"]):
            raise RuntimeError("新 GAnet 网络组件版本检查未通过")
        expected_commit = verified.release.get("commit")
        if expected_commit and binary.get("commit") != expected_commit:
            raise RuntimeError("新 GAnet 网络组件构建身份检查未通过")
        configured = (_ROOT / "config.json").is_file()
        if configured:
            _start()
            state = _wait_for_stable_start(
                verified.release["version"],
                require_online=bool(previous_state.get("online")),
                require_listening=bool(previous_state.get("listening")),
            )
        else:
            state = {"running": False, "online": False, "listening": False}
        with contextlib.suppress(OSError):
            backup.unlink()
        return {"ok": True, "version": binary.get("version"), "rolled_back": False,
                "running": bool(state.get("running")),
                "online": bool(state.get("online")), "listening": bool(state.get("listening"))}
    except Exception as exc:
        with contextlib.suppress(Exception):
            if _status().get("running"):
                _stop_running()
        rollback_error: Exception | None = None
        try:
            if had_old and replaced and backup.is_file():
                _replace_with_retry(backup, _EXECUTABLE)
            elif not had_old and replaced:
                with contextlib.suppress(OSError):
                    _EXECUTABLE.unlink()
            if had_old:
                _install_autostart()
                _start()
                _wait_for_stable_start(
                    str(previous_state.get("version") or ""),
                    require_online=bool(previous_state.get("online")),
                    require_listening=bool(previous_state.get("listening")),
                )
        except Exception as rollback_exc:
            rollback_error = rollback_exc
        if rollback_error is not None:
            raise RuntimeError("GAnet 网络组件安装失败，且原版本恢复未通过健康检查") \
                from rollback_error
        raise RuntimeError("GAnet 网络组件安装失败，已恢复原版本") from exc
    finally:
        with contextlib.suppress(OSError):
            staged.unlink()
