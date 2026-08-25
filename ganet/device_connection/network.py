"""Device network environment, enrollment, lifecycle, and SSH setup."""
from __future__ import annotations

import sys as _module_sys

# ---- environment and persisted network state ----

import contextlib
import getpass
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from typing import Any

BASE = os.environ.get("GA_NET_BASE", "https://ganet.gaagent.ai").rstrip("/")
AUTH_BASE = os.environ.get("GA_AUTH_URL", "https://auth.gaagent.ai").rstrip("/")
PROVISION_BASE = BASE + "/provision"
_IS_WIN = sys.platform == "win32"
_RECEIPT_DIR = os.path.join(os.path.expanduser("~"), ".genericagent", "ganet")
_CONFIG_PATH = os.path.join(_RECEIPT_DIR, "config.json")
_RECEIPT_PATH = os.path.join(_RECEIPT_DIR, "mesh_receipt.json")
_SETUP_LOG_PATH = os.path.join(_RECEIPT_DIR, "setup-elevated.log")
DEFAULT_SSH_PORT = 48222
_SIDECAR_ROOT = os.environ.get(
    "GANET_SIDECAR_DIR",
    os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")),
                 "GenericAgent", "GAnet"),
)
_SIDECAR_EXE = os.environ.get("GANET_SIDECAR_EXE", os.path.join(_SIDECAR_ROOT, "ganet-sidecar.exe"))
_SIDECAR_SOURCE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "sidecar",
                                               "ganet", "ganet-sidecar.exe"))


def _reset_setup_log() -> None:
    os.makedirs(_RECEIPT_DIR, exist_ok=True)
    with open(_SETUP_LOG_PATH, "w", encoding="utf-8") as fh:
        fh.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] setup start pid={os.getpid()}\n")


def _setup_log(line: str) -> None:
    with contextlib.suppress(OSError):
        os.makedirs(_RECEIPT_DIR, exist_ok=True)
        with open(_SETUP_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(f"[{time.strftime('%H:%M:%S')}] {line}\n")


def find_tailscale() -> str | None:
    """Return a local Tailscale CLI path without changing the computer."""
    windows_roots = tuple(filter(None, (
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramW6432"),
        os.environ.get("LOCALAPPDATA"),
    ))) if _IS_WIN else ()
    candidates = (
        os.environ.get("GA_TAILSCALE"),
        shutil.which("tailscale"),
        *(os.path.join(root, "Tailscale", "tailscale.exe") for root in windows_roots),
        "/usr/bin/tailscale",
        "/usr/local/bin/tailscale",
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
    )
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate
    return None


def default_hostname() -> str:
    raw = socket.gethostname().split(".")[0]
    name = re.sub(r"[^a-z0-9-]+", "-", raw.lower()).strip("-")
    if name:
        return name
    # Non-ASCII hostnames (common on localized Windows) sanitize to empty; derive a
    # stable per-machine suffix so several such computers do not all show as "ga-pc".
    suffix = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8] if raw else ""
    return f"ga-pc-{suffix}" if suffix else "ga-pc"


def device_id() -> str:
    """Return this installation's stable opaque identity; hostname is display only."""
    config = load_config() or {}
    value = config.get("device_id")
    if isinstance(value, str) and value.startswith("dev_"):
        return value
    value = "dev_" + uuid.uuid4().hex
    save_config(device_id=value)
    return value


def _valid_ed25519_host_key(value: object) -> str | None:
    """Return the normalized ``ssh-ed25519 <base64>`` key, dropping any comment.

    ``ssh-keygen`` always appends a comment field to ``*.pub`` files, so the real
    host key line has three whitespace-separated fields.  Pin only the type and
    base64 body so the value stays stable regardless of the trailing comment.
    """
    if not isinstance(value, str):
        return None
    line = next((candidate for candidate in value.splitlines() if candidate.strip()), "")
    parts = line.split()
    if len(parts) >= 2 and parts[0] == "ssh-ed25519" and re.fullmatch(r"[A-Za-z0-9+/]+={0,3}", parts[1]):
        return parts[0] + " " + parts[1]
    return None


def _sidecar_host_key_pub_path() -> str:
    return os.path.join(_SIDECAR_ROOT, "state", "ssh_host_ed25519_key.pub")


def _read_sidecar_host_key() -> str | None:
    """Read the embedded SSH host public key the sidecar mirrors beside its state."""
    with contextlib.suppress(OSError):
        value = _valid_ed25519_host_key(
            open(_sidecar_host_key_pub_path(), encoding="utf-8").read())
        if value:
            return value
    return None


def _cache_sidecar_host_key() -> str:
    """Have the sidecar create its host key now and remember the public half.

    Enrollment sends the host key to the control plane before the sidecar's
    first ``run``, so setup must ask the binary to generate it up front.
    """
    result = _run([_SIDECAR_EXE, "host-key"], timeout=20)
    payload: dict[str, Any] = {}
    with contextlib.suppress(json.JSONDecodeError):
        value = json.loads(result.stdout or "{}")
        if isinstance(value, dict):
            payload = value
    key = _valid_ed25519_host_key(payload.get("hostKey"))
    if result.returncode or not key:
        detail = str(payload.get("error") or result.stderr or "").strip()
        raise RuntimeError("生成 GAnet 内嵌 SSH 主机密钥失败" + (f"：{detail[:200]}" if detail else ""))
    config = load_config() or {}
    ssh = dict(config.get("ssh") or {})
    ssh["host_public_key"] = key
    save_config(ssh=ssh)
    return key


def ssh_host_key() -> str:
    """Return the embedded SSH service's Ed25519 host public key for mobile pinning."""
    config = load_config() or {}
    cached = _valid_ed25519_host_key((config.get("ssh") or {}).get("host_public_key"))
    if cached:
        return cached
    value = _read_sidecar_host_key()
    if value:
        return value
    raise RuntimeError("未找到 GAnet 内嵌 SSH 主机公钥；请先完成设备互联配置")


def local_device_metadata() -> dict[str, Any]:
    if sys.platform == "win32":
        platform, model = "windows", "Windows PC"
    elif sys.platform == "darwin":
        platform, model = "macos", "Mac"
    else:
        platform, model = "linux", "Linux PC"
    config = load_config() or {}
    return {"deviceId": device_id(), "displayName": default_hostname(),
            "meshHostname": default_hostname(), "kind": "computer",
            "platform": platform, "model": model, "sshUsername": getpass.getuser(),
            "sshPort": int((config.get("ssh") or {}).get("port", 48222)),
            "sshHostKey": ssh_host_key()}


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                              encoding="utf-8", errors="replace")
    except Exception as exc:  # probing must not crash user commands
        return subprocess.CompletedProcess(cmd, 127, "", str(exc))


def _json_probe(cmd: list[str], timeout: int) -> tuple[bool, dict[str, Any]]:
    """Return (responded, payload). A timeout means the local agent is unhealthy,
    which must stay distinguishable from a healthy agent reporting "offline"."""
    result = _run(cmd, timeout)
    if result.returncode:
        return False, {}
    with contextlib.suppress(json.JSONDecodeError):
        value = json.loads(result.stdout or "{}")
        if isinstance(value, dict):
            return True, value
    return False, {}


class SystemTailscaleProvider:
    name = "system-tailscale"
    # A healthy local tailscaled answers its socket in milliseconds; anything
    # slower is an unresponsive agent, not a slow network. Keep the probe short
    # so the user center never blocks on a wedged service.
    probe_seconds = 5

    def __init__(self, executable: str | None = None):
        self.executable = executable or find_tailscale()

    def binary_ok(self) -> bool:
        return bool(self.executable and os.path.isfile(self.executable))

    def _prefs(self) -> tuple[bool, dict[str, Any]]:
        if not self.binary_ok():
            return False, {}
        return _json_probe([self.executable, "debug", "prefs"], self.probe_seconds)

    def status(self) -> dict[str, Any]:
        responded, prefs = self._prefs()
        # A wedged agent would time out on every probe; one is enough to know.
        detail = (_json_probe([self.executable, "status", "--json"], self.probe_seconds)[1]
                  if responded else {})
        self_node = detail.get("Self") if isinstance(detail.get("Self"), dict) else {}
        ips = self_node.get("TailscaleIPs") if isinstance(self_node, dict) else []
        control_url = str(prefs.get("ControlURL") or "").rstrip("/")
        # CorpDNS is Tailscale's preference for accepting control-plane DNS.
        accepts_dns = bool(prefs.get("CorpDNS", False))
        return {
            "responsive": responded,
            "online": detail.get("BackendState") == "Running" and not prefs.get("LoggedOut", False),
            "logged_out": bool(prefs.get("LoggedOut", False)),
            "ip": ips[0] if isinstance(ips, list) and ips else None,
            "control_url": control_url or None,
            "on_ga_control": control_url == BASE,
            "accepts_dns": accepts_dns,
        }

    def join(self, control_url: str, enrollment_grant: str, hostname: str,
             apply_initial_network_defaults: bool = False) -> None:
        if not self.binary_ok():
            raise RuntimeError("未找到 tailscale 客户端")
        cmd = [self.executable, "login", "--login-server", control_url,
               "--auth-key", enrollment_grant, "--hostname", hostname]
        if apply_initial_network_defaults:
            # Fresh Tailscale installs default to accepting DNS and advertised routes.
            # GAnet needs neither, so specify both at first join to prevent changing
            # normal name resolution or routing while entering the control plane.
            cmd += ["--accept-dns=false", "--accept-routes=false"]
        result = _run(cmd, timeout=120)
        if result.returncode:
            raise RuntimeError(f"加入私有网络失败：{(result.stderr or result.stdout)[:300]}")

    def leave(self) -> None:
        if not self.binary_ok():
            raise RuntimeError("未找到 tailscale 客户端")
        result = _run([self.executable, "logout"], timeout=60)
        if result.returncode:
            raise RuntimeError(f"退出私有网络失败：{(result.stderr or result.stdout)[:240]}")


class WindowsTsnetSidecarProvider:
    name = "embedded-tsnet"
    probe_seconds = 5

    def __init__(self, executable: str | None = None):
        self.executable = executable or _SIDECAR_EXE

    def binary_ok(self) -> bool:
        return bool(self.executable and os.path.isfile(self.executable))

    def available(self) -> bool:
        return self.binary_ok()

    def status(self) -> dict[str, Any]:
        if not self.binary_ok():
            return {"responsive": False, "online": False, "logged_out": True,
                    "ip": None, "control_url": BASE, "on_ga_control": False,
                    "accepts_dns": False, "installed": False}
        responded, detail = _json_probe([self.executable, "status"], self.probe_seconds)
        online = bool(detail.get("running") and detail.get("online"))
        return {"responsive": responded, "online": online,
                "logged_out": not bool(detail.get("enrolled")),
                "ip": detail.get("ip"), "control_url": BASE,
                "on_ga_control": bool(detail.get("controlMatch")), "accepts_dns": False,
                "installed": True, "running": bool(detail.get("running")),
                "enrolled": bool(detail.get("enrolled")),
                "listening": bool(detail.get("listening")),
                "ssh_loopback": bool(detail.get("loopbackSsh")),
                "ssh_host_key": detail.get("sshHostKey"),
                "authorized_keys": bool(detail.get("authorizedKeys")),
                "version": detail.get("version"),
                "protocol_version": detail.get("protocolVersion"),
                "ssh_port": detail.get("sshPort"), "pid": detail.get("pid"),
                "error_category": detail.get("errorCategory")}

    def join(self, control_url: str, enrollment_grant: str, hostname: str,
             apply_initial_network_defaults: bool = False) -> None:
        del apply_initial_network_defaults
        if not self.binary_ok():
            raise RuntimeError("未安装 GAnet 网络组件；请先完成组件准备")
        state = self.status()
        if state.get("online"):
            return
        creationflags = 0x08000008 if _IS_WIN else 0
        config = load_config() or {}
        try:
            ssh_port = int((config.get("ssh") or {}).get("port", DEFAULT_SSH_PORT))
        except (TypeError, ValueError):
            ssh_port = DEFAULT_SSH_PORT
        process = subprocess.Popen(
            [self.executable, "run", "--control-url", control_url,
             "--hostname", hostname, "--ssh-port", str(ssh_port),
             "--auth-key-stdin"],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            text=True, creationflags=creationflags, close_fds=True,
        )
        assert process.stdin is not None
        process.stdin.write(enrollment_grant)
        process.stdin.close()
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            state = self.status()
            if state.get("online") and state.get("ip"):
                result = _run([self.executable, "autostart", "install"], timeout=30)
                if result.returncode:
                    raise RuntimeError("GAnet sidecar 已入网，但登录自启动配置失败")
                return
            if process.poll() is not None:
                raise RuntimeError("GAnet sidecar 启动失败；请查看本机脱敏日志")
            time.sleep(1)
        with contextlib.suppress(Exception):
            process.terminate()
        raise RuntimeError("GAnet sidecar 入网超时")

    def leave(self) -> None:
        state = self.status()
        pid = state.get("pid")
        if pid and _IS_WIN:
            _run(["taskkill", "/PID", str(pid), "/T"], timeout=15)
        state_dir = os.path.join(_SIDECAR_ROOT, "state")
        shutil.rmtree(state_dir, ignore_errors=True)


def get_provider():
    if _IS_WIN and os.environ.get("GANET_USE_SYSTEM_TAILSCALE") != "1":
        return WindowsTsnetSidecarProvider()
    return SystemTailscaleProvider()


def load_config() -> dict[str, Any] | None:
    try:
        with open(_CONFIG_PATH, encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def save_config(**fields: Any) -> None:
    config = load_config() or {"schema": 1}
    config.update(fields)
    config["updated_at"] = int(time.time())
    os.makedirs(_RECEIPT_DIR, exist_ok=True)
    tmp = _CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(config, fh, ensure_ascii=False, indent=2)
    with contextlib.suppress(OSError):
        os.chmod(tmp, 0o600)
    os.replace(tmp, _CONFIG_PATH)


def initial_network_defaults_pending() -> bool:
    config = load_config() or {}
    return bool((config.get("tailscale") or {}).get("initial_defaults_pending"))


def set_initial_network_defaults_pending(pending: bool) -> None:
    config = load_config() or {}
    tailscale = dict(config.get("tailscale") or {})
    tailscale.update(installed_by_ganet=True, initial_defaults_pending=bool(pending))
    save_config(tailscale=tailscale)


def load_receipt() -> dict[str, Any] | None:
    try:
        with open(_RECEIPT_PATH, encoding="utf-8") as fh:
            value = json.load(fh)
        return value if isinstance(value, dict) else None
    except (OSError, json.JSONDecodeError):
        return None


def save_receipt(**fields: Any) -> None:
    receipt = load_receipt() or {"schema": 1}
    receipt.update(fields)
    receipt["updated_at"] = int(time.time())
    os.makedirs(_RECEIPT_DIR, exist_ok=True)
    tmp = _RECEIPT_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(receipt, fh, ensure_ascii=False, indent=2)
    with contextlib.suppress(OSError):
        os.chmod(tmp, 0o600)
    os.replace(tmp, _RECEIPT_PATH)


def clear_receipt() -> bool:
    try:
        os.remove(_RECEIPT_PATH)
        return True
    except FileNotFoundError:
        return False


def managed_authorized_keys_path() -> Path:
    """Return the GAnet-owned authorization file the embedded SSH service reads."""
    return Path(_RECEIPT_DIR) / "authorized_keys"


def _managed_keys_acl_ok() -> bool:
    try:
        from . import pairing
    except ImportError:
        import pairing
    return pairing.authorized_keys_permissions_ok(managed_authorized_keys_path())


def _normalize_managed_keys_acl() -> None:
    try:
        from . import pairing
    except ImportError:
        import pairing
    pairing.ensure_authorized_keys_permissions(managed_authorized_keys_path())


def _port_listening(port: int) -> bool:
    for host in ("127.0.0.1", "::1"):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            with contextlib.suppress(OSError):
                sock.connect((host, port))
                return True
    return False


def _save_ssh_probe(result: dict[str, Any]) -> dict[str, Any]:
    """Persist only an outcome; the one-shot test key is never retained."""
    value = {"ok": bool(result.get("ok")), "detail": str(result.get("detail") or ""),
             "checked_at": int(time.time())}
    config = load_config() or {}
    config["ssh_probe"] = value
    save_config(**config)
    return value


def ssh_device_probe(port: int | None = None) -> dict[str, Any]:
    """Temporarily emulate a paired phone's SSH public-key login.

    The private key is created in a fresh temporary directory and removed in all
    cases. Its matching public key is added only for the duration of the request,
    then removed exactly again. The embedded SSH service accepts the same
    authentication path over loopback that the phone uses over the tailnet, so
    a loopback login proves the phone-facing auth chain end to end.
    """
    config = load_config() or {}
    if port is None:
        try:
            port = int((config.get("ssh") or {}).get("port", DEFAULT_SSH_PORT))
        except (TypeError, ValueError):
            port = DEFAULT_SSH_PORT
    provider = get_provider()
    runtime = provider.status() if provider.binary_ok() else {}
    host = ("127.0.0.1" if provider.name == "embedded-tsnet"
            else runtime.get("ip"))
    if provider.name == "embedded-tsnet":
        if not runtime.get("ssh_loopback"):
            return _save_ssh_probe({"ok": False,
                                    "detail": "GAnet 内嵌 SSH 回环监听未就绪，无法模拟手机请求"})
        if not (runtime.get("online") and runtime.get("ip") and runtime.get("listening")):
            return _save_ssh_probe({"ok": False,
                                    "detail": "GAnet sidecar 尚未在线监听，无法模拟手机请求"})
    ssh = shutil.which("ssh")
    keygen = shutil.which("ssh-keygen")
    if not isinstance(host, str) or not host:
        return _save_ssh_probe({"ok": False, "detail": "当前未获得本机 Tailnet 地址，无法模拟手机请求"})
    if not ssh or not keygen:
        return _save_ssh_probe({"ok": False, "detail": "缺少 OpenSSH Client，无法模拟手机请求"})
    try:
        from . import pairing
    except ImportError:
        import pairing
    temp_dir = tempfile.mkdtemp(prefix="ga-ssh-probe-")
    private_key = os.path.join(temp_dir, "phone_test_key")
    inserted = False
    public_key = ""
    try:
        generated = _run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", private_key], timeout=30)
        if generated.returncode:
            return _save_ssh_probe({"ok": False, "detail": "无法生成临时 SSH 测试密钥"})
        public_key = Path(private_key + ".pub").read_text(encoding="utf-8").strip()
        _, inserted = pairing.append_public_key(public_key)
        known_hosts = "NUL" if _IS_WIN else "/dev/null"
        command = [ssh, "-i", private_key, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
                   "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={known_hosts}",
                   "-o", "GlobalKnownHostsFile=none", "-o", "LogLevel=ERROR",
                   "-o", "ConnectTimeout=12", "-p", str(port), f"{getpass.getuser()}@{host}", "exit"]
        completed = _run(command, timeout=25)
        if completed.returncode == 0:
            detail = ("GAnet sidecar Tailnet 监听正常，内嵌 SSH 公钥认证通过"
                      if provider.name == "embedded-tsnet"
                      else "模拟手机 SSH 公钥认证通过")
            return _save_ssh_probe({"ok": True, "detail": detail})
        detail = (completed.stderr or completed.stdout).strip().replace("\n", " ")
        return _save_ssh_probe({"ok": False, "detail": "模拟手机 SSH 公钥认证失败" + (f"：{detail[:180]}" if detail else "")})
    except Exception as exc:
        return _save_ssh_probe({"ok": False, "detail": f"模拟手机请求未完成：{type(exc).__name__}"})
    finally:
        if inserted and public_key:
            with contextlib.suppress(Exception):
                pairing.remove_public_key(public_key)
        shutil.rmtree(temp_dir, ignore_errors=True)


def check_env() -> dict[str, Any]:
    provider = get_provider()
    runtime = provider.status() if provider.binary_ok() else {}
    receipt = load_receipt() or {}
    config = load_config() or {}
    try:
        port = int((config.get("ssh") or {}).get("port", DEFAULT_SSH_PORT))
    except (TypeError, ValueError):
        port = DEFAULT_SSH_PORT
    embedded = provider.name == "embedded-tsnet"
    ssh_probe = (config.get("ssh_probe") if isinstance(config.get("ssh_probe"), dict) else {})
    provider_available = provider.available() if hasattr(provider, "available") else provider.binary_ok()
    component = {"version_state": "unknown", "reason": ""}
    if embedded:
        with contextlib.suppress(Exception):
            from . import sidecar_manager
            component = sidecar_manager.inspect()
    version_state = str(component.get("version_state") or "unknown")
    plugin = {"version_state": "unknown", "reason": "", "ga_hint": ""}
    plugin_version_state = "unknown"
    host_key_ok = bool(_valid_ed25519_host_key(
        ((config.get("ssh") or {}).get("host_public_key"))) or _read_sidecar_host_key())
    checks = {
        "network_component": provider.binary_ok(),
        "network_provider": provider_available,
        "qr_component": importlib.util.find_spec("qrcode") is not None,
        "screenshot_media": importlib.util.find_spec("PIL") is not None,
        "ga_profile": bool(runtime.get("online") and runtime.get("on_ga_control")),
        "ssh_service": bool(runtime.get("running")),
        "ssh_listening": bool(runtime.get("listening")),
        "ssh_loopback": bool(runtime.get("ssh_loopback")),
        "host_key": host_key_ok,
        "managed_keys": managed_authorized_keys_path().is_file(),
        "managed_keys_acl": _managed_keys_acl_ok(),
        "ssh_probe": ssh_probe.get("ok") if isinstance(ssh_probe.get("ok"), bool) else None,
        "listening": _port_listening(port),
    }
    chain = [
        {"key": "base", "label": "基础环境", "ok": checks["network_provider"] and checks["qr_component"]
         and checks["screenshot_media"] and version_state != "required",
         "level": "warning" if "available" in (version_state, plugin_version_state) else
                  ("error" if version_state == "required" else "ok"),
         "detail": next((detail for ok, detail in (
             (checks["network_provider"], "未找到 GAnet 网络组件"),
             (version_state != "required", str(component.get("reason") or "GAnet 网络组件需要更新")),
             (checks["qr_component"], "缺少二维码组件"),
             (checks["screenshot_media"], "缺少电脑截图组件"),
         ) if not ok), str(plugin.get("reason") or component.get("reason") or "")
         if "available" in (plugin_version_state, version_state) else "")},
        {"key": "network", "label": "GAnet 控制面", "ok": checks["ga_profile"],
         "detail": "" if checks["ga_profile"] else
         ("GAnet 网络组件无响应，请让 GA 修复设备互联" if runtime.get("responsive") is False
          else "尚未连接 GAnet 控制面")},
        {"key": "ssh", "label": "SSH 服务", "ok": checks["ssh_service"] and checks["ssh_listening"]
         and checks["ssh_loopback"] and checks["listening"],
         "detail": next((detail for ok, detail in (
             (checks["ssh_service"], "GAnet 网络组件未运行"),
             (checks["ssh_listening"], "私有网络 SSH 监听未就绪"),
             (checks["ssh_loopback"], "本机回环 SSH 监听未就绪"),
             (checks["listening"], f"本机端口 {port} 未监听"),
         ) if not ok), "")},
        {"key": "access", "label": "设备访问", "ok": checks["managed_keys"] and checks["managed_keys_acl"]
         and checks["host_key"],
         "detail": next((detail for ok, detail in (
             (checks["managed_keys"], "未创建 GAnet 配对公钥文件"),
             (checks["managed_keys_acl"], "GAnet 授权文件权限需要修复"),
             (checks["host_key"], "GAnet 内嵌 SSH 主机密钥未生成"),
         ) if not ok), "")},
    ]
    if not checks["network_provider"] or not checks["qr_component"] or not checks["screenshot_media"]:
        status, hint = "need_install", "设备互联环境尚未配置"
    elif version_state == "required":
        status, hint = "need_repair", "GAnet 网络组件需要更新"
    elif all(value for key, value in checks.items() if key != "ssh_probe"):
        status, hint = "ok", "设备互联环境已就绪"
    else:
        status, hint = "need_repair", "设备互联环境需要修复"
    return {"status": status, "hint": hint, "provider": provider.name,
            "runtime": runtime, "component": component, "version_state": version_state,
            "plugin": plugin, "plugin_version_state": plugin_version_state,
            "receipt": receipt, "checks": checks, "chain": chain,
            "ssh_probe": ssh_probe, "ssh_port": port}


def environment_cli(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("check", "doctor", "ssh-probe"):
        print("用法: python -m ganet.device_connection.network [check|ssh-probe] [--json]")
        return 2
    if argv and argv[0] == "ssh-probe":
        report = ssh_device_probe()
        if "--json" in argv:
            print(json.dumps(report, ensure_ascii=False))
        else:
            print(("✓ " if report["ok"] else "✗ ") + report["detail"])
        return 0 if report["ok"] else 1
    report = check_env()
    if "--json" in argv:
        print(json.dumps(report, ensure_ascii=False))
    else:
        runtime = report["runtime"]
        print(f"{'✓' if report['status'] == 'ok' else '!'} {report['status']}：{report['hint']}")
        print(f"  provider={report['provider']}  DNS接管={'开' if runtime.get('accepts_dns') else '关'}")
        print(f"  网络={'在线' if runtime.get('online') else '未在线'}  控制面={runtime.get('control_url') or '无'}")
    return 0 if report["status"] == "ok" else 1

# Preserve the former module-shaped references while keeping one implementation file.
env = _module_sys.modules[__name__]

# ---- enrollment ----

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


_HTTP_TIMEOUT = 30


def _request_enrollment(token: str, hostname: str) -> dict:
    metadata = env.local_device_metadata()
    metadata["displayName"] = hostname
    metadata["meshHostname"] = hostname
    data = json.dumps(metadata).encode("utf-8")
    request = urllib.request.Request(
        env.PROVISION_BASE + "/enroll_pc", data=data, method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"设备登记失败（HTTP {exc.code}）") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"无法连接设备登记服务：{exc.reason}") from exc
    if not isinstance(payload, dict) or not payload.get("ok"):
        raise RuntimeError("设备登记服务返回异常")
    return payload


def enroll(token: str, hostname: str | None = None, *, apply_initial_network_defaults: bool = False) -> dict:
    """Request a one-time grant, join with the selected network policy, and save receipt."""
    hostname = hostname or os.environ.get("GA_PC_HOSTNAME") or env.default_hostname()
    provider = env.get_provider()
    provider_available = provider.available() if hasattr(provider, "available") else provider.binary_ok()
    if not provider_available:
        raise RuntimeError("未找到 GAnet 网络组件；请先运行 `python -m ganet.device_connection.network`")
    response = _request_enrollment(token, hostname)
    grant = response.get("enrollmentGrant") or response.get("preauthkey")
    control_url = response.get("controlUrl")
    if not isinstance(grant, str) or not grant or not isinstance(control_url, str) or not control_url:
        raise RuntimeError("设备登记服务未返回有效入网授权")
    receipt = {"uid": response.get("uid"),
               "device_id": response.get("deviceId") or env.device_id(),
               "hostname": response.get("hostname") or hostname,
               "control_url": control_url, "provider": provider.name,
               "enrollment_id": response.get("enrollmentId")}
    # Persist the recovery identity before changing the active network profile. If
    # joining fails, the next run can still identify the attempted enrollment.
    try:
        env.save_receipt(**receipt, enrollment_state="joining")
    except OSError as exc:
        raise RuntimeError("无法保存本机入网状态；请检查磁盘和用户目录权限后重试") from exc
    provider.join(control_url, grant, hostname, apply_initial_network_defaults=apply_initial_network_defaults)
    try:
        env.save_receipt(**receipt, enrollment_state="joined")
    except OSError as exc:
        raise RuntimeError("已加入 GA 私有网络，但本机状态保存失败；请检查磁盘和用户目录权限后重试") from exc
    return {"hostname": response.get("hostname") or hostname, "control_url": control_url,
            "ip": provider.status().get("ip")}


# ---- login/logout network lifecycle ----

_SETUP_HINT = "运行 `python -m ganet.device_connection.network` 配置 GAnet 环境"


def on_login(identity: dict | None, token: str | None) -> str:
    """Join the GA mesh after a successful GAuth login; never invalidate login itself."""
    try:
        ident = identity
        if not ident or not ident.get("valid") or not token:
            return "• GAnet：无有效登录态，未加入私有网络"
        if (ident.get("base_url") or "").rstrip("/") != env.AUTH_BASE:
            return "• GAnet：当前登录域不是组网认证域，未自动加入私有网络"
        provider = env.get_provider()
        if not provider.binary_ok():
            return "• GAnet：未找到网络组件；" + _SETUP_HINT
        state = provider.status()
        receipt = env.load_receipt() or {}
        owner_changed = receipt.get("uid") is not None and receipt.get("uid") != ident.get("userId")
        if state.get("online") and state.get("on_ga_control") and not owner_changed:
            return f"✓ GAnet：已在 GA 私有网络（{state.get('ip') or 'IP 待查询'}）"
        if state.get("online") and not state.get("on_ga_control"):
            return "• GAnet：当前系统网络客户端连接着其他网络；请先运行设备互联配置并确认网络切换"
        apply_defaults = env.initial_network_defaults_pending()
        joined = enroll(token, apply_initial_network_defaults=apply_defaults)
        if apply_defaults:
            env.set_initial_network_defaults_pending(False)
        return f"✓ GAnet：已加入 GA 私有网络（{joined.get('ip') or 'IP 待查询'}）"
    except Exception as exc:  # mesh failure must not turn a valid login into a failure
        return f"• GAnet：登录成功，但未加入私有网络：{exc}"


def on_logout() -> str:
    """Leave only the GA control-plane profile; user SSH credentials stay untouched."""
    try:
        provider = env.get_provider()
        if not provider.binary_ok():
            return "• GAnet：未找到网络组件，跳过退出私有网络"
        state = provider.status()
        if not state.get("on_ga_control"):
            return "• GAnet：当前网络身份不属于 GA，未执行退出"
        if state.get("logged_out"):
            return "• GAnet：已退出 GA 私有网络"
        provider.leave()
        return "✓ GAnet：已退出 GA 私有网络（未修改 SSH 密钥或系统 DNS）"
    except Exception as exc:
        return f"• GAnet：退出私有网络失败：{exc}"


def status_text() -> str:
    report = env.check_env()
    runtime = report["runtime"]
    receipt = report["receipt"]
    return "\n".join([
        f"环境：{report['status']}（{report['hint']}）",
        f"网络：{'在线' if runtime.get('online') else '未在线'}"
        + ("，GA 控制面" if runtime.get("on_ga_control") else ""),
        f"DNS 接管：{'开' if runtime.get('accepts_dns') else '关'}",
        f"设备回执：{receipt.get('hostname')} / uid={receipt.get('uid')}" if receipt else "设备回执：无",
    ])

lifecycle = _module_sys.modules[__name__]

# ---- device retirement ----

import argparse
import json
import os
import sys
import urllib.error
import urllib.request



def _retire_remote(token: str, hostname: str) -> None:
    request = urllib.request.Request(
        env.PROVISION_BASE + "/devices/" + hostname, method="DELETE",
        headers={"Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"远端注销失败（HTTP {exc.code}）") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"无法连接设备登记服务：{exc.reason}") from exc
    if isinstance(payload, dict) and payload.get("ok") is False:
        raise RuntimeError("远端注销服务返回异常")


def retire(token: str, hostname: str) -> list[str]:
    """Remove the remote node, leave only GA's profile, then clear its receipt."""
    _retire_remote(token, hostname)
    messages = [f"✓ 已注销远端设备：{hostname}"]
    provider = env.get_provider()
    state = provider.status() if provider.binary_ok() else {}
    if state.get("on_ga_control") and not state.get("logged_out"):
        provider.leave()
        messages.append("✓ 已退出 GA 私有网络")
    elif provider.binary_ok():
        messages.append("• 当前网络身份不属于 GA，未执行退出")
    env.clear_receipt()
    messages.append("✓ 已清除本机 GAnet 网络回执（未修改 SSH 密钥或系统 DNS）")
    return messages


# ---- local SSH environment setup ----
#
# The embedded SSH service lives inside the sidecar and everything it needs is
# user-owned: the authorization file, the host key, and the listeners (tsnet
# plus loopback). Setup therefore never elevates, never touches sshd_config,
# and never writes firewall rules.

import argparse
import contextlib
import os
import socket
import sys
from pathlib import Path


for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(Exception):
        _stream.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_PORT = 48222


def _port_is_free(port: int) -> bool:
    """Require the port to be free on every local address family the sidecar may bind."""
    sockets = [(socket.AF_INET, ("0.0.0.0", port))]
    if socket.has_ipv6:
        sockets.append((socket.AF_INET6, ("::", port)))
    for family, address in sockets:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                with contextlib.suppress(OSError):
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            try:
                sock.bind(address)
            except OSError:
                return False
    return True


def _validate_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("端口必须是整数") from exc
    if not 1024 <= port <= 65535:
        raise argparse.ArgumentTypeError("端口必须在 1024-65535")
    return port


def _apply_step(phase: str, action):
    _setup_log(f"{phase} begin")
    try:
        result = action()
    except Exception as exc:
        _setup_log(f"{phase} FAIL: {exc}")
        raise RuntimeError(f"{phase}|{exc}") from exc
    _setup_log(f"{phase} ok")
    return result


def _apply(port: int) -> None:
    """Prepare the user-owned embedded SSH environment; no elevation involved."""
    _reset_setup_log()
    _setup_log(f"port={port}")
    report = env.check_env()
    if not report["checks"].get("network_component"):
        raise RuntimeError("preflight|请先完成系统组件安装：GAnet 网络组件")
    _apply_step("managed_keys_acl", _normalize_managed_keys_acl)
    _apply_step("host_key", _cache_sidecar_host_key)
    _setup_log("setup done")


def _setup_failure(message: str, *, code: int = 1) -> dict[str, Any]:
    phase, separator, detail = message.partition("|")
    if not separator:
        phase, detail = "configuration", message
    detail = detail.strip() or "系统配置未完成"
    if os.path.isfile(_SETUP_LOG_PATH) and _SETUP_LOG_PATH not in detail:
        detail = f"{detail} (日志: {_SETUP_LOG_PATH})"
    return {"ok": False, "phase": phase, "code": code, "message": detail}


def _port_belongs_to_ganet(port: int) -> bool:
    """Allow repeat configuration when the running sidecar already owns the port."""
    provider = env.get_provider()
    if provider.name != "embedded-tsnet" or not provider.binary_ok():
        return False
    state = provider.status()
    return bool(state.get("running") and state.get("ssh_port") == port)


def _save_setup_config(port: int) -> None:
    config = env.load_config() or {}
    ssh = dict(config.get("ssh") or {})
    ssh.update(port=port, tailnet_only=True)
    env.save_config(ssh=ssh, setup_managed=True)


def apply_confirmed(port: int) -> dict[str, Any]:
    """Apply managed setup and preserve a safe, actionable failure reason."""
    if not _port_is_free(port) and not _port_belongs_to_ganet(port):
        return _setup_failure(f"port_preflight|SSH 端口 {port} 已被其他程序占用", code=2)
    try:
        _apply(port)
    except RuntimeError as exc:
        return _setup_failure(str(exc))
    try:
        _save_setup_config(port)
    except OSError as exc:
        return _setup_failure(f"local_state|配置已完成，但无法保存本机配置：{exc}")
    return {"ok": True}


def setup(port: int) -> int:
    outcome = apply_confirmed(port)
    if not outcome.get("ok"):
        print(f"✗ {outcome['message']}")
        return int(outcome.get("code") or 1)
    print("✓ GAnet 环境已就绪")
    print(f"  SSH：内嵌服务端口 {port}（仅私有网络与本机回环可达，无系统改动）")
    print("  下一步：打开 GAnet 用户中心完成登录与入网")
    return 0


def setup_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="配置 GAnet 私有网络与内嵌 SSH 环境")
    parser.add_argument("command", nargs="?", choices=("check", "doctor"))
    parser.add_argument("--port", type=_validate_port, default=DEFAULT_PORT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.check or args.command:
        return environment_cli([args.command or "check"] + (["--json"] if args.json else []))
    return setup(args.port)


if __name__ == "__main__":
    raise SystemExit(setup_cli())
