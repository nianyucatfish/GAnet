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
_FW_NAMES = ("GenericAgent GAnet SSH", "GA SSH (tailnet only)")


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


def _program_data_dir() -> str:
    return os.environ.get("ProgramData", r"C:\ProgramData")


def _host_key_pub_paths() -> tuple[str, ...]:
    if _IS_WIN:
        return (os.path.join(_program_data_dir(), "ssh", "ssh_host_ed25519_key.pub"),)
    return ("/etc/ssh/ssh_host_ed25519_key.pub",)


def _read_sshd_host_key() -> str | None:
    for path in _host_key_pub_paths():
        with contextlib.suppress(OSError):
            value = _valid_ed25519_host_key(open(path, encoding="utf-8").read())
            if value:
                return value
    return None


def _cache_sshd_host_key() -> str:
    value = _read_sshd_host_key()
    if not value:
        pub_present = False
        for path in _host_key_pub_paths():
            with contextlib.suppress(OSError):
                if open(path, encoding="utf-8").read().strip():
                    pub_present = True
                    break
        if pub_present:
            raise RuntimeError("读取到 sshd Ed25519 主机公钥文件，但内容格式无法识别")
        raise RuntimeError("未找到 sshd Ed25519 主机公钥；请检查 OpenSSH Server 配置")
    config = load_config() or {}
    ssh = dict(config.get("ssh") or {})
    ssh["host_public_key"] = value
    save_config(ssh=ssh)
    return value


def ssh_host_key() -> str:
    """Return this computer's Ed25519 sshd host public key for mobile pinning."""
    config = load_config() or {}
    cached = _valid_ed25519_host_key((config.get("ssh") or {}).get("host_public_key"))
    if cached:
        return cached
    value = _read_sshd_host_key()
    if value:
        return value
    port = int((config.get("ssh") or {}).get("port", DEFAULT_SSH_PORT))
    result = _run(["ssh-keyscan", "-T", "5", "-t", "ed25519", "-p", str(port), "127.0.0.1"],
                  timeout=10)
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "ssh-ed25519":
            return "ssh-ed25519 " + parts[2]
    raise RuntimeError("未找到 sshd Ed25519 主机公钥；请先完成 GAnet SSH 配置")


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


def _sshd_service_ok() -> bool:
    if _IS_WIN:
        result = _run(["powershell", "-NoProfile", "-Command",
                       "(Get-Service sshd -ErrorAction SilentlyContinue).Status"])
        return result.returncode == 0 and result.stdout.strip().lower() == "running"
    return any(_run(["systemctl", "is-active", name], timeout=10).stdout.strip() == "active"
               for name in ("sshd", "ssh"))


def _sshd_executable() -> str | None:
    executable = shutil.which("sshd")
    candidates = [executable] if executable else []
    if _IS_WIN:
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        candidates += [os.path.join(program_files, "OpenSSH", "sshd.exe"),
                       os.path.join(system_root, "System32", "OpenSSH", "sshd.exe")]
    return next((c for c in candidates if c and os.path.isfile(c)), None)


def _sshd_installed(effective: str) -> bool:
    """Whether OpenSSH Server is installed, independent of its first start.

    Windows only generates ``sshd_config`` and host keys when the sshd service
    first starts, so an installed-but-never-started sshd has a binary yet no
    readable configuration.  Judging installation by the effective config alone
    deadlocks setup: install is skipped (the component exists) while apply's
    preflight keeps demanding an "installation" that would change nothing.
    """
    return bool(effective) or _sshd_executable() is not None


def _sshd_effective_config() -> str:
    executable = _sshd_executable()
    if executable:
        command = [executable, "-T"]
        if _IS_WIN:
            # Match blocks are account-dependent. Inspect the current account's
            # final settings rather than merely finding a global config line.
            command += ["-C", f"user={getpass.getuser()},host=localhost,addr=100.64.0.1"]
        result = _run(command, timeout=20)
        if not result.returncode:
            return result.stdout.lower()
    if _IS_WIN:
        # A standard user can be unable to load sshd host keys for `-T`. The static
        # config is only a fallback; actual effective settings are preferred above.
        config = os.path.join(_program_data_dir(), "ssh", "sshd_config")
        with contextlib.suppress(OSError):
            return open(config, encoding="utf-8", errors="replace").read().lower()
    return ""


def is_windows_administrator() -> bool:
    """Return whether the current account belongs to the built-in Administrators group."""
    if not _IS_WIN:
        return False
    result = _run(["whoami", "/groups"], timeout=15)
    return result.returncode == 0 and "S-1-5-32-544" in result.stdout


def managed_authorized_keys_path() -> Path:
    """Return the current user's independent GAnet authorization file."""
    return Path.home() / ".ssh" / "authorized_keys_ganet"


def _effective_reads_ganet_keys(effective: str) -> bool:
    """Check the AuthorizedKeysFile sshd actually honours, not merely one present.

    ``sshd -T`` resolves a single line, but the static fallback is the whole
    config and may list several.  sshd keeps the first and ignores the rest, so
    a substring search over the file reports success even when GAnet's entry sits
    below an earlier line and never loads.  ``effective`` arrives lowercased.
    """
    for line in effective.splitlines():
        if re.match(r"^\s*match\s+", line):
            break
        found = re.match(r"^\s*authorizedkeysfile\s+(?P<files>.+?)\s*$", line)
        if found:
            return "authorized_keys_ganet" in found.group("files")
    return False


def _windows_administrator_reads_ganet_keys() -> bool:
    """Check the static administrator Match block when ``sshd -T`` is restricted.

    Standard Windows sessions often cannot load sshd host keys for ``-T``.  In
    that case a global text search is insufficient: the administrators Match
    block overrides the global AuthorizedKeysFile setting.
    """
    if not (_IS_WIN and is_windows_administrator()):
        return True
    path = Path(_program_data_dir()) / "ssh" / "sshd_config"
    try:
        config = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    match = re.search(r"(?ims)^\s*Match\s+Group\s+administrators\s*\n(?P<body>.*?)(?=^\s*Match\s|\Z)", config)
    return bool(match and re.search(r"(?im)^\s*AuthorizedKeysFile\s+.*authorized_keys_ganet", match.group("body")))


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


def _windows_firewall_netsh_status(port: int) -> str:
    """Read managed firewall rules through netsh when NetSecurity is restricted.

    ``Get-NetFirewallRule`` may be denied to a standard user on some Windows
    editions.  ``netsh advfirewall`` exposes the same local policy read-only
    on those installations, so use it before claiming the rule is missing.
    """
    readable = False
    for name in _FW_NAMES:
        # Let PowerShell transcode netsh's OEM console output before Python
        # receives it as UTF-8. Direct subprocess capture garbles localized
        # Windows output and would turn a valid Chinese rule into a mismatch.
        escaped_name = name.replace("'", "''")
        command = ("[Console]::OutputEncoding=[Text.UTF8Encoding]::new(); "
                   f"& netsh advfirewall firewall show rule name='{escaped_name}' verbose")
        result = _run(["powershell", "-NoProfile", "-Command", command], timeout=20)
        text = (result.stdout + result.stderr).lower()
        if result.returncode != 0:
            if "access is denied" in text or "access denied" in text:
                return "unconfirmed"
            continue
        readable = True
        if "no rules match" in text or "no rules match the specified criteria" in text:
            continue
        enabled = "yes" in text or "true" in text
        inbound = "inbound" in text or "\ndirection: in" in text
        allow = "allow" in text
        tcp = "tcp" in text
        local_port = str(port) in text
        tailnet = "100.64.0.0/10" in text or "100.64.0.0/255.192.0.0" in text
        # Chinese Windows emits localized Yes / Inbound / Allow values through
        # netsh.  They are readable after the PowerShell UTF-8 bridge above; use
        # the dedicated rule's stable TCP, port, Tailnet source and security mode
        # as an additional compatibility check.
        localized_match = tcp and local_port and tailnet and "notrequired" in text
        return "confirmed" if all((enabled, inbound, allow, tcp, local_port, tailnet)) or localized_match else "mismatch"
    return "mismatch" if readable else "unconfirmed"


def _firewall_status(port: int) -> str:
    """Return ``confirmed``, ``mismatch``, or ``unconfirmed`` for the rule."""
    if _IS_WIN:
        names = ",".join("'%s'" % name.replace("'", "''") for name in _FW_NAMES)
        command = ("try {$r=Get-NetFirewallRule -DisplayName " + names + " -ErrorAction Stop | "
                   "Where-Object {$_.Enabled.ToString() -eq 'True' -and $_.Direction.ToString() -eq 'Inbound' "
                   "-and $_.Action.ToString() -eq 'Allow'} | Select-Object -First 1; "
                   "if(!$r){exit 1}; $p=$r|Get-NetFirewallPortFilter; $a=$r|Get-NetFirewallAddressFilter; "
                   f"if($p.Protocol -ne 'TCP' -or $p.LocalPort -notcontains '{port}' "
                   "-or ($a.RemoteAddress -notcontains '100.64.0.0/10' -and $a.RemoteAddress -notcontains '100.64.0.0/255.192.0.0')){exit 2}} "
                   "catch {exit 3}")
        result = _run(["powershell", "-NoProfile", "-Command", command], timeout=20)
        if result.returncode == 0:
            return "confirmed"
        # The fallback also guards against ambiguous NetSecurity failures,
        # including the standard-user failure observed on Windows 10.
        return _windows_firewall_netsh_status(port)
    if shutil.which("ufw"):
        result = _run(["ufw", "status"], timeout=20)
        text = (result.stdout + result.stderr).lower()
        return "confirmed" if result.returncode == 0 and str(port) in text and "100.64.0.0/10" in text else "mismatch"
    return "mismatch"


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
    then removed exactly again. Embedded tsnet checks its Tailnet listener via
    sidecar status and tests the local OpenSSH authentication path over loopback.
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
    if provider.name == "embedded-tsnet" and not (
            runtime.get("online") and runtime.get("ip") and runtime.get("listening")):
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
            detail = ("GAnet sidecar Tailnet 监听正常，OpenSSH 公钥认证通过"
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
    effective = _sshd_effective_config()
    embedded = provider.name == "embedded-tsnet"
    firewall_status = "not_required" if embedded else _firewall_status(port)
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
    checks = {
        "network_component": provider.binary_ok(),
        "network_provider": provider_available,
        "qr_component": importlib.util.find_spec("qrcode") is not None,
        "screenshot_media": importlib.util.find_spec("PIL") is not None,
        "sftp_subsystem": bool(re.search(r"(?im)^\s*subsystem\s+sftp\s+\S+", effective)),
        "ga_profile": bool(runtime.get("online") and runtime.get("on_ga_control")),
        "sshd_installed": _sshd_installed(effective),
        "sshd_service": _sshd_service_ok(),
        "ssh_port": ("port %d" % port) in effective,
        "managed_keys": _effective_reads_ganet_keys(effective) and _windows_administrator_reads_ganet_keys(),
        "managed_keys_acl": _managed_keys_acl_ok(),
        "firewall": firewall_status in ("confirmed", "not_required"),
        "firewall_status": firewall_status,
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
        {"key": "ssh", "label": "SSH 服务", "ok": checks["sshd_service"] and checks["ssh_port"]
         and checks["sftp_subsystem"] and checks["listening"],
         "detail": next((detail for ok, detail in (
             (checks["sshd_service"], "sshd 服务未运行"),
             (checks["ssh_port"], f"sshd 未配置 GAnet 端口 {port}"),
             (checks["sftp_subsystem"], "sshd 未启用 SFTP 子系统"),
             (checks["listening"], f"本机端口 {port} 未监听"),
         ) if not ok), "")},
        {"key": "access", "label": "设备访问", "ok": checks["managed_keys"] and checks["managed_keys_acl"]
         and checks["firewall_status"] != "mismatch",
         "detail": next((detail for ok, detail in (
             (checks["managed_keys"], "未启用 GAnet 配对公钥文件"),
             (checks["managed_keys_acl"], "GAnet 授权文件权限需要修复"),
             (checks["firewall_status"] != "mismatch", f"Windows 防火墙未允许私有网络访问 TCP {port}"),
         ) if not ok), "")},
    ]
    if not checks["network_provider"] or not checks["qr_component"] or not checks["screenshot_media"] \
            or not checks["sshd_installed"]:
        status, hint = "need_install", "设备互联环境尚未配置"
    elif version_state == "required":
        status, hint = "need_repair", "GAnet 网络组件需要更新"
    elif all(value for key, value in checks.items() if key not in ("firewall", "ssh_probe")) \
            and firewall_status != "mismatch":
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


# ---- local SSH and firewall setup ----

import argparse
import contextlib
import ctypes
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


for _stream in (sys.stdout, sys.stderr):
    with contextlib.suppress(Exception):
        _stream.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_PORT = 48222
# sshd_config(5)的 Port 隐式默认值. 一旦出现任何显式 Port 它就失效, 所以在原本
# 依赖它的机器上必须显式重述, 否则用户原有的 22 端口访问会被静默切断.
_STANDARD_SSH_PORT = 22
_MARK_BEGIN = "# BEGIN GenericAgent GAnet"
_MARK_END = "# END GenericAgent GAnet"
_ADMIN_MARK_BEGIN = "# BEGIN GenericAgent GAnet administrators"
_ADMIN_MARK_END = "# END GenericAgent GAnet administrators"
_FW_NAME = _FW_NAMES[0]
_GANET_KEY_FILE = ".ssh/authorized_keys_ganet"
# sshd_config(5)默认搜索两个文件. 我们的块会写出显式指令并因此顶掉这个隐式默认,
# 所以必须原样带上 authorized_keys2, 否则会静默收窄用户原有的登录路径.
_DEFAULT_KEY_FILES = (".ssh/authorized_keys", ".ssh/authorized_keys2")


def _marked_block_re(begin: str, end: str) -> re.Pattern[str]:
    """Match a marked block whose begin and end each occupy their own line.

    ``_MARK_BEGIN``/``_MARK_END`` are prefixes of the administrators markers, so an
    unanchored non-greedy match would confuse the global block with the admin
    block and corrupt the config on repeat runs.  Requiring end-of-line right
    after each marker keeps the two unambiguous.
    """
    return re.compile(r"(?ms)^[ \t]*" + re.escape(begin) + r"[ \t]*\r?\n.*?^[ \t]*"
                      + re.escape(end) + r"[ \t]*\r?\n?")


_MARKED_BLOCK_RE = _marked_block_re(_MARK_BEGIN, _MARK_END)
_ADMIN_BLOCK_RE = _marked_block_re(_ADMIN_MARK_BEGIN, _ADMIN_MARK_END)


def _setup_run(cmd: list[str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          encoding="utf-8", errors="replace")


def _command_detail(result: subprocess.CompletedProcess[str]) -> str:
    """Condense a failed command's output into one reportable line."""
    text = ((result.stderr or "") + "\n" + (result.stdout or "")).strip()
    joined = " ".join(line.strip() for line in text.splitlines() if line.strip())
    return joined[:300]


def _is_admin() -> bool:
    if not _IS_WIN:
        return bool(hasattr(os, "geteuid") and os.geteuid() == 0)
    with contextlib.suppress(Exception):
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return False


def _port_is_free(port: int) -> bool:
    """Require the port to be free on every local address family sshd may bind."""
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


def _cfg_path() -> Path:
    if _IS_WIN:
        return Path(_program_data_dir()) / "ssh" / "sshd_config"
    return Path("/etc/ssh/sshd_config.d/60-genericagent-ganet.conf")


def _seed_default_sshd_config(path: Path) -> None:
    """Create the initial config for an installed-but-never-started sshd."""
    sshd = _sshd_executable()
    template = Path(sshd).with_name("sshd_config_default") if sshd else None
    if template and template.is_file():
        content = template.read_text(encoding="utf-8", errors="replace")
    else:
        # sshd falls back to built-in defaults for everything else, but SFTP must
        # be declared explicitly or the file-access capability breaks.
        content = "Subsystem\tsftp\tsftp-server.exe\n" if _IS_WIN else \
                  "Subsystem\tsftp\tinternal-sftp\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")


def _harden_host_key_acls() -> None:
    """Leave private host keys readable only by SYSTEM and Administrators.

    ``ssh-keygen -A`` also grants the elevated account that ran it.  sshd runs as
    LocalSystem and refuses to load a private host key any other account can
    read, so the service dies with error 1067 while a foreground run by that same
    account still starts and listens.  Rewrite the whole DACL by SID: replacing
    it also drops such a stray grant, and SIDs keep this locale independent.
    """
    if not _IS_WIN:
        return
    directory = str(Path(_program_data_dir()) / "ssh").replace("'", "''")
    script = ("$ErrorActionPreference='Stop'; "
              "$system=[Security.Principal.SecurityIdentifier]'S-1-5-18'; "
              "$admins=[Security.Principal.SecurityIdentifier]'S-1-5-32-544'; "
              f"Get-ChildItem -LiteralPath '{directory}' -File -ErrorAction SilentlyContinue | "
              "Where-Object {$_.Name -like 'ssh_host_*_key'} | ForEach-Object { "
              "$acl=New-Object Security.AccessControl.FileSecurity; "
              "$acl.SetAccessRuleProtection($true,$false); "
              "$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("
              "$system,'FullControl','Allow'))); "
              "$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule("
              "$admins,'FullControl','Allow'))); "
              # Taking ownership is privileged, so only do it when sshd would
              # actually reject the current owner.
              "$owner=(Get-Acl -LiteralPath $_.FullName).GetOwner("
              "[Security.Principal.SecurityIdentifier]).Value; "
              "if($owner -ne $system.Value -and $owner -ne $admins.Value){$acl.SetOwner($admins)}; "
              "Set-Acl -LiteralPath $_.FullName -AclObject $acl }")
    result = _setup_run(["powershell", "-NoProfile", "-Command", script], timeout=60)
    if result.returncode:
        raise RuntimeError("修复 sshd 主机密钥权限失败："
                           + (_command_detail(result) or "Set-Acl 返回非零"))


def _ensure_sshd_baseline() -> bool:
    """Provide what a first sshd service start would have generated.

    Windows creates ``%ProgramData%\\ssh\\sshd_config`` and the host keys only on
    the sshd service's first start.  Configuring on top of a never-started sshd
    therefore needs both seeded up front, or the managed block would land in a
    void config and host-key pinning plus ``sshd -t`` would fail on missing keys.
    Seeding first also keeps sshd's very first start on the GAnet port instead of
    briefly exposing the default port 22.

    Returns whether the config had to be seeded.  A seeded config proves this sshd
    has never started, so it never answered on port 22 and nothing depends on it.
    """
    seeded = False
    if _IS_WIN and not _cfg_path().exists():
        _seed_default_sshd_config(_cfg_path())
        seeded = True
    if not _read_sshd_host_key():
        sshd = _sshd_executable()
        keygen = (os.path.join(os.path.dirname(sshd), "ssh-keygen.exe")
                  if _IS_WIN and sshd else "ssh-keygen")
        result = _setup_run([keygen, "-A"], timeout=60)
        if result.returncode:
            raise RuntimeError("生成 sshd 主机密钥失败："
                               + (_command_detail(result) or "ssh-keygen -A 返回非零"))
    # Repair unconditionally: keys may predate this code or come from a manual run.
    _harden_host_key_acls()
    return seeded


def _merge_authorized_keys_files(config: str) -> str:
    """Return the config's own AuthorizedKeysFile search list plus GAnet's file.

    GAnet's block has to lead the file to win sshd's first-wins parsing, which
    would silently drop a custom search path.  Carrying the existing value over
    keeps whatever the administrator chose, including a deliberate removal of
    the default ``.ssh/authorized_keys``.
    """
    raw = ""
    for line in config.splitlines():
        if re.match(r"^\s*Match\s+", line, re.I):
            break
        found = re.match(r"^\s*AuthorizedKeysFile\s+(?P<files>.+?)\s*$", line, re.I)
        if found:
            raw = found.group("files")
            break
    if "authorized_keys_ganet" in raw.lower():
        return raw
    if '"' in raw:
        # Quoted paths may contain spaces, so appending is the only safe edit.
        return f"{raw} {_GANET_KEY_FILE}"
    paths = raw.split() or list(_DEFAULT_KEY_FILES)
    return " ".join([*paths, _GANET_KEY_FILE])


def _merge_ports(config: str, port: int, *, keep_default: bool) -> tuple[int, ...]:
    """Return the ports the managed block has to declare.

    Unlike most keywords, ``Port`` accumulates, so declaring ours never hides the
    administrator's own entries.  One explicit ``Port`` does retire the implicit
    22 though: a host that answered on 22 by default would lose it without a
    word, so restate 22 unless this sshd never served anyone.
    """
    for line in config.splitlines():
        if re.match(r"^\s*Match\s+", line, re.I):
            break
        if re.match(r"^\s*Port\s+\d+\s*$", line, re.I):
            return (port,)
    ports = (port, _STANDARD_SSH_PORT) if keep_default else (port,)
    return tuple(dict.fromkeys(ports))


def _managed_block(ports: tuple[int, ...], key_files: str) -> str:
    kept = "" if len(ports) < 2 else (
        f"# Port {_STANDARD_SSH_PORT} is restated because a single explicit Port retires\n"
        "# sshd's implicit default, which this host was still relying on.\n")
    return (f"{_MARK_BEGIN}\n"
            "# GAnet keeps paired-device keys separate from the user's normal keys.\n"
            "# This block leads the file on purpose: sshd honours the first\n"
            "# AuthorizedKeysFile it parses and ignores every later one.\n"
            + kept
            + "".join(f"Port {p}\n" for p in ports)
            + f"AuthorizedKeysFile {key_files}\n"
            f"{_MARK_END}\n")


def _administrator_managed_block() -> str:
    return (f"{_ADMIN_MARK_BEGIN}\n"
            "    AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys "
            ".ssh/authorized_keys_ganet\n"
            f"{_ADMIN_MARK_END}\n")


def _replace_windows_administrator_keys(config: str) -> str:
    """Keep Windows' administrator key file while adding GAnet's user key file."""
    managed = _administrator_managed_block()
    config = _ADMIN_BLOCK_RE.sub("", config)
    match = re.compile(r"(?ims)^(?P<head>\s*Match\s+Group\s+administrators\s*\n)(?P<body>.*?)(?=^\s*Match\s|\Z)")
    found = match.search(config)
    if not found:
        suffix = "" if not config or config.endswith("\n") else "\n"
        return config + suffix + "Match Group administrators\n" + managed
    body = found.group("body")
    key_line = re.compile(r"(?im)^\s*AuthorizedKeysFile\s+.*(?:\n|$)")
    body = key_line.sub(managed, body, count=1) if key_line.search(body) else managed + body
    return config[:found.start()] + found.group("head") + body + config[found.end():]


def _replace_marked_block(path: Path, port: int, *, keep_default_port: bool) -> None:
    """Write exactly one GAnet global block at the head of the config.

    sshd keeps the first ``AuthorizedKeysFile`` it parses and ignores every later
    one, and Windows ships an active line near the top of ``sshd_config``, so a
    block placed further down never applied to non-administrator accounts.
    Leading the file makes GAnet's entry the effective one while leaving every
    existing line untouched, so stripping the block restores the original
    setting without a separate undo step.
    """
    old = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    stripped = _MARKED_BLOCK_RE.sub("", old)
    new = _managed_block(_merge_ports(stripped, port, keep_default=keep_default_port),
                         _merge_authorized_keys_files(stripped)) + stripped
    if _IS_WIN:
        new = _replace_windows_administrator_keys(new)
    if new == old:
        return
    backup = path.with_name(path.name + ".bak.ganet")
    if path.exists() and not backup.exists():
        shutil.copy2(path, backup)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(new, encoding="utf-8", newline="\n")


def _validate_sshd_config() -> None:
    """Surface sshd's own config diagnostics before touching the service."""
    sshd = _sshd_executable()
    if not sshd:
        return
    result = _setup_run([sshd, "-t"], timeout=30)
    if result.returncode:
        raise RuntimeError("sshd 配置校验未通过："
                           + (_command_detail(result) or "sshd -t 返回非零"))


def _restart_sshd() -> None:
    if _IS_WIN:
        # sshd can reach Running and then exit at once (a rejected host key does
        # exactly that), so confirm the service survived instead of trusting the
        # restart call.
        command = ("$ErrorActionPreference='Stop'; Set-Service sshd -StartupType Automatic; "
                   "Restart-Service sshd -Force; Start-Sleep -Seconds 2; "
                   "$s=(Get-Service sshd).Status; "
                   "if($s -ne 'Running'){throw \"sshd 启动后未保持运行（当前状态 $s）\"}")
        result = _setup_run(["powershell", "-NoProfile", "-Command", command], timeout=90)
    else:
        result = _setup_run(["systemctl", "restart", "sshd"], timeout=90)
        if result.returncode:
            result = _setup_run(["systemctl", "restart", "ssh"], timeout=90)
    if result.returncode:
        # The service manager only reports "terminated unexpectedly", so pass the
        # command's own text through rather than sending the caller to the log.
        detail = _command_detail(result)
        raise RuntimeError("重启 sshd 失败；配置已保留"
                           + (f"：{detail}" if detail else "，请检查系统日志"))


def _add_firewall(port: int) -> None:
    if _IS_WIN:
        # Repair the same managed rule in place. This is idempotent and never deletes
        # a working rule before its replacement has been committed.
        script = ("$ErrorActionPreference='Stop'; "
                  f"$r=Get-NetFirewallRule -DisplayName '{_FW_NAME}' -ErrorAction SilentlyContinue | Select-Object -First 1; "
                  f"if(!$r){{$r=New-NetFirewallRule -DisplayName '{_FW_NAME}' -Direction Inbound -Action Allow "
                  f"-Protocol TCP -LocalPort {port} -RemoteAddress 100.64.0.0/10}}else{{"
                  "$r|Set-NetFirewallRule -Enabled True -Direction Inbound -Action Allow; "
                  f"$r|Get-NetFirewallPortFilter|Set-NetFirewallPortFilter -Protocol TCP -LocalPort {port}; "
                  "$r|Get-NetFirewallAddressFilter|Set-NetFirewallAddressFilter -RemoteAddress 100.64.0.0/10}; "
                  "$p=$r|Get-NetFirewallPortFilter; $a=$r|Get-NetFirewallAddressFilter; "
                  f"if($p.Protocol -ne 'TCP' -or $p.LocalPort -notcontains '{port}' "
                  "-or ($a.RemoteAddress -notcontains '100.64.0.0/10' "
                  "-and $a.RemoteAddress -notcontains '100.64.0.0/255.192.0.0')){throw 'rule verification failed'}")
        result = _setup_run(["powershell", "-NoProfile", "-Command", script], timeout=60)
    elif shutil.which("ufw"):
        result = _setup_run(["ufw", "allow", "from", "100.64.0.0/10", "to", "any", "port", str(port), "proto", "tcp"])
    else:
        raise RuntimeError("未找到可配置的防火墙；拒绝暴露 GAnet SSH 端口")
    if result.returncode:
        raise RuntimeError("添加 GAnet SSH 防火墙规则失败")


def _apply_step(phase: str, action):
    _setup_log(f"{phase} begin")
    try:
        result = action()
    except Exception as exc:
        _setup_log(f"{phase} FAIL: {exc}")
        raise RuntimeError(f"{phase}|{exc}") from exc
    _setup_log(f"{phase} ok")
    return result


def _apply(port: int, *, sshd_installed_by_ganet: bool = False) -> None:
    _reset_setup_log()
    _setup_log(f"port={port} sshd_installed_by_ganet={sshd_installed_by_ganet}")
    report = env.check_env()
    missing = []
    if not report["checks"].get("network_component"):
        missing.append("GAnet 网络组件")
    if not report["checks"].get("sshd_installed"):
        missing.append("OpenSSH Server")
    if missing:
        raise RuntimeError("preflight|请先完成系统组件安装：" + "、".join(missing))
    seeded = _apply_step("sshd_baseline", _ensure_sshd_baseline)
    # Only an sshd that GAnet brought in has no legacy port 22 users to protect.
    keep_default_port = not (sshd_installed_by_ganet or seeded)
    _apply_step("sshd_config", lambda: _replace_marked_block(
        _cfg_path(), port, keep_default_port=keep_default_port))
    _apply_step("managed_keys_acl", _normalize_managed_keys_acl)
    _apply_step("host_key", _cache_sshd_host_key)
    _apply_step("sshd_config_check", _validate_sshd_config)
    _apply_step("sshd_restart", _restart_sshd)
    if env.get_provider().name != "embedded-tsnet":
        _apply_step("firewall", lambda: _add_firewall(port))
    _setup_log("setup done")


def _setup_failure(message: str, *, code: int = 1) -> dict[str, Any]:
    phase, separator, detail = message.partition("|")
    if not separator:
        phase, detail = "configuration", message
    detail = detail.strip() or "系统配置未完成"
    if os.path.isfile(_SETUP_LOG_PATH) and _SETUP_LOG_PATH not in detail:
        detail = f"{detail} (日志: {_SETUP_LOG_PATH})"
    return {"ok": False, "phase": phase, "code": code, "message": detail}


def _elevated_apply(port: int, *, sshd_installed_by_ganet: bool = False) -> dict[str, Any]:
    if _is_admin():
        try:
            _apply(port, sshd_installed_by_ganet=sshd_installed_by_ganet)
            return {"ok": True}
        except RuntimeError as exc:
            return _setup_failure(str(exc))
    if not _IS_WIN:
        return _setup_failure("elevation|需要管理员权限；请在系统授权提示中确认", code=3)
    result_file = os.path.join(tempfile.gettempdir(), f"ga-ganet-setup-{os.getpid()}.json")
    with contextlib.suppress(OSError):
        os.remove(result_file)
    package_root = str(Path(__file__).resolve().parents[2]).replace("'", "''")
    python = sys.executable.replace("'", "''")
    fresh = "--sshd-installed-by-ganet " if sshd_installed_by_ganet else ""
    args = (f'-m ganet.device_connection.network --apply-admin --port {port} '
            f'{fresh}--result-file "{result_file}"').replace("'", "''")
    ps = (f"$p=Start-Process -FilePath '{python}' -ArgumentList '{args}' "
          f"-WorkingDirectory '{package_root}' -Verb RunAs -Wait -PassThru; exit $p.ExitCode")
    try:
        result = subprocess.run(["powershell", "-NoProfile", "-Command", ps], timeout=1800)
    except (OSError, subprocess.SubprocessError) as exc:
        return _setup_failure(f"elevation|无法启动管理员配置：{exc}", code=3)
    try:
        with open(result_file, encoding="utf-8") as fh:
            outcome = json.load(fh)
        if isinstance(outcome, dict) and isinstance(outcome.get("ok"), bool):
            return outcome
    except (OSError, json.JSONDecodeError):
        pass
    finally:
        with contextlib.suppress(OSError):
            os.remove(result_file)
    return _setup_failure("elevation|管理员授权被取消或配置进程未能启动",
                          code=result.returncode or 3)


def _port_belongs_to_configured_sshd(port: int) -> bool:
    """Allow repeat configuration when GAnet's own sshd already owns the port."""
    report = env.check_env()
    return bool(report.get("ssh_port") == port and report["checks"].get("sshd_service")
                and report["checks"].get("ssh_port") and report["checks"].get("listening"))


def _save_setup_config(port: int) -> None:
    config = env.load_config() or {}
    ssh = dict(config.get("ssh") or {})
    ssh.update(port=port, tailnet_only=True)
    env.save_config(ssh=ssh, setup_managed=True)


def apply_confirmed(port: int, *, sshd_installed_by_ganet: bool = False) -> dict[str, Any]:
    """Apply managed setup and preserve a safe, actionable failure reason."""
    if not _port_is_free(port) and not _port_belongs_to_configured_sshd(port):
        return _setup_failure(f"port_preflight|SSH 端口 {port} 已被其他程序占用", code=2)
    outcome = _elevated_apply(port, sshd_installed_by_ganet=sshd_installed_by_ganet)
    if not outcome.get("ok"):
        return outcome
    try:
        _save_setup_config(port)
    except OSError as exc:
        return _setup_failure(f"local_state|系统配置已完成，但无法保存本机配置：{exc}")
    return {"ok": True}


def setup(port: int) -> int:
    if not _port_is_free(port) and not _port_belongs_to_configured_sshd(port):
        print(f"✗ SSH 端口 {port} 已被占用。请显式选择另一个端口：--port <端口>")
        return 2
    print("GAnet 将写入自己的 SSH 配置并配置设备互联防火墙规则。")
    if input("继续并在需要时确认 UAC/sudo？ [y/N] ").strip().lower() not in ("y", "yes"):
        print("已取消")
        return 130
    try:
        outcome = _elevated_apply(port)
        if not outcome.get("ok"):
            print(f"✗ {outcome['message']}")
            return int(outcome.get("code") or 1)
        _save_setup_config(port)
        print("✓ GAnet 环境已就绪")
        print(f"  SSH：端口 {port}（仅 tailnet 访问规则已添加）")
        print("  DNS：保留现有 Tailscale 与系统 DNS 设置")
        print("  下一步：打开 GAnet 用户中心完成登录；入网后使用 `ssh -p %d <本机用户名>@<tailnet-ip>`" % port)
        return 0
    except RuntimeError as exc:
        print(f"✗ {exc}")
        return 1


def setup_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="配置 GAnet 私有网络与用户自管 SSH 环境")
    parser.add_argument("command", nargs="?", choices=("check", "doctor"))
    parser.add_argument("--port", type=_validate_port, default=DEFAULT_PORT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--apply-admin", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--sshd-installed-by-ganet", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--result-file", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.check or args.command:
        return environment_cli([args.command or "check"] + (["--json"] if args.json else []))
    if args.apply_admin:
        try:
            _apply(args.port, sshd_installed_by_ganet=args.sshd_installed_by_ganet)
            outcome = {"ok": True}
        except RuntimeError as exc:
            outcome = _setup_failure(str(exc))
        if args.result_file:
            try:
                with open(args.result_file, "w", encoding="utf-8") as fh:
                    json.dump(outcome, fh, ensure_ascii=False)
            except OSError:
                return 1
        if not outcome["ok"]:
            print(f"✗ {outcome['message']}")
            return int(outcome.get("code") or 1)
        return 0
    return setup(args.port)


if __name__ == "__main__":
    raise SystemExit(setup_cli())
