"""Secure phone pairing, SSH key authorization, and connection facade."""
from __future__ import annotations

import sys as _module_sys
from . import auth, network
login = auth

env = network
lifecycle = network

# ---- authenticated QR protocol ----

import base64
import hashlib
import hmac
import json
import struct
import subprocess
from pathlib import Path
from typing import Any, Iterable

PROTOCOL = "ganet-qr-pair-v1"
SUITE = "hkdf-sha256+hmac-sha256"
QR_SCHEME = "ganet://pair/v1#"
SECRET_BYTES = 32
NONCE_BYTES = 16
SESSION_BYTES = 24

_PC_FIELDS = (
    "protocol", "suite", "sessionId", "ownerId", "role", "computerDeviceId",
    "displayName", "platform", "model", "tailnetIp", "sshUsername", "sshPort", "sshHostKey", "pcNonce",
    "expiresAt",
)
_PHONE_FIELDS = (
    "protocol", "suite", "sessionId", "ownerId", "role", "pcHelloHash",
    "computerDeviceId", "pcNonce", "phoneDeviceId", "displayName", "platform", "model", "publicKey",
    "phoneNonce", "expiresAt",
)
_RESULT_FIELDS = (
    "protocol", "suite", "sessionId", "ownerId", "role", "phoneHelloHash",
    "computerDeviceId", "phoneDeviceId", "state", "expiresAt",
)
_RESULT_STATES = frozenset(("approved", "cancelled", "rejected"))


def b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64u_decode(value: str, *, size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("invalid base64url value")
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in value):
        raise ValueError("invalid base64url value")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError("invalid base64url value") from exc
    if size is not None and len(raw) != size:
        raise ValueError("invalid decoded length")
    return raw


def _field_bytes(value: Any) -> bytes:
    if isinstance(value, bool) or value is None or isinstance(value, (dict, list, float)):
        raise ValueError("unsupported canonical value")
    if isinstance(value, int):
        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("integer out of range")
        return b"i" + struct.pack(">Q", value)
    if isinstance(value, bytes):
        return b"b" + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        if len(encoded) > 4096:
            raise ValueError("field too long")
        return b"s" + encoded
    raise ValueError("unsupported canonical value")


def canonical(message: dict[str, Any], fields: Iterable[str]) -> bytes:
    """Encode a fixed schema as name/value length-prefixed bytes."""
    names = tuple(fields)
    if set(message) != set(names):
        raise ValueError("message fields do not match schema")
    out = bytearray(b"GANETPAIR\x01")
    for name in names:
        key = name.encode("ascii")
        value = _field_bytes(message[name])
        out += struct.pack(">H", len(key)) + key + struct.pack(">I", len(value)) + value
    return bytes(out)


def _hkdf(secret: bytes, session_id: str, label: str) -> bytes:
    if len(secret) != SECRET_BYTES:
        raise ValueError("invalid QR secret length")
    session_raw = b64u_decode(session_id, size=SESSION_BYTES)
    salt = hashlib.sha256(PROTOCOL.encode("ascii") + b"\x00" + session_raw).digest()
    prk = hmac.new(salt, secret, hashlib.sha256).digest()
    info = (PROTOCOL + "/" + SUITE + "/" + label).encode("ascii")
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def _schema(kind: str):
    if kind == "pcHello":
        return _PC_FIELDS, "pc-to-phone/hello"
    if kind == "phoneHello":
        return _PHONE_FIELDS, "phone-to-pc/confirm"
    if kind == "result":
        return _RESULT_FIELDS, "pc-to-phone/result"
    raise ValueError("unknown envelope kind")


def envelope(kind: str, message: dict[str, Any], secret: bytes) -> dict[str, Any]:
    fields, label = _schema(kind)
    raw = canonical(message, fields)
    mac = hmac.new(_hkdf(secret, message["sessionId"], label), raw, hashlib.sha256).digest()
    return {"kind": kind, "message": message, "mac": b64u_encode(mac)}


def verify_envelope(value: dict[str, Any], kind: str, secret: bytes) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"kind", "message", "mac"} or value.get("kind") != kind:
        raise ValueError("invalid envelope")
    message = value.get("message")
    if not isinstance(message, dict):
        raise ValueError("invalid envelope message")
    expected = envelope(kind, message, secret)["mac"]
    supplied = value.get("mac")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied, expected):
        raise ValueError("envelope authentication failed")
    validate_message(kind, message)
    return message


def validate_message(kind: str, message: dict[str, Any]) -> None:
    fields, _ = _schema(kind)
    canonical(message, fields)
    if message["protocol"] != PROTOCOL or message["suite"] != SUITE:
        raise ValueError("unsupported pairing protocol")
    if message["role"] != ("pc" if kind in ("pcHello", "result") else "phone"):
        raise ValueError("invalid message role")
    b64u_decode(message["sessionId"], size=SESSION_BYTES)
    if kind in ("pcHello", "phoneHello"):
        b64u_decode(message["pcNonce"], size=NONCE_BYTES)
    if kind == "phoneHello":
        b64u_decode(message["phoneNonce"], size=NONCE_BYTES)
        b64u_decode(message["pcHelloHash"], size=32)
    if kind == "result":
        b64u_decode(message["phoneHelloHash"], size=32)
        if message["state"] not in _RESULT_STATES:
            raise ValueError("invalid result state")
    if not str(message["ownerId"]).isdigit():
        raise ValueError("invalid owner identity")
    for name in ("computerDeviceId",) + (("phoneDeviceId",) if kind != "pcHello" else ()):
        if not isinstance(message[name], str) or not message[name].startswith("dev_") or len(message[name]) > 128:
            raise ValueError("invalid device identity")
    if not isinstance(message["expiresAt"], int) or message["expiresAt"] <= 0:
        raise ValueError("invalid expiry")


def envelope_hash(value: dict[str, Any]) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return b64u_encode(hashlib.sha256(raw).digest())


def make_qr_payload(session_id: str, secret: bytes, expires_at: int) -> str:
    b64u_decode(session_id, size=SESSION_BYTES)
    if len(secret) != SECRET_BYTES or not isinstance(expires_at, int) or expires_at <= 0:
        raise ValueError("invalid QR payload")
    binary = b"\x01" + b64u_decode(session_id) + secret + struct.pack(">Q", expires_at)
    return QR_SCHEME + b64u_encode(binary)


def parse_qr_payload(value: str) -> dict[str, Any]:
    if not isinstance(value, str) or not value.startswith(QR_SCHEME) or len(value) > 256:
        raise ValueError("invalid pairing QR code")
    raw = b64u_decode(value[len(QR_SCHEME):])
    if len(raw) != 1 + SESSION_BYTES + SECRET_BYTES + 8 or raw[0] != 1:
        raise ValueError("invalid pairing QR code")
    return {"sessionId": b64u_encode(raw[1:25]), "secret": raw[25:57],
            "expiresAt": struct.unpack(">Q", raw[57:65])[0]}

protocol = _module_sys.modules[__name__]

# ---- pairing state and managed SSH keys ----

import base64
import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request

from pathlib import Path
from typing import Any


_HTTP_TIMEOUT = 30
QR_PAIRING_TTL_SECONDS = 60
_KEY_RE = re.compile(r"^(ssh-ed25519)\s+([A-Za-z0-9+/]+={0,3})(?:\s+([^\r\n]+))?$")
_PAIRED_PATH = Path.home() / ".genericagent" / "ganet" / "paired_devices.json"


def _token() -> str:
    try:
        from . import auth as login
    except ImportError:
        import auth as login
    token = login.get_token()
    if not token:
        raise RuntimeError("请先在 GAnet 用户中心登录，再创建手机公钥配对")
    return token


def _request(path: str, token: str, method: str = "GET", body: dict | None = None) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(
        env.PROVISION_BASE + path, data=data, method=method,
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=_HTTP_TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"配对服务请求失败（HTTP {exc.code}）") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"无法连接配对服务：{exc.reason}") from exc
    if not isinstance(payload, dict) or payload.get("ok") is False:
        raise RuntimeError("配对服务返回异常")
    return payload


def fingerprint(public_key: str) -> str:
    match = _KEY_RE.fullmatch(public_key.strip())
    if not match:
        raise ValueError("只接受单行 ssh-ed25519 公钥")
    try:
        raw = base64.b64decode(match.group(2), validate=True)
    except Exception as exc:
        raise ValueError("SSH 公钥编码无效") from exc
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def authorized_keys_path() -> Path:
    """GAnet-owned key file; the embedded SSH service reads exactly this path."""
    return Path.home() / ".genericagent" / "ganet" / "authorized_keys"


def _windows_acl_script(path: Path, *, verify: bool) -> str:
    """Compare and rewrite the DACL purely by SID.

    Built-in account names are localized, so ``NT AUTHORITY\\SYSTEM`` and
    ``OWNER RIGHTS`` only match on English installs.  Since icacls grants by SID,
    a name-based check would keep failing after a successful repair and turn a
    non-English desktop into a hard pairing error.
    """
    quoted = str(path).replace("'", "''")
    identity = "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
    if verify:
        return (
            f"$p='{quoted}';$a=Get-Acl -LiteralPath $p -ErrorAction Stop;"
            "$rules=@($a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]));"
            "$ownerRights=$rules|Where-Object {$_.IdentityReference.Value -eq 'S-1-3-4'};"
            f"$expected=@(@({identity},'S-1-5-18','S-1-5-32-544')|Select-Object -Unique);"
            "$ok=$a.AreAccessRulesProtected -and -not $ownerRights;"
            "$ok=$ok -and (@($expected|Where-Object {$id=$_;@($rules|Where-Object {"
            "$_.IdentityReference.Value -eq $id -and $_.AccessControlType -eq 'Allow' -and "
            "($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq "
            "[Security.AccessControl.FileSystemRights]::FullControl -and -not $_.IsInherited}).Count -gt 0"
            "}).Count -eq $expected.Count);"
            "$ok=$ok -and -not @($rules|Where-Object {$expected -contains $_.IdentityReference.Value -and $_.AccessControlType -eq 'Deny'}).Count;"
            "if($ok){exit 0};exit 1"
        )
    return (
        f"$p='{quoted}';$a=Get-Acl -LiteralPath $p -ErrorAction Stop;"
        "$backup=$p+'.acl-backup.sddl';if(-not(Test-Path -LiteralPath $backup)){Set-Content -LiteralPath $backup -Value $a.Sddl -NoNewline -Encoding ascii};"
        f"$user={identity};"
        "& icacls $p /inheritance:r /remove:g '*S-1-3-4' /grant:r \"*${user}:(F)\" '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' | Out-Null;"
        "if($LASTEXITCODE){exit $LASTEXITCODE}"
    )


def ensure_authorized_keys_permissions(path: Path | None = None) -> bool:
    """Normalize the GAnet key file permissions and verify the result."""
    path = path or authorized_keys_path()
    if not path.exists():
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.touch()
    if _module_sys.platform != "win32":
        with contextlib.suppress(OSError):
            os.chmod(path, 0o600)
        return True
    def run(verify: bool) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["powershell", "-NoProfile", "-Command",
                               _windows_acl_script(path, verify=verify)],
                              capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=30)

    verified = run(True)
    if not verified.returncode:
        return True
    configured = run(False)
    if configured.returncode:
        detail = (configured.stderr or configured.stdout).strip().replace("\n", " ")
        raise RuntimeError("GAnet 授权文件权限配置失败" + ("：" + detail[:300] if detail else ""))
    verified = run(True)
    if verified.returncode:
        detail = (verified.stderr or verified.stdout).strip().replace("\n", " ")
        raise RuntimeError("GAnet 授权文件权限验证失败" + ("：" + detail[:300] if detail else ""))
    return True


def authorized_keys_permissions_ok(path: Path | None = None) -> bool:
    path = path or authorized_keys_path()
    if not path.is_file():
        return False
    if _module_sys.platform != "win32":
        return True
    completed = subprocess.run(["powershell", "-NoProfile", "-Command",
                                _windows_acl_script(path, verify=True)],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=30)
    return completed.returncode == 0


def _paired_devices() -> dict[str, Any]:
    try:
        value = json.loads(_PAIRED_PATH.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def list_paired_devices() -> list[dict[str, Any]]:
    """Return paired records enriched with their current SSH authorization fact.

    A pairing record alone is not proof the embedded SSH service still accepts that phone.
    Compare each recorded key with the GAnet-owned authorization file instead of
    exposing the never-updated ``last_seen`` field as a connection status.
    """
    try:
        text = authorized_keys_path().read_text(encoding="utf-8", errors="replace")
        authorized = {line.strip() for line in text.splitlines()
                      if line.strip() and not line.lstrip().startswith("#")}
    except OSError:
        authorized = set()
    devices = []
    for stored in _paired_devices().values():
        device = dict(stored)
        public_key = device.get("public_key")
        device["authorized"] = isinstance(public_key, str) and public_key.strip() in authorized
        devices.append(device)
    return devices


def remove_paired_device(device_id: str) -> bool:
    devices = _paired_devices()
    device = devices.get(device_id)
    if not device:
        return False
    public_key = device.get("public_key")
    if isinstance(public_key, str):
        remove_public_key(public_key)
    devices.pop(device_id, None)
    _PAIRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PAIRED_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(devices, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _PAIRED_PATH)
    return True


def _paired_snapshot() -> bytes | None:
    try:
        return _PAIRED_PATH.read_bytes()
    except FileNotFoundError:
        return None


def _restore_paired_snapshot(snapshot: bytes | None) -> None:
    if snapshot is None:
        with contextlib.suppress(FileNotFoundError):
            _PAIRED_PATH.unlink()
        return
    _PAIRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PAIRED_PATH.with_suffix(".tmp")
    tmp.write_bytes(snapshot)
    os.replace(tmp, _PAIRED_PATH)


def _save_paired_device(candidate: dict[str, Any], public_key: str) -> None:
    devices = _paired_devices()
    device_id = candidate.get("device_id")
    if not isinstance(device_id, str) or not device_id.startswith("dev_"):
        raise RuntimeError("配对服务未返回有效的手机设备 ID")
    devices[device_id] = {
        "device_id": device_id,
        "display_name": candidate.get("device_name") or "手机",
        "platform": candidate.get("platform") or "android",
        "model": candidate.get("model") or "Android phone",
        "public_key": public_key.strip(),
        "fingerprint": fingerprint(public_key),
        "paired_at": int(time.time()),
        "last_seen": None,
    }
    _PAIRED_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PAIRED_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(devices, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, _PAIRED_PATH)


def append_public_key(public_key: str) -> tuple[Path, bool]:
    """Append a deduplicated public key and report whether this call added it."""
    normalized = public_key.strip()
    fingerprint(normalized)
    path = authorized_keys_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    old = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    existing = {line.strip() for line in old.splitlines() if line.strip() and not line.startswith("#")}
    if normalized in existing:
        ensure_authorized_keys_permissions(path)
        return path, False
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        if old and not old.endswith("\n"):
            fh.write("\n")
        fh.write(normalized + "\n")
    try:
        ensure_authorized_keys_permissions(path)
    except Exception:
        path.write_text(old, encoding="utf-8", newline="\n")
        raise
    return path, True


def remove_public_key(public_key: str) -> bool:
    """Remove only the exact normalized key this pairing call inserted."""
    normalized = public_key.strip()
    fingerprint(normalized)
    path = authorized_keys_path()
    if not path.exists():
        return False
    old = path.read_text(encoding="utf-8", errors="replace")
    kept = [line for line in old.splitlines() if line.strip() != normalized]
    if len(kept) == len(old.splitlines()):
        return False
    path.write_text(("\n".join(kept) + "\n") if kept else "", encoding="utf-8", newline="\n")
    return True


def _owner_id() -> str:
    try:
        from . import auth as login
    except ImportError:
        import auth as login
    identity = login.current_identity() or {}
    owner_id = identity.get("userId")
    if owner_id is None or not str(owner_id).isdigit():
        raise RuntimeError("无法确认当前正式 GA 账号")
    return str(owner_id)


def _qr_svg(payload: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg
    except ImportError as exc:
        raise RuntimeError(
            "缺少二维码组件，先对 GA 发送“"
            "帮我配置 GAnet。”"
        ) from exc
    qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
                       box_size=8, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    output = io.BytesIO()
    image.save(output)
    return output.getvalue().decode("utf-8")


def create_secure_pairing() -> dict[str, Any]:
    receipt = env.load_receipt() or {}
    metadata = env.local_device_metadata()
    runtime = env.get_provider().status()
    ip = runtime.get("ip")
    if not ip:
        raise RuntimeError("电脑尚未连接 GAnet 控制面")
    now = int(time.time())
    session_id = protocol.b64u_encode(secrets.token_bytes(protocol.SESSION_BYTES))
    secret = secrets.token_bytes(protocol.SECRET_BYTES)
    expires_at = now + QR_PAIRING_TTL_SECONDS
    pc_nonce = protocol.b64u_encode(secrets.token_bytes(protocol.NONCE_BYTES))
    message = {
        "protocol": protocol.PROTOCOL, "suite": protocol.SUITE,
        "sessionId": session_id, "ownerId": _owner_id(), "role": "pc",
        "computerDeviceId": receipt.get("device_id") or metadata["deviceId"],
        "displayName": metadata["displayName"], "platform": metadata["platform"],
        "model": metadata["model"], "tailnetIp": ip,
        "sshUsername": metadata["sshUsername"], "sshPort": metadata["sshPort"],
        "sshHostKey": metadata["sshHostKey"], "pcNonce": pc_nonce,
        "expiresAt": expires_at,
    }
    pc_hello = protocol.envelope("pcHello", message, secret)
    _request("/pairings/relay", _token(), "POST",
             {"sessionId": session_id, "expiresAt": expires_at, "pcHello": pc_hello})
    qr_payload = protocol.make_qr_payload(session_id, secret, expires_at)
    return {"pairing_id": session_id, "secret": secret, "pc_hello": pc_hello,
            "expires_at": expires_at, "qr_svg": _qr_svg(qr_payload), "state": "qr_waiting"}


def create_pairing_card() -> dict[str, Any]:
    """Create a PC-local QR session; its secret remains only in `_PENDING`."""
    session = create_secure_pairing()
    return {"ok": True, **session,
            "message": "使用同一 GA 账号的手机扫描二维码，并在本电脑确认。"}


_PENDING: dict[str, dict[str, Any]] = {}
_PENDING_LOCK = threading.Lock()


def _publish_result(state: dict[str, Any], result_state: str) -> None:
    candidate = state.get("candidate") or {}
    message = {
        "protocol": protocol.PROTOCOL, "suite": protocol.SUITE,
        "sessionId": state["pairing_id"], "ownerId": state["pc_hello"]["message"]["ownerId"],
        "role": "pc", "phoneHelloHash": protocol.envelope_hash(state["phone_hello"]),
        "computerDeviceId": state["pc_hello"]["message"]["computerDeviceId"],
        "phoneDeviceId": candidate["device_id"], "state": result_state,
        "expiresAt": state["expires_at"],
    }
    result = protocol.envelope("result", message, state["secret"])
    try:
        _request(f"/pairings/relay/{state['pairing_id']}/result", _token(), "POST", {"result": result})
    except RuntimeError:
        # A lost response is ambiguous. Keep local authorization only when the relay
        # durably exposes the exact authenticated result we attempted to publish.
        relay = _request(f"/pairings/relay/{state['pairing_id']}", _token())
        if relay.get("result") != result:
            raise


def _secure_candidate(state: dict[str, Any], relay: dict[str, Any]) -> dict[str, Any]:
    phone_hello = relay.get("phoneHello")
    try:
        message = protocol.verify_envelope(phone_hello, "phoneHello", state["secret"])
    except (ValueError, TypeError) as exc:
        raise RuntimeError("手机安全验证失败") from exc
    pc = state["pc_hello"]["message"]
    if (message["sessionId"] != state["pairing_id"] or message["ownerId"] != pc["ownerId"] \
            or message["computerDeviceId"] != pc["computerDeviceId"] \
            or message["pcNonce"] != pc["pcNonce"] \
            or message["pcHelloHash"] != protocol.envelope_hash(state["pc_hello"]) \
            or message["expiresAt"] != state["expires_at"]):
        raise RuntimeError("手机配对上下文不匹配")
    public_key = message["publicKey"]
    return {"device_id": message["phoneDeviceId"], "device_name": message["displayName"],
            "platform": message["platform"], "model": message["model"],
            "fingerprint": fingerprint(public_key),
            "public_key": public_key, "phone_nonce": message["phoneNonce"],
            "phone_hello": phone_hello}


def _pairing_worker(pairing_id: str) -> None:
    """Verify the phone envelope before exposing a candidate to local approval."""
    while True:
        with _PENDING_LOCK:
            state = _PENDING.get(pairing_id)
            if not state or state.get("cancelled"):
                return
            snapshot = dict(state)
        if int(time.time()) >= snapshot["expires_at"]:
            with _PENDING_LOCK:
                if pairing_id in _PENDING:
                    _PENDING[pairing_id]["state"] = "expired"
                    _PENDING[pairing_id].pop("secret", None)
            return
        try:
            relay = _request(f"/pairings/relay/{pairing_id}", _token())
            if relay.get("phoneHello"):
                try:
                    candidate = _secure_candidate(snapshot, relay)
                except RuntimeError as exc:
                    with _PENDING_LOCK:
                        if pairing_id in _PENDING:
                            _PENDING[pairing_id].update(state="security_failed", last_error=str(exc))
                            _PENDING[pairing_id].pop("secret", None)
                    return
                with _PENDING_LOCK:
                    if pairing_id in _PENDING:
                        _PENDING[pairing_id].update(state="phone_verified", candidate=candidate,
                                                    phone_hello=candidate.pop("phone_hello"))
                return
        except RuntimeError as exc:
            with _PENDING_LOCK:
                if pairing_id in _PENDING:
                    _PENDING[pairing_id]["last_error"] = str(exc)
        time.sleep(0.75)


def start_local_pairing() -> str:
    """Start a local user-center pairing session for one phone key."""
    if pending_pairing_id():
        return "已有待处理的手机配对，请在 GAnet 用户中心继续或取消。"
    card = create_pairing_card()
    card["state"] = "qr_waiting"
    with _PENDING_LOCK:
        _PENDING[card["pairing_id"]] = card
    threading.Thread(target=_pairing_worker, args=(card["pairing_id"],), daemon=True).start()
    return ("GAnet 手机配对\n\n"
            "二维码已在本机 GAnet 用户中心 → 我的设备 → 添加设备 中显示。\n"
            "请使用手机 GA：设置 → 设备互联 → 扫描二维码。\n"
            "手机验证后，回到本电脑本地确认。")


def pending_pairing_id() -> str | None:
    with _PENDING_LOCK:
        return next(reversed(_PENDING), None) if _PENDING else None


def cancel_local_pairing() -> str:
    pairing_id = pending_pairing_id()
    if not pairing_id:
        return "当前没有待处理的手机配对。"
    with _PENDING_LOCK:
        if pairing_id in _PENDING:
            _PENDING[pairing_id]["cancelled"] = True
    with _PENDING_LOCK:
        state = dict(_PENDING.get(pairing_id) or {})
    if state.get("phone_hello"):
        with contextlib.suppress(Exception):
            _publish_result(state, "cancelled" if state.get("state") != "phone_verified" else "rejected")
    else:
        with contextlib.suppress(Exception):
            _request(f"/pairings/relay/{pairing_id}", _token(), "DELETE")
    with _PENDING_LOCK:
        if pairing_id in _PENDING:
            _PENDING[pairing_id].pop("secret", None)
        _PENDING.pop(pairing_id, None)
    return "✓ 已取消并销毁本次手机配对。"


def approve_local_pairing() -> str:
    pairing_id = pending_pairing_id()
    if not pairing_id:
        return "当前没有待确认的手机配对。"
    with _PENDING_LOCK:
        state = _PENDING.get(pairing_id) or {}
        candidate = state.get("candidate")
    if state.get("state") != "phone_verified" or not isinstance(candidate, dict):
        return "手机尚未完成安全验证。"
    result = approve_secure_pairing(state, candidate)
    with _PENDING_LOCK:
        if pairing_id in _PENDING:
            _PENDING[pairing_id].update(state="approved", device_name=candidate["device_name"],
                                        fingerprint=result["fingerprint"], path=result["path"])
            _PENDING[pairing_id].pop("secret", None)
    return (f"✓ 已配对：{candidate['device_name']}\n"
            f"指纹：{result['fingerprint']}\n已写入：{result['path']}")


def approve_secure_pairing(state: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    """Commit both PC records, then publish the authenticated approved result."""
    public_key = candidate["public_key"]
    paired_before = _paired_snapshot()
    inserted = False
    try:
        path, inserted = append_public_key(public_key)
        _save_paired_device(candidate, public_key)
        _publish_result(state, "approved")
    except Exception as exc:
        if inserted:
            with contextlib.suppress(Exception):
                remove_public_key(public_key)
        with contextlib.suppress(Exception):
            _restore_paired_snapshot(paired_before)
        raise RuntimeError("本地配对保存或结果发布失败，已回滚；请重新配对") from exc
    return {"ok": True, "path": str(path), "fingerprint": fingerprint(public_key)}


def local_pairing_qr_svg(expected_pairing_id: str | None = None) -> bytes | None:
    """Return only the QR image for the requested live pairing session.

    The browser gives each image request its session ID.  Never substitute a newly
    generated QR for a request that belongs to an expired or cancelled session:
    that mixes the countdown and code across pairing attempts.
    """
    pairing_id = pending_pairing_id()
    if not pairing_id or not expected_pairing_id or expected_pairing_id != pairing_id:
        return None
    with _PENDING_LOCK:
        value = (_PENDING.get(pairing_id) or {}).get("qr_svg")
    return value.encode("utf-8") if isinstance(value, str) else None


def local_pairing_state() -> dict[str, Any] | None:
    pairing_id = pending_pairing_id()
    if not pairing_id:
        return None
    with _PENDING_LOCK:
        state = dict(_PENDING.get(pairing_id) or {})
    state.pop("secret", None)
    state.pop("pc_hello", None)
    if isinstance(state.get("expires_at"), int):
        state["expires_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(state["expires_at"]))
    state.pop("phone_hello", None)
    state.pop("qr_svg", None)
    candidate = state.get("candidate")
    if isinstance(candidate, dict):
        candidate = dict(candidate)
        candidate.pop("public_key", None)
        state["candidate"] = candidate
    return state


keys = _module_sys.modules[__name__]

# ---- user-center connection facade ----

from typing import Callable



AuthListener = Callable[[str, dict | None, str | None], str]


def on_auth_event(event: str, identity: dict | None, token: str | None) -> str:
    """Project generic authentication events into GAnet without auth importing GAnet."""
    if event == "login":
        return lifecycle.on_login(identity, token)
    if event == "logout":
        return lifecycle.on_logout()
    raise ValueError(f"unsupported auth event: {event}")


def register_auth_lifecycle() -> None:
    """Attach GAnet to the generic auth event bus at application composition time."""
    try:
        from . import auth
    except ImportError:  # direct `python frontends/tui*.py` launch
        import auth
    auth.register(on_auth_event)


def _report_with_ssh_probe(report: dict, probe: dict) -> dict:
    """Attach the just-run probe without repeating slow environment checks."""
    updated = dict(report)
    checks = dict(updated.get("checks") or {})
    checks["ssh_probe"] = bool(probe.get("ok"))
    updated["checks"] = checks
    updated["ssh_probe"] = dict(probe)
    if not probe.get("ok"):
        updated["status"] = "need_repair"
        updated["hint"] = "模拟手机 SSH 请求未通过"
    return updated


def configure_environment(*, approved: bool = False,
                          tailscale_installed_by_ganet: bool = False,
                          network_switch_approved: bool = False) -> dict:
    """Plan or apply the standard PC setup, then return the authoritative doctor state."""
    if tailscale_installed_by_ganet:
        env.set_initial_network_defaults_pending(True)
    report = env.check_env()
    initial_defaults_pending = env.initial_network_defaults_pending()
    receipt = report.get("receipt") or {}
    if report["status"] == "ok":
        if receipt.get("enrollment_state") == "joining":
            try:
                env.save_receipt(enrollment_state="joined")
                report = env.check_env()
            except OSError as exc:
                return {"status": "blocked", "changed": False, "stage": "local_state",
                        "environment": report,
                        "message": f"GAnet 已连接，但无法完成本机状态保存：{exc}"}
        # Static checks alone cannot prove the embedded SSH service accepts the
        # managed key file. Finish every GA-directed setup run with a disposable
        # public-key request.
        probe = probe_phone_ssh()
        report = _report_with_ssh_probe(report, probe)
        return {"status": report["status"], "changed": False, "environment": report,
                "ssh_probe": probe, "message": "" if probe.get("ok") else probe.get("detail", "模拟手机请求未通过")}
    missing_project_components = [label for key, label in (
        ("qr_component", "二维码组件"),
        ("screenshot_media", "电脑截图组件"),
    ) if not report["checks"].get(key, False)]
    missing_system_components = [label for key, label in (
        ("network_provider", "GAnet 网络组件"),
    ) if not report["checks"].get(key, False)]
    if missing_project_components:
        return {"status": "needs_project_setup", "changed": False, "environment": report,
                "message": "请先补齐当前 GA 环境：" + "、".join(missing_project_components)}
    # Installing or replacing the network component is the staged, user-visible
    # flow in sidecar_manager; this call only configures and enrolls what is
    # already installed, and reports missing pieces instead of fetching them.
    if missing_system_components:
        return {"status": "needs_system_setup", "changed": False, "environment": report,
                "message": "请先安装：" + "、".join(missing_system_components)}
    if (report.get("provider") == "embedded-tsnet"
            and report.get("version_state") == "required"):
        return {"status": "needs_system_setup", "changed": False, "environment": report,
                "message": "GAnet 网络组件需要更新，请先完成组件替换"}
    # SSH service state (running/listening) follows enrollment, which happens
    # below; configuration here only covers the user-owned local facts.
    configuration_checks = ["managed_keys", "managed_keys_acl", "host_key"]
    needs_ganet_configuration = any(not report["checks"].get(key, False)
                                    for key in configuration_checks)
    try:
        from . import auth as login
    except ImportError:
        import auth as login
    token = login.get_token()
    identity = login.current_identity() if token else None
    if not token or not identity or not identity.get("valid"):
        return {"status": "needs_login", "changed": False, "environment": report,
                "message": "需要先登录正式 GA 账号"}
    if (identity.get("base_url") or "").rstrip("/") != env.AUTH_BASE:
        return {"status": "needs_login", "changed": False, "environment": report,
                "message": "需要登录正式 GA 账号"}
    runtime = report.get("runtime") or {}
    switching_active_network = bool(report.get("provider") == "system-tailscale"
                                    and runtime.get("online") and not runtime.get("on_ga_control"))
    if switching_active_network and not network_switch_approved:
        return {"status": "needs_network_switch_approval", "changed": False,
                "environment": report,
                "message": "这台电脑当前连接着另一个 Tailscale 网络；继续会将它切换到 GAnet"}
    if needs_ganet_configuration and not approved:
        return {"status": "needs_approval", "changed": False, "environment": report,
                "message": "需要配置 GAnet 内嵌 SSH 环境"}
    if needs_ganet_configuration:
        setup = network.apply_confirmed(int(report["ssh_port"]))
        if not setup.get("ok"):
            return {"status": "blocked", "changed": False, "environment": env.check_env(),
                    "stage": setup.get("phase"), "code": setup.get("code"),
                    "message": setup.get("message") or "GAnet 系统配置未完成"}
    report = env.check_env()
    if not report["checks"].get("ga_profile"):
        try:
            network.enroll(token, apply_initial_network_defaults=initial_defaults_pending)
            if initial_defaults_pending:
                env.set_initial_network_defaults_pending(False)
        except RuntimeError as exc:
            return {"status": "blocked", "changed": bool(needs_ganet_configuration),
                    "environment": env.check_env(), "message": str(exc)}
    report = env.check_env()
    if report["status"] != "ok":
        return {"status": report["status"], "changed": bool(needs_ganet_configuration),
                "environment": report}
    probe = probe_phone_ssh()
    report = _report_with_ssh_probe(report, probe)
    return {"status": report["status"], "changed": bool(needs_ganet_configuration),
            "environment": report, "ssh_probe": probe,
            "message": "" if probe.get("ok") else probe.get("detail", "模拟手机请求未通过")}


# ---- uninstall ----

import os
import shutil
import time

_UNINSTALL_PLAN = (
    "注销远端设备记录（未登录则跳过）",
    "停止常驻 Worker 与 GAnet 网络组件",
    "移除登录自启动",
    "删除配对密钥、配对记录与本机 GAnet 数据（组件代码目录保留）",
)


def remove_environment(*, approved: bool = False) -> dict:
    """Plan or apply the fixed PC-side uninstall sequence.

    The component checkout itself stays: without the local state removed here
    the code is inert, and keeping it makes a later reconfiguration one step.
    """
    if not approved:
        return {"status": "needs_approval", "changed": False,
                "steps": list(_UNINSTALL_PLAN),
                "message": "将卸载本机 GAnet 设备互联环境；组件代码目录保留"}
    # interactive_worker resolves the host binding at import time, so on a
    # half-configured machine the import itself raises. No binding also means
    # no worker was ever started, so skipping the stop step is the truth.
    try:
        try:
            from ..device_access import interactive_worker
        except ImportError:
            from device_access import interactive_worker  # type: ignore[no-redef]
    except (ImportError, RuntimeError):
        interactive_worker = None  # type: ignore[assignment]
    try:
        from . import sidecar_manager
    except ImportError:
        import sidecar_manager  # type: ignore[no-redef]

    steps: dict[str, str] = {}

    # Remote retirement is best-effort by design: local removal must not
    # depend on the login session or the registry service being reachable.
    receipt = env.load_receipt() or {}
    token = login.get_token()
    hostname = receipt.get("hostname")
    if token and hostname:
        try:
            network._retire_remote(token, str(hostname))
            steps["remote"] = "ok"
        except RuntimeError as exc:
            steps["remote"] = f"failed: {exc}"
    else:
        steps["remote"] = "skipped"

    if interactive_worker is None:
        steps["worker"] = "skipped"
    else:
        try:
            worker = interactive_worker.stop_worker()
            steps["worker"] = "ok" if worker.get("ok") else f"failed: {worker.get('detail')}"
        except (RuntimeError, OSError) as exc:
            steps["worker"] = f"failed: {exc}"

    try:
        sidecar_manager._stop_running()
        steps["service"] = "ok"
    except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
        steps["service"] = f"failed: {exc}"

    steps["autostart"] = _remove_autostart(Path(sidecar_manager._EXECUTABLE))

    config_dir = Path(network.managed_authorized_keys_path()).parent
    steps["sidecar_data"] = _remove_tree(Path(sidecar_manager._ROOT))
    steps["local_state"] = _remove_tree(config_dir)

    local_failed = [name for name, state in steps.items()
                    if name != "remote" and state.startswith("failed")]
    if local_failed:
        return {"status": "partial", "changed": True, "steps": steps,
                "message": "部分卸载步骤未完成：" + "、".join(local_failed)}
    return {"status": "removed", "changed": True, "steps": steps,
            "message": "GAnet 已从本机卸载；组件代码目录保留，可随时重新配置"}


def _remove_autostart(executable: Path) -> str:
    if os.name != "nt":
        return "skipped"
    binary_present = executable.is_file()
    # The sidecar owns autostart install/remove; once its binary is gone, fall
    # back to deleting the same registry value it would have removed.
    command = ([str(executable), "autostart", "remove"] if binary_present else
               ["reg.exe", "delete", r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                "/v", "GenericAgent GAnet", "/f"])
    try:
        completed = subprocess.run(command, capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"failed: {exc}"
    if completed.returncode and binary_present:
        detail = (completed.stderr or completed.stdout or b"").decode(errors="replace")
        return "failed: " + detail.strip()[:200]
    # reg.exe reports an error for an already-absent value; absence is success.
    return "ok"


def _remove_tree(root: Path) -> str:
    if not root.exists():
        return "ok"
    for attempt in range(2):
        try:
            shutil.rmtree(root)
            return "ok"
        except OSError as exc:
            # Freshly killed processes can release file handles a beat later.
            if attempt:
                return f"failed: {exc}"
            time.sleep(1.0)
    return "ok"


def get_user_center_state() -> dict:
    """Return the fast local facts for the user center.

    The environment probe shells out to the network agent and can take seconds,
    so it lives in `get_environment_report()` and is fetched separately; page
    rendering must never wait on it.
    """
    try:
        from . import auth as login
    except ImportError:
        import auth as login
    return {"identity": login.current_identity(),
            "devices": keys.list_paired_devices(), "pairing": keys.local_pairing_state()}


def get_environment_report() -> dict:
    """Run the slow device-interconnect checks for the user center."""
    return env.check_env()


def probe_phone_ssh() -> dict:
    """Run the one-shot local emulation of a paired phone's SSH request."""
    return env.ssh_device_probe()


def pairing_qr_svg(expected_pairing_id: str | None = None) -> bytes | None:
    return keys.local_pairing_qr_svg(expected_pairing_id)


def create_pairing() -> str:
    return keys.start_local_pairing()


def approve_pairing() -> str:
    return keys.approve_local_pairing()


def cancel_pairing() -> str:
    return keys.cancel_local_pairing()


def remove_device(device_id: str) -> bool:
    return keys.remove_paired_device(device_id)


def status_text() -> str:
    return lifecycle.status_text()
