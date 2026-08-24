"""Account authentication, credentials, and connection lifecycle events."""
from __future__ import annotations

import sys as _module_sys

# ---- authentication event bus ----

from typing import Callable

Listener = Callable[[str, dict | None, str | None], str | None]
_LISTENERS: list[Listener] = []


def register(listener: Listener) -> None:
    if listener not in _LISTENERS:
        _LISTENERS.append(listener)


def unregister(listener: Listener) -> None:
    if listener in _LISTENERS:
        _LISTENERS.remove(listener)


def notify(event: str, identity: dict | None, token: str | None) -> list[str]:
    messages = []
    for listener in tuple(_LISTENERS):
        try:
            message = listener(event, identity, token)
            if message:
                messages.append(str(message))
        except Exception as exc:
            messages.append(f"• 登录生命周期钩子未运行：{type(exc).__name__}: {exc}")
    return messages

# The login implementation historically imported `auth`; keep the same boundary locally.
auth = _module_sys.modules[__name__]

# ---- GAuth login and credential storage ----

import base64
import json
import os
from pathlib import Path
import sys
import time
import contextlib
import secrets
import threading
import webbrowser
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

# 中文输出在部分 Windows 控制台会乱码 → 对齐 desktop_bridge 的 stdout/err UTF-8 兜底。
for _s in (sys.stdout, sys.stderr):
    with contextlib.suppress(Exception):
        _s.reconfigure(encoding="utf-8", errors="replace")

# GAuth 基址：默认走 HTTPS 域名（provisioning-TLS 是归约前提，§8.1）。
# 可用 GA_AUTH_URL 覆盖（如本地联调 http://47.79.38.240:8099）。
_DEFAULT_BASE = "https://auth.gaagent.ai"
_STORE_DIR = os.path.join(os.path.expanduser("~"), ".genericagent", "gauth")
_TOKEN_PATH = os.path.join(_STORE_DIR, "token.json")


def _auth_base() -> str:
    return (os.environ.get("GA_AUTH_URL") or _DEFAULT_BASE).rstrip("/")


# ----- token 存取 ---------------------------------------------------------

def save_token(data: dict, base_url: str | None = None) -> None:
    """落地 token 记录（0600）。data 至少含 token/userId/email。"""
    os.makedirs(_STORE_DIR, exist_ok=True)
    try:
        os.chmod(_STORE_DIR, 0o700)
    except OSError:
        pass
    rec = {
        "token": data.get("token"),
        "userId": data.get("userId"),
        "email": data.get("email"),
        "nickname": data.get("nickname"),
        "hasPassword": data.get("hasPassword"),
        "base_url": (base_url or _auth_base()).rstrip("/"),
        "obtained_at": int(time.time()),
    }
    tmp = _TOKEN_PATH + ".tmp"
    # 先建再收权限，减少明文可读窗口。
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, ensure_ascii=False)
    os.replace(tmp, _TOKEN_PATH)
    try:
        os.chmod(_TOKEN_PATH, 0o600)
    except OSError:
        pass


def load_token() -> dict | None:
    try:
        with open(_TOKEN_PATH, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) and d.get("token") else None
    except Exception:
        return None


def clear_token() -> bool:
    try:
        os.remove(_TOKEN_PATH)
        return True
    except FileNotFoundError:
        return False
    except OSError:
        return False


# ----- JWT 解码（仅读 payload 展示/查过期，不验签；验签是网关侧 D3 的事）--------

def _decode_payload(token: str) -> dict:
    try:
        pl = token.split(".")[1]
        pl += "=" * (-len(pl) % 4)
        return json.loads(base64.urlsafe_b64decode(pl))
    except Exception:
        return {}


def token_valid(rec: dict | None = None) -> bool:
    """本地判活：仅看 exp 是否在未来（不代表服务端未吊销）。"""
    rec = rec or load_token()
    if not rec or not rec.get("token"):
        return False
    exp = _decode_payload(rec["token"]).get("exp", 0)
    return bool(exp) and exp > time.time()


def get_token() -> str | None:
    """当前有效 token 字符串，或 None。**D1 broker 契约的种子**：其它 UI/网关
    经此取用（后续包成本地 HTTP 端点）。v1 不自动刷新，过期即需重登。"""
    rec = load_token()
    return rec["token"] if token_valid(rec) else None


def current_identity() -> dict | None:
    """{userId, email, exp, expires_in} 或 None。用于 whoami / owner 展示。"""
    rec = load_token()
    if not rec or not rec.get("token"):
        return None
    pl = _decode_payload(rec["token"])
    exp = pl.get("exp", 0)
    return {
        "userId": rec.get("userId") or pl.get("uid"),
        "email": rec.get("email") or pl.get("email"),
        "nickname": rec.get("nickname"),
        "exp": exp,
        "expires_in": max(0, int(exp - time.time())) if exp else 0,
        "valid": bool(exp) and exp > time.time(),
        "base_url": rec.get("base_url"),
    }


# ----- web 登录（loopback + 本地登录页，复刻 GitHub/VSCode 形态）------------
# 差异见文档 §9.5：GAuth 非 OAuth 服务器，故本地页调 GAuth API 拿 JWT 再回传 loopback，
# 用 state 随机数防 CSRF；只绑 127.0.0.1、随机端口、单次短命（§9.5 避坑）。

_LOGIN_PAGE_PATH = Path(__file__).with_name("pages") / "auth_login.html"


def _login_page(base: str, state: str, app_name: str = "GAgent") -> str:
    """Render the static loopback login page with per-session values."""
    return (_LOGIN_PAGE_PATH.read_text(encoding="utf-8")
            .replace("__BASE__", base)
            .replace("__STATE__", state)
            .replace("__APP__", app_name))




def login_web(timeout: int = 180, open_browser: bool = True,
              auth_base: str | None = None,
              on_url=None, on_success=None) -> tuple[bool, str]:
    """起 127.0.0.1 loopback + 本地登录页，浏览器登录后回传 JWT。返回 (ok, msg)。

    ``on_url`` 收到登录页地址时由调用方决定如何展示（TUI 用它把地址回显给用户，
    远程服务器上的用户自行做端口转发）；缺省仍按 CLI 习惯直接 print。
    ``on_success`` 在令牌落盘后调用，可返回一个后续地址；登录页拿到它就直接跳转，
    使「登录 → 目标界面」在同一个浏览器标签里一气呵成。
    """
    state = secrets.token_urlsafe(18)
    base = (auth_base or _auth_base()).rstrip("/")
    page = _login_page(base, state)
    result: dict = {}
    done = threading.Event()

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):            # 静默，别污染终端
            pass

        def _send(self, code, body, ctype="application/json"):
            data = body.encode("utf-8") if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            with contextlib.suppress(Exception):
                self.wfile.write(data)

        def do_GET(self):
            if self.path == "/" or self.path.startswith("/?"):
                self._send(200, page, "text/html")
            elif self.path == "/favicon.ico":
                self._send(204, b"")
            else:
                self._send(404, "{}")

        def do_POST(self):
            if self.path != "/callback":
                self._send(404, "{}"); return
            try:
                n = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(n).decode("utf-8"))
            except Exception:
                self._send(400, '{"ok":false}'); return
            if data.get("state") != state:      # state 不符 → 拒（防本地 CSRF/注入）
                self._send(403, '{"ok":false}'); return
            if not data.get("token"):
                self._send(400, '{"ok":false}'); return
            save_token(data, base_url=base)
            result.update(data)
            # A failure here must not cost the user their freshly saved login, so the
            # page silently falls back to "close this tab" when no address comes back.
            next_url = ""
            if on_success is not None:
                try:
                    next_url = on_success() or ""
                except Exception:
                    next_url = ""
            self._send(200, json.dumps({"ok": True, "next": next_url}))
            done.set()

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    url = f"http://127.0.0.1:{port}/?state={state}"
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    if on_url is not None:
        on_url(url)
    else:
        print(f"已在浏览器打开登录页：{url}")
        print("（若未自动弹出，请手动复制上面地址到浏览器）")
    if open_browser:
        with contextlib.suppress(Exception):
            webbrowser.open(url)
    try:
        ok = done.wait(timeout)
    except KeyboardInterrupt:
        ok = False
    with contextlib.suppress(Exception):
        httpd.shutdown()
    if ok and result.get("token"):
        return True, f"登录成功（uid={result.get('userId')}，{result.get('email')}）"
    return False, "web 登录超时或取消"


# ----- Authentication lifecycle listeners ---------------------------------

def _notify_auth(event: str) -> str:
    try:
        from . import auth
    except ImportError:  # direct script execution
        import auth
    identity = current_identity() if event == "login" else None
    token = get_token() if event == "login" else None
    return "\n".join(auth.notify(event, identity, token))
