"""Resident Windows interactive-session worker for GAnet atomic tools.

The SSH entry remains a noninteractive Session 0 process.  On Windows this module
starts a worker through a one-shot ``schtasks /IT`` task on first use and then
reuses it for the rest of the desktop session, so only the very first request of
a login pays the startup cost.  Nothing is installed at login: the worker lives
until the user logs off or shuts down, until a deploy replaces the code it
loaded, or until it is stopped explicitly.

The worker is found at a stable loopback port, the same convention the hub and the
other resident GA services use.  A port is released the moment its process dies,
which is why the listening socket alone can serve as the single-instance lock and
why no liveness bookkeeping has to be persisted.
"""
from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import locale
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable
from xml.sax.saxutils import escape as xml_escape

from .. import paths
from . import host_adapter


def runtime_identity() -> dict[str, str]:
    """Identify the GA runtime a worker belongs to.

    A published worker is only reusable by the interpreter and project that
    started it; another GA install writing the same state path must not have its
    worker adopted, because the tools would then run in the wrong environment.
    """
    return {"pythonExecutable": str(Path(sys.executable).resolve()),
            "projectRoot": str(host_adapter.bound_ga_root())}


def _runtime_seed() -> str:
    identity = runtime_identity()
    return (identity["pythonExecutable"] + "\0" + identity["projectRoot"]).lower()


def _runtime_slug() -> str:
    """Name the per-runtime files.

    Everything a worker publishes has to be scoped to the runtime allowed to reuse
    it.  One shared record for the whole machine would let two interpreters
    overwrite each other's entry in turn, and each would then keep cold-starting a
    worker while stranding the one it just displaced.
    """
    return hashlib.sha256(_runtime_seed().encode("utf-8")).hexdigest()[:12]


# Single-instance lock port.  Deliberately below the Windows dynamic range
# (49152+), so the system never hands it to an unrelated program behind our back.
_PORT_OVERRIDE = os.environ.get("GA_WORKER_PORT")
_PORT_BASE = int(_PORT_OVERRIDE or 19800)
_PORT_SPAN = 64
_START_SECONDS = 15
# A retiring worker needs a moment to release the port, so a handover must not
# fail merely because the outgoing process has not exited yet.
_BIND_SECONDS = 20
_CODE_CHECK_SECONDS = 10
_DRAIN_SECONDS = 30
_CONNECT_SECONDS = 10
# A tool may legitimately run far longer than the connect handshake.  ``code_run``
# alone is clamped to 300s, so the reply deadline has to clear that ceiling by a
# margin instead of reusing the connect timeout.
_REPLY_SECONDS = 360
_BACKLOG = 64
# Only one process may create a worker.  Losers wait for the winner to publish
# rather than racing it, which is what previously produced several workers that
# then evicted each other.
_START_LOCK_SECONDS = 90
_MAX_MESSAGE_BYTES = 8 * 1024 * 1024
_STATE_DIR = Path.home() / ".genericagent" / "ganet"
_STATE_PATH = _STATE_DIR / "interactive_worker_{}.json".format(_runtime_slug())
_START_LOCK_PATH = _STATE_PATH.with_suffix(".lock")
# Shared on purpose: one timeline for every runtime is what makes a collision
# between two of them readable afterwards.  Each line already carries its pid.
_LIFECYCLE_LOG_PATH = _STATE_DIR / "interactive_worker.log"
_WINDOWLESS_LAUNCHER_PATH = _STATE_DIR / "interactive_worker_launch.vbs"


def _lifecycle(event: str, **fields: Any) -> None:
    """Persist timing and request kind only; never log tokens or tool payloads."""
    try:
        _LIFECYCLE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        record = {"time": round(time.time(), 3), "pid": os.getpid(), "event": event}
        record.update(fields)
        with _LIFECYCLE_LOG_PATH.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError:
        pass


def _console_encoding() -> str:
    """Console tools write in the OEM code page, which need not be the Python default."""
    if os.name == "nt":
        with contextlib.suppress(Exception):
            import ctypes
            return "cp{}".format(ctypes.windll.kernel32.GetOEMCP())
    return locale.getpreferredencoding(False)


def _run(command: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout,
                          check=False, encoding=_console_encoding(), errors="replace",
                          creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _task_name() -> str:
    return "GenericAgent-GAnet-Interactive-" + secrets.token_hex(12)


def _write_windowless_launcher() -> Path:
    """Write a stable launcher which outlives the scheduled task that reads it."""
    _WINDOWLESS_LAUNCHER_PATH.parent.mkdir(parents=True, exist_ok=True)
    content = (
        'If WScript.Arguments.Count <> 1 Then WScript.Quit 2\r\n'
        'CreateObject("Wscript.Shell").Run WScript.Arguments(0), 0, False\r\n'
    )
    temporary = _WINDOWLESS_LAUNCHER_PATH.with_suffix(".tmp")
    temporary.write_text(content, encoding="ascii", newline="")
    os.replace(temporary, _WINDOWLESS_LAUNCHER_PATH)
    return _WINDOWLESS_LAUNCHER_PATH


def _create_interactive_task(task_name: str, command: str, arguments: str,
                             working_directory: Path) -> None:
    """Create a hidden one-shot desktop task that is also allowed on battery power."""
    descriptor, name = tempfile.mkstemp(prefix="ganet-task-", suffix=".xml")
    os.close(descriptor)
    path = Path(name)
    try:
        user = xml_escape(os.environ["USERNAME"])
        command_xml = xml_escape(command)
        args_xml = xml_escape(arguments)
        work_xml = xml_escape(str(working_directory))
        path.write_text(
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
            '<Arguments>{}</Arguments><WorkingDirectory>{}</WorkingDirectory>'
            '</Exec></Actions></Task>'.format(user, command_xml, args_xml, work_xml),
            encoding="utf-16")
        created = _run(["schtasks.exe", "/Create", "/TN", task_name, "/XML", str(path), "/F"])
        if created.returncode:
            detail = (created.stderr or created.stdout).strip()
            raise RuntimeError("无法创建交互桌面 Worker" + ("：" + detail[:300] if detail else ""))
    finally:
        with contextlib.suppress(OSError):
            path.unlink()


def _worker_port() -> int:
    """Derive the port from the runtime that is allowed to reuse the worker.

    The other resident GA services use a literal constant because each of them is
    meant to exist once per machine.  A worker is different: it may only be shared
    within one runtime identity, since its tools must run under the interpreter and
    project that started it.  A single machine-wide port would therefore promise
    what the identity check forbids — on this developer's box a conda run and a
    venv run both want the port while neither may adopt the other's worker, so
    whichever binds first locks the other out of device access entirely.  Deriving
    the port from that same identity keeps the port's scope equal to the reuse
    scope.  An explicit GA_WORKER_PORT still wins outright.
    """
    if _PORT_OVERRIDE:
        return _PORT_BASE
    offset = int.from_bytes(hashlib.sha256(_runtime_seed().encode("utf-8")).digest()[:2], "big")
    return _PORT_BASE + offset % _PORT_SPAN


def _code_fingerprint() -> str:
    """Digest the sources a worker serves requests from.

    A resident worker keeps running whatever it loaded at startup, so a deploy
    that replaces these files has to retire it.  Both sides compare the same
    digest: callers stop adopting a worker whose code is outdated, and the worker
    itself steps down once it notices the files beneath it changed.  Content is
    hashed rather than timestamps so that re-checking out identical files does not
    interrupt a live terminal for nothing.
    """
    digest = hashlib.sha256()
    for path in sorted(Path(__file__).resolve().parent.glob("*.py")):
        digest.update(path.name.encode("utf-8") + b"\0")
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"<unreadable>")
        digest.update(b"\0")
    return digest.hexdigest()


def _read_state() -> dict[str, Any] | None:
    try:
        value = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    if not all(isinstance(value.get(key), expected) for key, expected in
               (("token", str), ("pid", int), ("sessionId", int), ("codeFingerprint", str))):
        return None
    if len(value["token"]) < 32:
        return None
    if value["codeFingerprint"] != _code_fingerprint():
        return None
    identity = runtime_identity()
    if any(value.get(key) != expected for key, expected in identity.items()):
        return None
    return value


def _write_state(state: dict[str, Any]) -> None:
    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = _STATE_PATH.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, separators=(",", ":")), encoding="utf-8")
    os.replace(temporary, _STATE_PATH)


def _state_token() -> str | None:
    with contextlib.suppress(OSError, json.JSONDecodeError):
        current = json.loads(_STATE_PATH.read_text(encoding="utf-8"))
        if isinstance(current, dict) and isinstance(current.get("token"), str):
            return current["token"]
    return None


def _remove_state(token: str | None = None) -> None:
    if token is not None and _state_token() != token:
        return
    with contextlib.suppress(OSError):
        _STATE_PATH.unlink()


class WorkerUnreachable(RuntimeError):
    """The worker could not be reached, so the request never began running."""


def _send(state: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    """Run one request on the worker.

    Failing to connect and failing to hear back are different faults.  Only the
    former leaves the request unstarted, so only the former may be retried; a
    reply that is merely slow must never cause the request to be sent twice.
    """
    payload = json.dumps({"token": state["token"], "request": request},
                         ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > _MAX_MESSAGE_BYTES:
        raise RuntimeError("交互电脑工具请求过大")
    try:
        connection = socket.create_connection(("127.0.0.1", _worker_port()),
                                              timeout=_CONNECT_SECONDS)
    except OSError as exc:
        raise WorkerUnreachable("交互桌面 Worker 不可用") from exc
    try:
        with connection:
            connection.settimeout(_REPLY_SECONDS)
            connection.sendall(len(payload).to_bytes(4, "big") + payload)
            size = int.from_bytes(_receive_exact(connection, 4), "big")
            if size < 2 or size > _MAX_MESSAGE_BYTES:
                raise WorkerUnreachable("交互桌面 Worker 响应无效")
            raw = _receive_exact(connection, size)
    except OSError as exc:
        raise RuntimeError("交互电脑工具未返回结果：" + str(exc)[:200]) from exc
    # An unparsable reply cannot have come from our worker, so nothing was run
    # and replacing it is safe.  A reply that merely arrives late is a different
    # fault and stays non-retryable above.
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerUnreachable("交互桌面 Worker 响应无效") from exc
    if not isinstance(response, dict):
        raise WorkerUnreachable("交互桌面 Worker 响应无效")
    if response.get("workerRejected") is True:
        # Rejected before dispatch, so no tool ran and the credentials are simply
        # stale; without this the caller would keep failing against a worker it
        # can no longer authenticate to.
        raise WorkerUnreachable("交互桌面 Worker 凭据已失效")
    return response


def _receive_exact(connection: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = connection.recv(remaining)
        if not chunk:
            raise RuntimeError("交互电脑工具连接提前关闭")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


@contextlib.contextmanager
def _start_claim():
    """Yield True to the single process allowed to start a worker.

    Every phone request arrives as its own bridge process, so an in-process lock
    cannot order them.  The claim is an exclusive file create: the winner starts
    a worker, everyone else waits for it to publish.  A claim left behind by a
    killed process is reclaimed once it ages past the start window.
    """
    _START_LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    descriptor = None
    with contextlib.suppress(OSError):
        age = time.time() - _START_LOCK_PATH.stat().st_mtime
        if age > _START_LOCK_SECONDS:
            _START_LOCK_PATH.unlink()
    try:
        descriptor = os.open(_START_LOCK_PATH, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
    try:
        yield descriptor is not None
    finally:
        if descriptor is not None:
            os.close(descriptor)
            with contextlib.suppress(OSError):
                _START_LOCK_PATH.unlink()


def _await_published_worker(deadline: float) -> dict[str, Any] | None:
    """Wait for the claim holder to publish.  None once it released without one."""
    while time.monotonic() < deadline:
        state = _read_state()
        if state is not None:
            return state
        if not _START_LOCK_PATH.exists():
            return _read_state()
        time.sleep(0.1)
    return _read_state()


def _start_worker() -> dict[str, Any]:
    if os.name != "nt":
        raise RuntimeError("交互桌面 Worker 仅支持 Windows")
    started_at = time.monotonic()
    _lifecycle("start_enter")
    deadline = time.monotonic() + _START_LOCK_SECONDS
    failure: Exception | None = None
    while time.monotonic() < deadline:
        with _start_claim() as claimed:
            if claimed:
                _lifecycle("start_claimed", ms=int((time.monotonic() - started_at) * 1000))
                state = _read_state()
                if state is not None:
                    return state
                try:
                    return _spawn_worker()
                except RuntimeError as exc:
                    # Release the claim before retrying so a transient failure
                    # does not hold every other caller for the whole window.
                    failure = exc
                    continue
            _lifecycle("start_waiting", ms=int((time.monotonic() - started_at) * 1000))
            state = _await_published_worker(deadline)
            if state is not None:
                _lifecycle("start_adopted", ms=int((time.monotonic() - started_at) * 1000))
                return state
    _lifecycle("start_timeout", ms=int((time.monotonic() - started_at) * 1000),
               error=type(failure).__name__ if failure else "none")
    raise failure or RuntimeError("交互桌面 Worker 启动超时")


def _spawn_worker() -> dict[str, Any]:
    started_at = time.monotonic()
    task_name = _task_name()
    token = secrets.token_urlsafe(32)
    # The port travels on the command line instead of being derived again inside
    # the worker: a scheduled task starts from the login environment, so it would
    # not see a GA_WORKER_PORT set for this SSH session and the two sides would
    # disagree on where the worker lives.
    port = _worker_port()
    project_root = host_adapter.package_root()
    python_command = ('"{}" -X faulthandler "{}" --ga-root "{}" '
                      '--interactive-worker --port {} --token {}').format(
                          sys.executable, paths.package_entry(),
                          host_adapter.bound_ga_root(), port, token)
    launcher = _write_windowless_launcher()
    arguments = '//B "{}" "{}"'.format(launcher, python_command.replace('"', '""'))
    created_task = False
    try:
        _lifecycle("spawn_task_create")
        _create_interactive_task(task_name, "wscript.exe", arguments, project_root)
        created_task = True
        _lifecycle("spawn_task_created", ms=int((time.monotonic() - started_at) * 1000))
        started = _run(["schtasks.exe", "/Run", "/TN", task_name])
        if started.returncode:
            detail = (started.stderr or started.stdout).strip()
            _lifecycle("spawn_task_run_failed", code=started.returncode)
            raise RuntimeError("无法启动交互桌面 Worker" + ("：" + detail[:300] if detail else ""))
        _lifecycle("spawn_task_ran", ms=int((time.monotonic() - started_at) * 1000))
        deadline = time.monotonic() + _START_SECONDS
        while time.monotonic() < deadline:
            state = _read_state()
            # The token alone identifies the worker we just asked for; the record
            # no longer carries a port because the port is a constant both sides
            # already agree on.
            if state and state.get("token") == token:
                _lifecycle("spawn_published", ms=int((time.monotonic() - started_at) * 1000),
                           pid=state.get("pid"))
                return state
            time.sleep(0.1)
        _lifecycle("spawn_publish_timeout", ms=int((time.monotonic() - started_at) * 1000))
        raise RuntimeError("交互桌面 Worker 启动超时")
    finally:
        if created_task:
            with contextlib.suppress(Exception):
                _run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"])


def invoke(request: dict[str, Any]) -> dict[str, Any]:
    """Send one validated bridge request to the current user's interactive worker.

    Retrying is only safe while the request has not reached the worker, so an
    unreachable worker is retried once and every other fault is surfaced as-is.
    Anything else risks running a tool's side effects twice.
    """
    state = _read_state()
    for attempt in range(2):
        if state is None:
            state = _start_worker()
        try:
            return _send(state, request)
        except WorkerUnreachable:
            _remove_state(state.get("token"))
            state = None
            if attempt:
                raise
    raise RuntimeError("交互桌面 Worker 不可用")


def stop_worker() -> dict[str, Any]:
    """Retire the resident worker, the way ``/scheduler`` stops a background service.

    The token is read without checking the fingerprint on purpose: the worker most
    worth stopping by hand is precisely one left over from an earlier build, and a
    fingerprint check would refuse to look at it.
    """
    token = _state_token()
    if token is None:
        return {"ok": True, "stopped": False, "detail": "当前没有已发布的交互桌面 Worker"}
    try:
        response = _send({"token": token}, {"shutdown": True})
    except WorkerUnreachable:
        # Nothing is listening, so the desired state already holds; the leftover
        # record is what remains to clean up.
        _remove_state(token)
        return {"ok": True, "stopped": False, "detail": "交互桌面 Worker 未在运行，已清理残留记录"}
    except RuntimeError as exc:
        return {"ok": False, "stopped": False, "detail": str(exc)[:300]}
    if response.get("ok") is not True:
        return {"ok": False, "stopped": False,
                "detail": str(response.get("error") or "交互桌面 Worker 未确认停止")}
    _remove_state(token)
    return {"ok": True, "stopped": True, "detail": ""}


def _serve_connection(connection: socket.socket, token: str,
                      dispatch: Callable[[dict[str, Any]], dict[str, Any]],
                      shutdown: threading.Event | None = None) -> None:
    with connection:
        request: Any = None
        rejected = False
        try:
            size = int.from_bytes(_receive_exact(connection, 4), "big")
            if size < 2 or size > _MAX_MESSAGE_BYTES:
                raise ValueError("请求无效")
            payload = json.loads(_receive_exact(connection, size).decode("utf-8"))
            # Capture the caller's identity before authenticating: a rejected
            # request still has to be answered in terms the caller can match,
            # otherwise its real error is reported as a context mismatch.
            if isinstance(payload, dict):
                request = payload.get("request")
            if not isinstance(payload, dict) or payload.get("token") != token or not isinstance(request, dict):
                # Flagged so the caller can tell "wrong credentials, nothing ran"
                # apart from a tool that genuinely failed.
                rejected = True
                raise ValueError("交互桌面 Worker 认证失败")
            if request.get("shutdown") is True:
                _lifecycle("request_shutdown")
                if shutdown is not None:
                    shutdown.set()
                response = {"ok": True, "result": {"stopped": True}, "error": None}
            else:
                tool = str(request.get("tool") or "")
                arguments = request.get("arguments")
                action = str(arguments.get("action") or "") if isinstance(arguments, dict) else ""
                started = time.monotonic()
                _lifecycle("request_start", tool=tool, action=action)
                response = dispatch(request)
                _lifecycle("request_done", tool=tool, action=action,
                           ms=int((time.monotonic() - started) * 1000),
                           ok=isinstance(response, dict) and response.get("ok") is True)
        except Exception as exc:
            _lifecycle("request_exception", error=type(exc).__name__)
            response = {"ok": False, "result": None,
                        "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
            if rejected:
                response["workerRejected"] = True
        response = _identified(response, request)
        raw = json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(raw) > _MAX_MESSAGE_BYTES:
            raw = json.dumps(_identified(
                {"ok": False, "result": None, "error": "交互电脑工具响应过大"}, request),
                ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        connection.sendall(len(raw).to_bytes(4, "big") + raw)


def _identified(response: dict[str, Any], request: Any) -> dict[str, Any]:
    """Stamp a reply with the protocol and request id its caller will check."""
    if not isinstance(response, dict):
        return response
    value = dict(response)
    if isinstance(request, dict):
        value.setdefault("protocol", request.get("protocol"))
        value.setdefault("requestId", request.get("requestId"))
    value.setdefault("protocol", None)
    value.setdefault("requestId", None)
    return value


def _bind_listener(port: int) -> socket.socket:
    """Claim the fixed port; the listening socket is itself the single-instance lock.

    Retrying covers a handover: the worker being replaced only releases the port
    once it has finished stepping down, and failing the takeover for those few
    seconds would leave the desktop with no worker at all.
    """
    deadline = time.monotonic() + _BIND_SECONDS
    while True:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError as exc:
            listener.close()
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    f"交互桌面 Worker 端口 {port} 已被占用；"
                    "可设置环境变量 GA_WORKER_PORT 换一个端口") from exc
            time.sleep(0.5)
            continue
        listener.listen(_BACKLOG)
        listener.settimeout(1.0)
        return listener


def serve(*, port: int, token: str,
          dispatch: Callable[[dict[str, Any]], dict[str, Any]]) -> int:
    """Run in the interactive Session.  The listener is loopback-only and token-gated.

    The worker is resident: it serves every request of the desktop session so only
    the first one pays the startup cost.  It leaves on three occasions — an
    explicit stop, a deploy that changed the code beneath it, and the session
    ending at logoff or shutdown, which the OS takes care of.
    """
    if os.name != "nt":
        raise RuntimeError("交互桌面 Worker 仅支持 Windows")
    if not 1 <= port <= 65535 or len(token) < 32:
        raise ValueError("交互桌面 Worker 参数无效")
    listener = _bind_listener(port)
    fingerprint = _code_fingerprint()
    session_id = _current_session_id()
    state = {"token": token, "pid": os.getpid(), "sessionId": session_id,
             "codeFingerprint": fingerprint, **runtime_identity()}
    _write_state(state)
    _lifecycle("worker_started", sessionId=session_id, port=port)
    # Requests are served concurrently so a long tool does not hold the accept
    # loop and freeze screenshots or other interactive requests.
    active = _ActiveRequests()
    shutdown = threading.Event()
    reason = "stopped"
    checked = time.monotonic()
    try:
        while not shutdown.is_set():
            if time.monotonic() - checked >= _CODE_CHECK_SECONDS:
                checked = time.monotonic()
                if _code_fingerprint() != fingerprint:
                    reason = "code_changed"
                    break
            try:
                connection, _ = listener.accept()
            except socket.timeout:
                continue
            active.start(connection, token, dispatch, shutdown)
    finally:
        # Stop accepting first, then let running tools answer their callers, so
        # stepping down never truncates a reply that is already on its way.
        listener.close()
        active.drain(_DRAIN_SECONDS)
        _remove_state(token)
        _lifecycle("worker_stopped", reason=reason, active=active.busy())
    return 0


class _ActiveRequests:
    """Track in-flight request threads so retiring cannot cut one short."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._count = 0

    def busy(self) -> bool:
        with self._lock:
            return self._count > 0

    def drain(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while self.busy() and time.monotonic() < deadline:
            time.sleep(0.1)

    def start(self, connection: socket.socket, token: str,
              dispatch: Callable[[dict[str, Any]], dict[str, Any]],
              shutdown: threading.Event | None = None) -> None:
        with self._lock:
            self._count += 1

        def run() -> None:
            try:
                _serve_connection(connection, token, dispatch, shutdown)
            except Exception:
                # _serve_connection already answers its caller; a socket that died
                # mid-reply must not take the worker down with it.
                with contextlib.suppress(OSError):
                    connection.close()
            finally:
                with self._lock:
                    self._count -= 1

        threading.Thread(target=run, name="ga-worker-request", daemon=True).start()


def _current_session_id() -> int:
    try:
        import ctypes
        session_id = ctypes.c_uint32()
        if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(session_id)):
            return int(session_id.value)
    except Exception:
        pass
    return 0
