"""Capture the logged-in Windows desktop for the GAnet screenshot atomic tool.

Capture runs in Python rather than a PowerShell worker.  Defender's AMSI matches
a PowerShell script that combines a user32 P/Invoke with ``CopyFromScreen``
against ``HackTool:PowerShell/EmpireGetScreenshot``, and the block happens at
parse time, so a script cannot even report its own failure.  Pillow is already a
declared device dependency for exactly this capture.

The SSH entry itself is Session 0.  Callers that already run inside the user's
interactive session capture in-process; the Session 0 fallback drives a one-shot
``schtasks /IT`` task that launches Python's GUI-subsystem host, rather than a
console host, so requests do not flash a terminal window on the user's desktop.
"""
from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape as xml_escape

_MAX_IMAGE_BYTES = 5 * 1024 * 1024
_WAIT_SECONDS = 30
_JPEG_QUALITY = 80


def _run(command: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, timeout=timeout,
                          check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))


def _task_name() -> str:
    return "GenericAgent-GAnet-Screenshot-" + secrets.token_hex(12)


def _enable_dpi_awareness() -> None:
    """Opt this process into physical pixels before the desktop is measured.

    A scheduled task starts a DPI-unaware host, and Windows then virtualizes a
    1920x1080 desktop to e.g. 1536x864 at 125% scaling.  Both calls are per
    process and one-way, so a second call simply reports failure and is ignored.
    """
    with contextlib.suppress(Exception):
        import ctypes
        user32 = ctypes.windll.user32
        # -4 is DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2.
        if not user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
            user32.SetProcessDPIAware()


def _session_id() -> int:
    """Report the desktop session the capture actually came from.

    Windows uses the real session id. On macOS a launchd user agent already
    runs in the login session, so the uid identifies it; the phone treats any
    positive value as a valid interactive session.
    """
    if os.name != "nt":
        return max(1, os.getuid())
    with contextlib.suppress(Exception):
        import ctypes
        value = ctypes.c_uint32()
        if ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(value)):
            return int(value.value)
    return 0


_MACOS_SCREEN_PERMISSION_HINT = (
    "macOS 未授予屏幕录制权限：请在“系统设置 → 隐私与安全性 → 屏幕录制”中允许 "
    "ganet-sidecar，然后重试"
)


def _macos_screen_capture_allowed() -> bool | None:
    """Ask TCC whether this process may capture the screen.

    Without the permission ``screencapture`` still succeeds but returns only the
    wallpaper and menu bar, so the failure must be detected up front. Returns
    ``None`` when the check itself is unavailable.
    """
    try:
        import ctypes
        core_graphics = ctypes.cdll.LoadLibrary(
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics")
        core_graphics.CGPreflightScreenCaptureAccess.restype = ctypes.c_bool
        core_graphics.CGRequestScreenCaptureAccess.restype = ctypes.c_bool
    except (OSError, AttributeError):
        return None
    if core_graphics.CGPreflightScreenCaptureAccess():
        return True
    # Triggers the one-time system prompt for the responsible process; the
    # current call still fails so the user gets an actionable message.
    with contextlib.suppress(Exception):
        core_graphics.CGRequestScreenCaptureAccess()
    return False


def _capture_here() -> tuple[dict[str, Any], bytes]:
    """Capture the whole virtual desktop from the calling process."""
    if os.name != "nt" and sys.platform != "darwin":
        raise RuntimeError("电脑截图仅支持 Windows 与 macOS")
    try:
        from PIL import ImageGrab
    except ImportError as exc:
        raise RuntimeError("缺少电脑截图组件 Pillow") from exc
    if sys.platform == "darwin":
        if _macos_screen_capture_allowed() is False:
            raise RuntimeError(_MACOS_SCREEN_PERMISSION_HINT)
    else:
        _enable_dpi_awareness()
    image = ImageGrab.grab(all_screens=True)
    try:
        width, height = image.size
        if width < 1 or height < 1:
            raise RuntimeError("未检测到交互桌面显示区域")
        buffer = io.BytesIO()
        image.convert("RGB").save(buffer, format="JPEG", quality=_JPEG_QUALITY)
    finally:
        image.close()
    data = buffer.getvalue()
    if len(data) > _MAX_IMAGE_BYTES:
        raise RuntimeError("截图文件无效或过大")
    return {"contentType": "image/jpeg", "contentLength": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), "width": width,
            "height": height, "sessionId": _session_id()}, data


def _pythonw_executable() -> Path:
    """Use the GUI Python host so a one-shot desktop task has no terminal window."""
    pythonw = Path(sys.executable).with_name("pythonw.exe")
    return pythonw if pythonw.is_file() else Path(sys.executable)


def _create_interactive_task(task_name: str, work_dir: Path) -> None:
    """Create a hidden one-shot desktop task which is also allowed on battery."""
    descriptor, name = tempfile.mkstemp(prefix="ganet-screenshot-task-", suffix=".xml")
    os.close(descriptor)
    path = Path(name)
    try:
        user = xml_escape(os.environ["USERNAME"])
        script_path = Path(__file__).resolve()
        arguments = xml_escape('"{}" --capture-to "{}"'.format(script_path, work_dir))
        project_root = xml_escape(str(Path(__file__).resolve().parents[2]))
        pythonw = xml_escape(str(_pythonw_executable()))
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
            '<ExecutionTimeLimit>PT2M</ExecutionTimeLimit>'
            '</Settings><Actions Context="Author"><Exec><Command>{}</Command>'
            '<Arguments>{}</Arguments><WorkingDirectory>{}</WorkingDirectory>'
            '</Exec></Actions></Task>'.format(user, pythonw, arguments, project_root),
            encoding="utf-16")
        created = _run(["schtasks.exe", "/Create", "/TN", task_name, "/XML", str(path), "/F"])
        if created.returncode:
            detail = (created.stderr or created.stdout).strip()
            raise RuntimeError("无法创建交互截图任务" + ("：" + detail[:300] if detail else ""))
    finally:
        with contextlib.suppress(OSError):
            path.unlink()


def capture_to(work_dir: Path) -> int:
    """Capture on behalf of a Session 0 caller, reporting through ``work_dir``.

    The marker is written first so the caller can tell a worker that never
    started from one that started and then failed; a bare timeout cannot.
    """
    started_path = work_dir / "started"
    result_path = work_dir / "result.json"
    with contextlib.suppress(OSError):
        started_path.write_text(str(os.getpid()), encoding="utf-8")
    try:
        metadata, image = _capture_here()
        (work_dir / "desktop.jpg").write_bytes(image)
        result_path.write_text(json.dumps({"ok": True, **metadata}), encoding="utf-8")
        return 0
    except Exception as exc:
        with contextlib.suppress(OSError):
            result_path.write_text(
                json.dumps({"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:300]}"},
                           ensure_ascii=False), encoding="utf-8")
        return 1


def _validate_capture(image_path: Path, result_path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        result = json.loads(result_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("交互截图结果无效") from exc
    if not isinstance(result, dict) or result.get("ok") is not True:
        raise RuntimeError(str(result.get("error") if isinstance(result, dict) else "截图任务失败")[:300])
    if not image_path.is_file():
        raise RuntimeError("交互截图未生成图片")
    image = image_path.read_bytes()
    if not image.startswith(b"\xff\xd8\xff") or len(image) > _MAX_IMAGE_BYTES:
        raise RuntimeError("截图文件无效或过大")
    width, height = result.get("width"), result.get("height")
    session_id = result.get("sessionId")
    if not all(isinstance(v, int) and v > 0 for v in (width, height)) \
            or not isinstance(session_id, int):
        raise RuntimeError("截图元数据无效")
    return {"contentType": "image/jpeg", "contentLength": len(image),
            "sha256": hashlib.sha256(image).hexdigest(), "width": width,
            "height": height, "sessionId": session_id}, image


def _timeout_detail(task_name: str, started_path: Path) -> str:
    """Name the stage that stalled instead of reporting a bare timeout."""
    if started_path.is_file():
        return "交互截图进程已启动但未返回结果"
    query = _run(["schtasks.exe", "/Query", "/TN", task_name, "/V", "/FO", "LIST"])
    code = next((line.split(":", 1)[1].strip()
                 for line in (query.stdout or "").splitlines()
                 if line.split(":", 1)[0].strip() in ("上次结果", "Last Result")), "")
    return "交互截图进程未能启动" + (f"（计划任务上次结果 {code}）" if code else "")


def capture_current_session() -> tuple[dict[str, Any], bytes]:
    """Capture directly from the caller's already-interactive Windows Session."""
    return _capture_here()


def capture() -> tuple[dict[str, Any], bytes]:
    """Return verified JPEG bytes captured in the current interactive desktop session."""
    if sys.platform == "darwin":
        # No Session 0 detour exists on macOS; the caller is already in the GUI session.
        return _capture_here()
    if os.name != "nt":
        raise RuntimeError("电脑截图仅支持 Windows 与 macOS")

    work_dir = Path(tempfile.mkdtemp(prefix="ganet-screenshot-"))
    task_name = _task_name()
    started_path = work_dir / "started"
    image_path = work_dir / "desktop.jpg"
    result_path = work_dir / "result.json"
    created_task = False
    try:
        _create_interactive_task(task_name, work_dir)
        created_task = True
        started = _run(["schtasks.exe", "/Run", "/TN", task_name])
        if started.returncode:
            detail = (started.stderr or started.stdout).strip()
            raise RuntimeError("无法启动交互截图任务" + ("：" + detail[:300] if detail else ""))

        deadline = time.monotonic() + _WAIT_SECONDS
        while time.monotonic() < deadline:
            if result_path.is_file():
                break
            time.sleep(0.1)
        if not result_path.is_file():
            raise RuntimeError(_timeout_detail(task_name, started_path))
        return _validate_capture(image_path, result_path)
    finally:
        if created_task:
            with contextlib.suppress(Exception):
                _run(["schtasks.exe", "/Delete", "/TN", task_name, "/F"])
        shutil.rmtree(work_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) == 2 and argv[0] == "--capture-to":
        return capture_to(Path(argv[1]))
    print("用法: python -m ganet.device_access.screenshot --capture-to <目录>")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
