"""Single-request JSON bridge to the computer GA's existing atomic tools."""
from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from . import host_adapter, tools

PROTOCOL_VERSION = 1
NATIVE_TOOLS = tools.BRIDGE_NATIVE_TOOL_NAMES
DEVICE_TOOLS = tuple(tools.BRIDGE_DEVICE_TOOL_SCHEMAS)
ALLOWED_TOOLS = tools.bridge_tool_names()
MAX_REQUEST_BYTES = 256 * 1024
MAX_RESULT_CHARS = 256 * 1024
MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024


def project_root() -> Path:
    return host_adapter.bound_ga_root()


def tool_cwd() -> Path:
    return host_adapter.current_adapter().tool_cwd


def _load_schema() -> dict[str, dict[str, Any]]:
    schemas = dict(host_adapter.current_adapter().schemas)
    schemas.update(tools.BRIDGE_DEVICE_TOOL_SCHEMAS)
    return schemas


def tool_catalog() -> list[dict[str, Any]]:
    """Return legacy bridge-only tool schemas for pre-capability clients."""
    schemas = _load_schema()
    catalog = []
    for name in ALLOWED_TOOLS:
        function = schemas[name]
        parameters = json.loads(json.dumps(function["parameters"], ensure_ascii=False))
        if name == "code_run":
            tool_type = parameters["properties"]["type"]
            tool_type["enum"] = ["python", "powershell"] if os.name == "nt" else ["python", "bash"]
        catalog.append({"name": name, "description": function["description"],
                        "parameters": parameters})
    return catalog


def capability_catalog() -> list[dict[str, Any]]:
    """Return every paired-device capability and its selected transport."""
    schemas = _load_schema()
    bridge_schemas = {}
    for item in tool_catalog():
        bridge_schemas[item["name"]] = item
    return tools.capability_catalog(bridge_schemas)


def check() -> dict[str, Any]:
    try:
        adapter = host_adapter.current_adapter()
        schemas = _load_schema()
    except Exception as exc:
        return {"ok": False, "protocol": PROTOCOL_VERSION,
                "error": f"电脑工具模块加载失败：{type(exc).__name__}: {exc}"}
    return {"ok": True, "protocol": PROTOCOL_VERSION,
            "pythonExecutable": str(Path(sys.executable).resolve()),
            "projectRoot": str(adapter.ga_root), "toolCwd": str(adapter.tool_cwd),
            "tools": [schemas[name] for name in ALLOWED_TOOLS]}


def _validate_request(value: Any) -> tuple[str, str, dict[str, Any]]:
    if not isinstance(value, dict) or set(value) != {"protocol", "requestId", "tool", "arguments"}:
        raise ValueError("请求字段无效")
    if value["protocol"] != PROTOCOL_VERSION:
        raise ValueError("协议版本不支持")
    request_id = value["requestId"]
    if not isinstance(request_id, str) or not request_id.startswith("req_") or len(request_id) > 80:
        raise ValueError("requestId 无效")
    tool = value["tool"]
    schemas = _load_schema()
    if tool not in schemas:
        raise ValueError("电脑工具不允许调用")
    arguments = value["arguments"]
    if not isinstance(arguments, dict):
        raise ValueError("arguments 必须是对象")
    properties = schemas[tool]["parameters"].get("properties", {})
    if set(arguments) - set(properties):
        raise ValueError("电脑工具包含未知参数")
    for name, spec in properties.items():
        if name not in arguments:
            continue
        value = arguments[name]
        expected = spec.get("type")
        if expected == "string" and not isinstance(value, str):
            raise ValueError(f"{name} 必须是字符串")
        if expected == "integer" and (isinstance(value, bool) or not isinstance(value, int)):
            raise ValueError(f"{name} 必须是整数")
        if expected == "boolean" and not isinstance(value, bool):
            raise ValueError(f"{name} 必须是布尔值")
        enum = spec.get("enum")
        if enum and value not in enum:
            if not (tool == "code_run" and name == "type" and os.name != "nt" and value == "bash"):
                raise ValueError(f"{name} 取值无效")
    if tool == "code_run" and arguments.get("inline_eval"):
        raise ValueError("远程 code_run 不允许 inline_eval")
    required = {"code_run": ("script",), "file_read": ("path",),
                "file_patch": ("path", "old_content", "new_content"),
                "file_write": ("path", "content"), "web_scan": (),
                "web_execute_js": ("script",), "computer_screenshot": ()}[tool]
    if any(name not in arguments for name in required):
        raise ValueError("电脑工具缺少必要参数")
    return request_id, tool, dict(arguments)


def _invoke(tool: str, arguments: dict[str, Any]) -> Any:
    args = dict(arguments)
    if tool == "code_run":
        args["timeout"] = max(1, min(int(args.get("timeout", 60)), 300))
        if os.name != "nt" and args.get("type") == "powershell":
            args["type"] = "bash"
    adapter = host_adapter.current_adapter()
    from types import SimpleNamespace
    response = SimpleNamespace(content="")
    outcome = adapter.exhaust(adapter.handler().dispatch(tool, args, response))
    return getattr(outcome, "data", outcome)


def _quiet_tools(enabled: bool):
    """Keep tool prints out of stdout only when stdout carries the reply.

    ``redirect_stdout`` swaps a process-global, so concurrent worker threads
    would restore each other's streams and leak the buffers they replaced.  The
    worker answers over its socket and never parses stdout, so it opts out.
    """
    if not enabled:
        return contextlib.nullcontext()
    stack = contextlib.ExitStack()
    stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
    return stack


def handle(value: Any, *, capture_output: bool = True) -> dict[str, Any]:
    request_id = value.get("requestId") if isinstance(value, dict) else None
    try:
        request_id, tool, arguments = _validate_request(value)
        with _quiet_tools(capture_output):
            result = _invoke(tool, arguments)
        encoded = json.dumps(result, ensure_ascii=False, default=str)
        if len(encoded) > MAX_RESULT_CHARS:
            raise ValueError("电脑工具返回内容过大")
        return {"protocol": PROTOCOL_VERSION, "requestId": request_id,
                "ok": True, "result": result, "error": None}
    except Exception as exc:
        return {"protocol": PROTOCOL_VERSION, "requestId": request_id,
                "ok": False, "result": None,
                "error": f"{type(exc).__name__}: {str(exc)[:500]}"}


def _read_stdin_request() -> Any:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("请求内容过大")
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise ValueError(f"JSON 请求无效：{exc}") from exc


def _serve_stdin() -> dict[str, Any]:
    request_id = None
    try:
        request = _read_stdin_request()
        request_id = request.get("requestId") if isinstance(request, dict) else None
        from . import interactive_worker
        return interactive_worker.invoke(request)
    except Exception as exc:
        return {"protocol": PROTOCOL_VERSION, "requestId": request_id, "ok": False,
                "result": None, "error": f"{type(exc).__name__}: {exc}"}


def _screenshot_response(request: dict[str, Any], *, current_session: bool = False) -> dict[str, Any]:
    request_id, tool, arguments = _validate_request(request)
    if tool != "computer_screenshot" or arguments:
        raise ValueError("截图入口只接受 computer_screenshot 空参数请求")
    from .screenshot import capture, capture_current_session
    metadata, image = (capture_current_session() if current_session else capture())
    if len(image) > MAX_SCREENSHOT_BYTES:
        raise ValueError("截图内容过大")
    return {"protocol": PROTOCOL_VERSION, "requestId": request_id, "ok": True, "error": None,
            **metadata, "image": base64.b64encode(image).decode("ascii")}


def _serve_screenshot() -> int:
    """Write one JSON header line followed by bounded JPEG bytes to stdout."""
    request_id = None
    try:
        request = _read_stdin_request()
        request_id = request.get("requestId") if isinstance(request, dict) else None
        from . import interactive_worker
        response = interactive_worker.invoke(request)
        if response.get("ok") is not True:
            raise RuntimeError(str(response.get("error") or "交互截图失败"))
        image = base64.b64decode(response.pop("image"), validate=True)
        sys.stdout.buffer.write(json.dumps(response, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        sys.stdout.buffer.write(image)
        sys.stdout.buffer.flush()
        return 0
    except Exception as exc:
        header = {"protocol": PROTOCOL_VERSION, "requestId": request_id, "ok": False,
                  "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
        sys.stdout.buffer.write(json.dumps(header, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        sys.stdout.buffer.flush()
        return 1


def _interactive_dispatch(request: dict[str, Any]) -> dict[str, Any]:
    """Run the same allowed atomic request inside the verified desktop Session."""
    try:
        if request.get("tool") == "computer_screenshot":
            return _screenshot_response(request, current_session=True)
        return handle(request, capture_output=False)
    except Exception as exc:
        request_id = request.get("requestId") if isinstance(request, dict) else None
        return {"protocol": PROTOCOL_VERSION, "requestId": request_id, "ok": False,
                "result": None, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GAnet 电脑原子工具入口")
    parser.add_argument("--ga-root", help=argparse.SUPPRESS)
    parser.add_argument("--check", action="store_true", help="验证当前电脑 GA 运行环境")
    parser.add_argument("--catalog", action="store_true", help="返回允许远程调用的正式工具描述")
    parser.add_argument("--screenshot", action="store_true", help="流式返回交互桌面截图")
    parser.add_argument("--interactive-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--stop-worker", action="store_true",
                        help="停止常驻的交互桌面 Worker（部署新代码或排查时使用）")
    parser.add_argument("--port", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--token", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    host_adapter.configure_process_root(args.ga_root)
    if args.interactive_worker:
        if args.port is None or args.token is None:
            parser.error("interactive worker 参数不完整")
        from . import interactive_worker
        return interactive_worker.serve(port=args.port, token=args.token,
                                       dispatch=_interactive_dispatch)
    if args.stop_worker:
        from . import interactive_worker
        result = {"protocol": PROTOCOL_VERSION, **interactive_worker.stop_worker()}
    elif args.screenshot:
        return _serve_screenshot()
    elif args.check:
        result = check()
    elif args.catalog:
        # ``tools`` preserves the deployed client contract. ``capabilities`` is the
        # complete agent-facing contract; dispatch transport remains private.
        result = {"ok": True, "protocol": PROTOCOL_VERSION,
                  "tools": tool_catalog(), "capabilities": capability_catalog()}
    else:
        result = _serve_stdin()
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), default=str))
    return 0 if result.get("ok") else 1


# ---- explicit GenericAgent host binding ----


def configure_host(ga_root: str, ga_python: str, *, replace: bool = False) -> dict[str, Any]:
    return host_adapter.configure_host(ga_root, ga_python, replace=replace)


def validate(timeout: int = 20) -> dict[str, Any]:
    return host_adapter.validate_binding(timeout=timeout)


if __name__ == "__main__":
    raise SystemExit(main())
