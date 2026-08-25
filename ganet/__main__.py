"""GAnet command-line entry point."""
from __future__ import annotations

import argparse
import json
import re
import threading
import webbrowser

_URL_PATTERN = re.compile(r"https?://[^\s]+")


def _open_user_center() -> int:
    from . import open_user_center
    from .component_location import refresh_location
    from .device_access.host_adapter import refresh_launcher

    component = refresh_location()
    if not component.get("ok"):
        raise RuntimeError(str(component.get("error") or "GAnet 组件不完整"))
    refresh_launcher()
    message = open_user_center()
    match = _URL_PATTERN.search(message)
    if not match:
        raise RuntimeError(message)
    url = match.group(0)
    print(message)
    webbrowser.open(url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ganet", description="Open the GAnet user center.")
    parser.add_argument("command", nargs="?", help=argparse.SUPPRESS)
    parser.add_argument("--ga-root", help=argparse.SUPPRESS)
    parser.add_argument("--ga-python", help=argparse.SUPPRESS)
    parser.add_argument("--repair", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.command == "inspect-component":
        from .component_location import inspect_component

        result = inspect_component()
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result.get("ok") else 1
    if args.command == "configure-host":
        if not args.ga_root or not args.ga_python:
            parser.error("内部配置入口缺少运行环境参数")
        from .component_location import refresh_location
        from .device_access.host_adapter import configure_host

        component = refresh_location()
        if not component.get("ok"):
            raise RuntimeError(str(component.get("error") or "GAnet 组件不完整"))
        result = configure_host(args.ga_root, args.ga_python, replace=args.repair)
        print("设备访问环境已准备：" + result["projectRoot"])
        return 0
    if args.command is not None:
        parser.error("未知命令")
    return _open_user_center()


if __name__ == "__main__":
    raise SystemExit(main())
