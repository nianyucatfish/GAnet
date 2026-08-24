from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path

import pytest

from ganet.device_access import bridge, host_adapter


GA_ROOT = Path(__file__).resolve().parents[2] / "GenericAgent"
GA_PYTHON = GA_ROOT / ".venv" / "Scripts" / "python.exe"


def _request(tool: str, arguments: dict, suffix: str) -> dict:
    return {
        "protocol": 1,
        "requestId": "req_" + suffix,
        "tool": tool,
        "arguments": arguments,
    }


def _invoke_host(request: dict) -> dict:
    completed = subprocess.run(
        [
            str(GA_PYTHON),
            str(Path(__file__).resolve().parents[1] / "ganet" / "host_entry.py"),
            "--ga-root",
            str(GA_ROOT),
        ],
        input=json.dumps(request),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=Path.home(),
        timeout=30,
    )
    lines = [line for line in completed.stdout.splitlines() if line.strip()]
    assert lines, completed.stderr
    response = json.loads(lines[-1])
    assert completed.returncode == (0 if response.get("ok") else 1), response
    return response


@pytest.fixture(scope="module", autouse=True)
def verified_host() -> None:
    if not GA_PYTHON.is_file():
        pytest.skip("GenericAgent test Python is unavailable")
    report = host_adapter.probe_target(GA_ROOT, GA_PYTHON)
    assert report["ok"] is True, report


def test_catalog_is_loaded_from_bound_genericagent() -> None:
    host_adapter.configure_process_root(GA_ROOT)
    host_adapter._ADAPTER = None

    catalog = bridge.tool_catalog()

    names = {item["name"] for item in catalog}
    assert names == {
        "code_run",
        "file_read",
        "file_patch",
        "file_write",
        "web_scan",
        "web_execute_js",
        "computer_screenshot",
    }


def test_code_and_file_tools_keep_original_contract() -> None:
    relative = "ganet_bridge_contract_" + uuid.uuid4().hex + ".txt"
    target = GA_ROOT / "temp" / relative
    try:
        write = _invoke_host(_request(
            "file_write", {"path": relative, "content": "alpha\nbeta\n"}, "write"
        ))
        assert write["ok"] is True
        assert target.read_text(encoding="utf-8") == "alpha\nbeta\n"

        read = _invoke_host(_request("file_read", {"path": relative}, "read"))
        assert read["ok"] is True
        assert "alpha" in json.dumps(read["result"], ensure_ascii=False)

        patch = _invoke_host(_request(
            "file_patch",
            {"path": relative, "old_content": "beta", "new_content": "gamma"},
            "patch",
        ))
        assert patch["ok"] is True
        assert target.read_text(encoding="utf-8") == "alpha\ngamma\n"

        run = _invoke_host(_request(
            "code_run", {"script": "print(6 * 7)", "type": "python", "timeout": 20}, "run"
        ))
        assert run["ok"] is True
        assert run["result"]["stdout"].strip() == "42"
    finally:
        target.unlink(missing_ok=True)


def test_web_tools_dispatch_through_original_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    host_adapter.configure_process_root(GA_ROOT)
    host_adapter._ADAPTER = None
    adapter = host_adapter.current_adapter()
    calls = []

    class Handler:
        def dispatch(self, tool, arguments, response):
            calls.append((tool, arguments))
            if False:
                yield None
            return type("Outcome", (), {"data": {"tool": tool}})()

    monkeypatch.setattr(
        host_adapter.GenericAgentHostAdapter, "handler", lambda self: Handler()
    )

    scan = bridge.handle(_request("web_scan", {"tabs_only": True}, "scan"))
    execute = bridge.handle(_request(
        "web_execute_js", {"script": "document.title", "no_monitor": True}, "js"
    ))

    assert scan["ok"] is True
    assert execute["ok"] is True
    assert calls == [
        ("web_scan", {"tabs_only": True}),
        ("web_execute_js", {"script": "document.title", "no_monitor": True}),
    ]


def test_unknown_arguments_and_inline_eval_are_rejected() -> None:
    unknown = _invoke_host(_request("file_read", {"path": "x", "extra": True}, "unknown"))
    inline = _invoke_host(_request(
        "code_run", {"script": "1", "type": "python", "inline_eval": True}, "inline"
    ))

    assert unknown["ok"] is False
    assert "未知参数" in unknown["error"]
    assert inline["ok"] is False
    assert "inline_eval" in inline["error"]
