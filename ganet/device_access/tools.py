"""Single paired-computer capability directory.

Private dispatch metadata stays in this module. Phone agents receive only public
names, descriptions, parameters, and operations; they never need transport or
implementation details.
"""
from __future__ import annotations

from typing import Any


BRIDGE_NATIVE_TOOL_NAMES = (
    "code_run", "file_read", "file_patch", "file_write", "web_scan", "web_execute_js",
)

BRIDGE_DEVICE_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {
    "computer_screenshot": {
        "name": "computer_screenshot",
        "description": (
            "Capture the current logged-in computer desktop and return it to the paired "
            "phone. Use when the user needs to see or visually verify the computer. Before "
            "calling, make the target window visible and foreground; for a browser, bring "
            "the target tab to front with web_execute_js CDP Page.bringToFront. Do not use "
            "a browser Page.captureScreenshot as a substitute. The result includes Markdown "
            "that must be cited verbatim in the final reply."
        ),
        "parameters": {"type": "object", "properties": {}},
    },
}


CAPABILITIES: dict[str, dict[str, Any]] = {
    **{
        name: {"name": name, "transport": "bridge", "kind": "atomic"}
        for name in BRIDGE_NATIVE_TOOL_NAMES
    },
    "computer_screenshot": {
        "name": "computer_screenshot", "transport": "bridge", "kind": "desktop",
        "interactiveSession": True,
    },
    "file_transfer": {
        "name": "file_transfer", "transport": "sftp", "kind": "files",
        "description": (
            "Stream one file between the paired phone and computer. Relative computer "
            "paths use the computer atomic-tool working directory; relative phone paths "
            "use the phone artifact directory. Existing destinations are not overwritten "
            "unless overwrite is true."
        ),
        "operations": ("upload", "download"),
        "parameters": {
            "oneOf": (
                {
                    "type": "object", "additionalProperties": False,
                    "properties": {
                        "action": {"const": "upload"},
                        "local_path": {"type": "string", "description": "Phone source file."},
                        "remote_path": {"type": "string", "description": "Computer destination; defaults to the source name."},
                        "overwrite": {"type": "boolean", "default": False},
                    },
                    "required": ("action", "local_path"),
                },
                {
                    "type": "object", "additionalProperties": False,
                    "properties": {
                        "action": {"const": "download"},
                        "remote_path": {"type": "string", "description": "Computer source file."},
                        "local_path": {"type": "string", "description": "Phone destination; defaults to the artifact directory."},
                        "overwrite": {"type": "boolean", "default": False},
                    },
                    "required": ("action", "remote_path"),
                },
            ),
        },
    },
}


def bridge_tool_names() -> tuple[str, ...]:
    """Return the capabilities executable through the atomic bridge."""
    return tuple(name for name, item in CAPABILITIES.items() if item["transport"] == "bridge")


def capability_catalog(bridge_schemas: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the agent-facing contract without dispatch implementation details."""
    catalog = []
    for name, definition in CAPABILITIES.items():
        item = {"name": name}
        if name in bridge_schemas:
            schema = bridge_schemas[name]
            item["description"] = schema["description"]
            item["parameters"] = schema["parameters"]
        else:
            item["description"] = definition["description"]
            if "parameters" in definition:
                item["parameters"] = definition["parameters"]
            item["operations"] = list(definition.get("publicOperations", definition["operations"]))
        catalog.append(item)
    return catalog
