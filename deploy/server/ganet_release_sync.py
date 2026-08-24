#!/usr/bin/env python3
"""Mirror one trusted GAnet GitHub Release and sign the public sidecar manifest."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

REPOSITORY = "nianyucatfish/GAnet"
GITHUB_API = f"https://api.github.com/repos/{REPOSITORY}"
RELEASE_ROOT = Path("/srv/ganet.gaagent.ai/releases")
SIDECAR_ROOT = RELEASE_ROOT / "sidecar"
KEY_PATH = Path("/opt/ga-ops/secrets/ganet-sidecar-release-ed25519.pem")
STATE_PATH = Path("/var/lib/ganet-release-sync/state.json")
SOURCE_ROOT = Path("/opt/ganet-release-sync/source")
MAX_SIDECAR_BYTES = 128 * 1024 * 1024
MAX_COMPONENT_BYTES = 512 * 1024 * 1024
SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def _version(value: str) -> tuple[int, int, int]:
    match = SEMVER.fullmatch(value)
    if not match:
        raise RuntimeError(f"unsupported release tag: {value}")
    return tuple(int(part) for part in match.groups())


def _request_json(url: str) -> Any:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.netloc != "api.github.com":
        raise RuntimeError("GitHub API URL is outside the allowed host")
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ganet-release-sync/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.netloc != "api.github.com":
                raise RuntimeError("GitHub API request left the allowed host")
            length = response.headers.get("Content-Length")
            if length and int(length) > 8 * 1024 * 1024:
                raise RuntimeError("GitHub API response exceeds its size limit")
            data = response.read(8 * 1024 * 1024 + 1)
            if len(data) > 8 * 1024 * 1024:
                raise RuntimeError("GitHub API response exceeds its size limit")
            return json.loads(data)
    except urllib.error.HTTPError as exc:
        if exc.code == 404 and url == f"{GITHUB_API}/releases/latest":
            return None
        raise RuntimeError(f"GitHub API request failed: {url}") from exc
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError) as exc:
        raise RuntimeError(f"GitHub API request failed: {url}") from exc


def _download(url: str, destination: Path, limit: int) -> tuple[str, int]:
    request = urllib.request.Request(url, headers={"User-Agent": "ganet-release-sync/1"})
    digest = hashlib.sha256()
    size = 0
    try:
        with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.netloc not in {
                "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"
            }:
                raise RuntimeError("release asset download left the allowed hosts")
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > limit:
                    raise RuntimeError("release asset exceeds its size limit")
                digest.update(chunk)
                output.write(chunk)
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError("release asset download failed") from exc
    return digest.hexdigest(), size


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def _sign(signed: dict[str, Any]) -> str:
    if not KEY_PATH.is_file() or KEY_PATH.stat().st_mode & 0o077:
        raise RuntimeError("sidecar signing key is missing or too broadly accessible")
    completed = subprocess.run(
        ["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(KEY_PATH)],
        input=_canonical(signed), capture_output=True, timeout=15,
    )
    if completed.returncode:
        raise RuntimeError("sidecar manifest signing failed")
    return base64.b64encode(completed.stdout).decode("ascii")


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_value = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_value)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _sync_source(commit: str) -> None:
    if not COMMIT.fullmatch(commit):
        raise RuntimeError("release commit identity is invalid")
    if not (SOURCE_ROOT / ".git").is_dir():
        SOURCE_ROOT.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["git", "clone", "--filter=blob:none", "--no-checkout",
             f"https://github.com/{REPOSITORY}.git", str(SOURCE_ROOT)],
            check=True, timeout=120,
        )
    subprocess.run(
        ["git", "-C", str(SOURCE_ROOT), "fetch", "--prune", "origin", "+refs/heads/main:refs/remotes/origin/main"],
        check=True, timeout=120,
    )
    subprocess.run(
        ["git", "-C", str(SOURCE_ROOT), "merge-base", "--is-ancestor", commit, "origin/main"],
        check=True, timeout=15,
    )
    subprocess.run(
        ["git", "-C", str(SOURCE_ROOT), "checkout", "--detach", "--force", commit],
        check=True, timeout=60,
    )
    actual = subprocess.run(
        ["git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True, timeout=15,
    ).stdout.strip()
    if actual != commit:
        raise RuntimeError("server source checkout does not match the release commit")


def _existing_releases() -> list[dict[str, Any]]:
    manifest = _load_json(SIDECAR_ROOT / "manifest.json")
    releases = manifest.get("signed", {}).get("releases", [])
    if not isinstance(releases, list):
        return []
    result = []
    for entry in releases:
        if isinstance(entry, dict) and SEMVER.fullmatch(str(entry.get("version") or "")):
            result.append(dict(entry))
    return result


def sync(tag: str | None = None) -> dict[str, Any]:
    release = _request_json(
        f"{GITHUB_API}/releases/tags/{urllib.parse.quote(tag)}" if tag else f"{GITHUB_API}/releases/latest"
    )
    if release is None and tag is None:
        return {"ok": True, "changed": False, "reason": "no published release"}
    if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
        raise RuntimeError("only published, non-prerelease releases may be mirrored")
    tag_name = str(release.get("tag_name") or "")
    version = _version(tag_name)
    version_text = ".".join(str(part) for part in version)
    state = _load_json(STATE_PATH)
    known_versions = [
        str(entry["version"]) for entry in _existing_releases()
        if SEMVER.fullmatch(str(entry.get("version") or ""))
    ]
    known_versions.append(str(state.get("version") or "0.0.0"))
    current = max(known_versions, key=_version)
    if version < _version(current):
        raise RuntimeError(f"release downgrade rejected: {version_text} < {current}")

    assets = release.get("assets")
    if not isinstance(assets, list):
        raise RuntimeError("GitHub release has no assets")
    asset_names = [str(item.get("name")) for item in assets if isinstance(item, dict)]
    if len(asset_names) != len(set(asset_names)):
        raise RuntimeError("GitHub release contains duplicate asset names")
    by_name = {str(item.get("name")): item for item in assets if isinstance(item, dict)}
    sidecar_name = f"ganet-sidecar-windows-amd64-{version_text}.exe"
    component_name = f"GAnet-Windows-amd64-{version_text}.zip"
    identity_name = "sidecar-version.json"
    required = (sidecar_name, component_name, identity_name, "SHA256SUMS.txt", "provenance.json")
    if any(name not in by_name for name in required):
        raise RuntimeError("GitHub release is missing required GAnet assets")

    with tempfile.TemporaryDirectory(prefix="ganet-release-sync-") as temporary_value:
        temporary = Path(temporary_value)
        downloaded: dict[str, tuple[Path, str, int]] = {}
        for name in required:
            limit = MAX_COMPONENT_BYTES if name.endswith(".zip") else MAX_SIDECAR_BYTES
            path = temporary / name
            digest, size = _download(str(by_name[name]["browser_download_url"]), path, limit)
            expected_size = int(by_name[name].get("size") or -1)
            if expected_size <= 0 or size != expected_size:
                raise RuntimeError(f"GitHub asset size mismatch: {name}")
            downloaded[name] = path, digest, size

        checksums = {}
        checksum_lines = downloaded["SHA256SUMS.txt"][0].read_text(encoding="ascii").splitlines()
        for line in checksum_lines:
            digest, separator, name = line.partition("  ")
            if separator and re.fullmatch(r"[0-9a-f]{64}", digest):
                if name in checksums:
                    raise RuntimeError(f"duplicate GitHub checksum entry: {name}")
                checksums[name] = digest
        if set(checksums) != {sidecar_name, component_name, identity_name}:
            raise RuntimeError("GitHub checksum file contains an unexpected artifact set")
        for name in (sidecar_name, component_name, identity_name):
            if checksums.get(name) != downloaded[name][1]:
                raise RuntimeError(f"GitHub checksum mismatch: {name}")

        provenance = json.loads(downloaded["provenance.json"][0].read_text(encoding="utf-8-sig"))
        commit = str(provenance.get("commit") or "")
        provenance_artifacts = provenance.get("artifacts")
        if provenance.get("repository") != REPOSITORY or provenance.get("version") != version_text or \
                not COMMIT.fullmatch(commit) or not isinstance(provenance_artifacts, list) or \
                sorted(provenance_artifacts) != sorted((sidecar_name, component_name, identity_name)):
            raise RuntimeError("release provenance identity is invalid")
        identity = json.loads(downloaded[identity_name][0].read_text(encoding="utf-8-sig"))
        if identity != {"version": version_text, "commit": commit, "protocolVersion": "1"}:
            raise RuntimeError("sidecar build identity does not match the release provenance")
        tag_ref = _request_json(
            f"{GITHUB_API}/git/ref/tags/{urllib.parse.quote(tag_name, safe='')}"
        )
        tag_object = tag_ref.get("object", {}) if isinstance(tag_ref, dict) else {}
        for _ in range(2):
            if tag_object.get("type") != "tag":
                break
            tag_object = _request_json(str(tag_object.get("url") or "")).get("object", {})
        if tag_object.get("type") != "commit" or tag_object.get("sha") != commit:
            raise RuntimeError("release tag and provenance commit do not match")

        _sync_source(commit)
        sidecar_destination = SIDECAR_ROOT / sidecar_name
        _write_atomic(sidecar_destination, downloaded[sidecar_name][0].read_bytes())
        if hashlib.sha256(sidecar_destination.read_bytes()).hexdigest() != downloaded[sidecar_name][1]:
            raise RuntimeError("server mirror digest verification failed")

    releases = [entry for entry in _existing_releases() if entry.get("version") != version_text]
    releases.append({
        "architecture": "amd64",
        "commit": commit,
        "platform": "windows",
        "protocol_version": "1",
        "sha256": downloaded[sidecar_name][1],
        "size": downloaded[sidecar_name][2],
        "update_level": "available",
        "url": f"https://ganet.gaagent.ai/releases/sidecar/{sidecar_name}",
        "version": version_text,
    })
    releases.sort(key=lambda entry: _version(str(entry["version"])))
    signed = {
        "component": "ganet-sidecar",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "releases": releases,
        "schema": 1,
    }
    manifest = {"signed": signed, "signature": _sign(signed)}
    _write_atomic(
        SIDECAR_ROOT / "manifest.json",
        json.dumps(manifest, ensure_ascii=False, indent=2).encode() + b"\n",
    )
    _write_atomic(
        STATE_PATH,
        json.dumps({"commit": commit, "release_id": release.get("id"), "tag": tag_name,
                    "version": version_text}, indent=2).encode() + b"\n",
        mode=0o600,
    )
    return {"ok": True, "changed": True, "version": version_text, "commit": commit}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", help="sync one exact published release tag")
    args = parser.parse_args()
    try:
        print(json.dumps(sync(args.tag), separators=(",", ":")))
        return 0
    except Exception as exc:
        print(f"ganet release sync failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
