from __future__ import annotations

import importlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

class NetworkComponentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.env = mock.patch.dict(os.environ, {
            "GANET_SIDECAR_DIR": str(self.root),
            "GANET_SIDECAR_EXE": str(self.root / "ganet-sidecar.exe"),
        })
        self.env.start()
        from ganet.device_connection import sidecar_manager
        self.component = importlib.reload(sidecar_manager)

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def test_select_release_uses_actual_platform_and_architecture(self):
        releases = [{"platform": "windows", "architecture": "arm64", "version": "9.0.0"},
                    {"platform": "windows", "architecture": "amd64", "version": "0.2.0"}]
        got = self.component.select_release(releases, system="windows", architecture="amd64")
        self.assertEqual(got["version"], "0.2.0")

    def test_invalid_signature_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "签名"):
            self.component._validate_manifest({"signed": {"schema": 1}, "signature": "AAAA"})

    def test_manifest_entries_are_listed_newest_first(self):
        def entry(version):
            return {"platform": "windows", "architecture": "amd64",
                    "version": version, "protocol_version": "1",
                    "url": "https://ganet.gaagent.ai/releases/sidecar/x.exe",
                    "sha256": "0" * 64, "size": 1, "update_level": "available"}
        manifest = {"signed": {"schema": 1, "component": "ganet-sidecar",
                               "releases": [entry("0.2.1"), entry("0.10.0"), entry("0.3.0")]},
                    "signature": "AAAA"}
        with mock.patch.object(self.component, "_verify_signature"):
            got = self.component._validate_manifest(manifest)
        self.assertEqual([release["version"] for release in got],
                         ["0.10.0", "0.3.0", "0.2.1"])

    def test_inspect_keeps_working_install_unknown_when_release_unavailable(self):
        with mock.patch.object(self.component, "_status", return_value={
                "installed": True, "running": True, "online": True, "listening": True,
                "version": "0.2.0"}), mock.patch.object(
                    self.component, "list_releases", side_effect=RuntimeError("offline")):
            got = self.component.inspect()
        self.assertEqual(got["version_state"], "unknown")
        self.assertTrue(got["online"])

    def test_verify_release_rejects_digest_mismatch(self):
        artifact = self.root / "bad.exe"
        artifact.write_bytes(b"bad")
        release = {"manifest_verified": True, "sha256": "0" * 64,
                   "architecture": "amd64", "platform": "windows"}
        downloaded = self.component.DownloadedRelease(artifact, release)
        with self.assertRaisesRegex(RuntimeError, "SHA-256"):
            self.component.verify_release(downloaded)

    def test_first_install_without_config_does_not_require_running_daemon(self):
        artifact = self.root / "release.exe"
        artifact.write_bytes(b"release")
        verified = self.component.VerifiedRelease(artifact, {
            "version": "0.2.0", "protocol_version": "1",
        })
        with mock.patch.object(self.component, "_protect_windows_directory"), \
                mock.patch.object(self.component, "_install_autostart"), \
                mock.patch.object(self.component, "_binary_version", return_value={
                    "version": "0.2.0", "protocolVersion": "1",
                }), mock.patch.object(self.component, "_start") as start:
            got = self.component.install_release(verified)
        self.assertTrue(got["ok"])
        self.assertFalse(got["running"])
        start.assert_not_called()
        self.assertEqual(self.component._EXECUTABLE.read_bytes(), b"release")

    def test_configured_install_requires_running_replacement(self):
        artifact = self.root / "release.exe"
        artifact.write_bytes(b"release")
        (self.root / "config.json").write_text("{}", encoding="utf-8")
        verified = self.component.VerifiedRelease(artifact, {
            "version": "0.2.0", "protocol_version": "1",
        })
        with mock.patch.object(self.component, "_status", return_value={
                "installed": False, "running": False}), \
                mock.patch.object(self.component, "_protect_windows_directory"), \
                mock.patch.object(self.component, "_install_autostart"), \
                mock.patch.object(self.component, "_binary_version", return_value={
                    "version": "0.2.0", "protocolVersion": "1",
                }), mock.patch.object(self.component, "_start") as start, \
                mock.patch.object(self.component, "_wait_for_stable_start", return_value={
                    "running": True, "version": "0.2.0", "online": True,
                    "listening": True, "pid": 42,
                }) as wait:
            got = self.component.install_release(verified)
        start.assert_called_once()
        wait.assert_called_once_with("0.2.0", require_online=False, require_listening=False)
        self.assertTrue(got["running"])
        self.assertTrue(got["online"])

    def test_stable_start_requires_previous_online_state(self):
        statuses = iter([
            {"running": True, "version": "0.2.0", "pid": 10,
             "online": False, "listening": False},
            {"running": True, "version": "0.2.0", "pid": 10,
             "online": True, "listening": True},
            {"running": True, "version": "0.2.0", "pid": 10,
             "online": True, "listening": True},
        ])
        clock = iter([0.0, 0.0, 0.2, 0.2, 0.4, 0.4])
        with mock.patch.object(self.component, "_status", side_effect=lambda: next(statuses)), \
                mock.patch.object(self.component.time, "monotonic", side_effect=lambda: next(clock)), \
                mock.patch.object(self.component.time, "sleep"):
            got = self.component._wait_for_stable_start(
                "0.2.0", require_online=True, require_listening=True,
                timeout=1.0, stable_seconds=0.2)
        self.assertTrue(got["online"])
        self.assertTrue(got["listening"])

    def test_stable_start_rejects_transient_process(self):
        statuses = iter([
            {"running": True, "version": "0.2.0", "pid": 10},
            {"running": False},
            {"running": False},
        ])
        clock = iter([0.0, 0.0, 0.5, 1.0, 1.5])
        with mock.patch.object(self.component, "_status", side_effect=lambda: next(statuses)), \
                mock.patch.object(self.component.time, "monotonic", side_effect=lambda: next(clock)), \
                mock.patch.object(self.component.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "健康检查"):
                self.component._wait_for_stable_start("0.2.0", timeout=1.0, stable_seconds=0.5)

    def test_replace_retries_delayed_windows_handle_release(self):
        source = self.root / "new.exe"
        destination = self.root / "current.exe"
        source.write_bytes(b"new")
        destination.write_bytes(b"old")
        real_replace = os.replace
        attempts = 0

        def delayed_replace(src, dst):
            nonlocal attempts
            attempts += 1
            if attempts < 3:
                error = PermissionError("busy")
                error.winerror = 5
                raise error
            real_replace(src, dst)

        with mock.patch.object(self.component.os, "replace", side_effect=delayed_replace), \
                mock.patch.object(self.component.time, "sleep"):
            self.component._replace_with_retry(source, destination)
        self.assertEqual(attempts, 3)
        self.assertEqual(destination.read_bytes(), b"new")

    def test_replace_does_not_retry_unrelated_failure(self):
        source = self.root / "new.exe"
        destination = self.root / "current.exe"
        source.write_bytes(b"new")
        with mock.patch.object(self.component.os, "replace",
                               side_effect=FileNotFoundError("missing")) as replace, \
                mock.patch.object(self.component.time, "sleep") as sleep:
            with self.assertRaises(FileNotFoundError):
                self.component._replace_with_retry(source, destination)
        replace.assert_called_once()
        sleep.assert_not_called()

    def test_failure_before_replace_restarts_existing_without_overwriting_it(self):
        self.component._EXECUTABLE.write_bytes(b"old")
        artifact = self.root / "release.exe"
        artifact.write_bytes(b"new")
        verified = self.component.VerifiedRelease(artifact, {
            "version": "0.3.0", "protocol_version": "1",
        })
        previous = {"running": True, "online": True, "listening": True,
                    "version": "0.2.0"}
        with mock.patch.object(self.component, "_status", return_value=previous), \
                mock.patch.object(self.component, "_stop_running"), \
                mock.patch.object(self.component, "_replace_with_retry",
                                  side_effect=PermissionError("busy")) as replace, \
                mock.patch.object(self.component, "_install_autostart"), \
                mock.patch.object(self.component, "_start"), \
                mock.patch.object(self.component, "_wait_for_stable_start",
                                  return_value=previous) as wait:
            with self.assertRaisesRegex(RuntimeError, "已恢复原版本"):
                self.component.install_release(verified)
        replace.assert_called_once()
        self.assertEqual(self.component._EXECUTABLE.read_bytes(), b"old")
        wait.assert_called_once_with("0.2.0", require_online=True,
                                     require_listening=True)

    def test_failure_after_replace_restores_backup_and_health(self):
        self.component._EXECUTABLE.write_bytes(b"old")
        artifact = self.root / "release.exe"
        artifact.write_bytes(b"new")
        verified = self.component.VerifiedRelease(artifact, {
            "version": "0.3.0", "protocol_version": "1",
        })
        previous = {"running": False, "online": False, "listening": False,
                    "version": "0.2.0"}
        with mock.patch.object(self.component, "_status", return_value=previous), \
                mock.patch.object(self.component, "_protect_windows_directory",
                                  side_effect=RuntimeError("injected")), \
                mock.patch.object(self.component, "_install_autostart"), \
                mock.patch.object(self.component, "_start"), \
                mock.patch.object(self.component, "_wait_for_stable_start",
                                  return_value={"running": True, "version": "0.2.0"}):
            with self.assertRaisesRegex(RuntimeError, "已恢复原版本"):
                self.component.install_release(verified)
        self.assertEqual(self.component._EXECUTABLE.read_bytes(), b"old")


if __name__ == "__main__":
    unittest.main()
