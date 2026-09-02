//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	autostartValueName = "GenericAgent GAnet"
	autostartRunKey    = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
)

func autostartScriptPath() string {
	return filepath.Join(stateDir(), "ganet-sidecar-start.vbs")
}

func autostartInstall() error {
	if err := os.MkdirAll(stateDir(), 0700); err != nil {
		return fmt.Errorf("create autostart state directory: %w", err)
	}
	command := fmt.Sprintf("\"%s\" run", executablePath())
	// Run with window style 0 so a long-lived tsnet process never flashes a
	// console at logon. Keep diagnostics in the sidecar log instead.
	script := "Set shell = CreateObject(\"WScript.Shell\")\r\n" +
		"shell.Run \"" + strings.ReplaceAll(command, "\"", "\"\"") + "\", 0, False\r\n"
	scriptPath := autostartScriptPath()
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		return fmt.Errorf("write hidden autostart launcher: %w", err)
	}
	target := fmt.Sprintf("wscript.exe //B //Nologo \"%s\"", scriptPath)
	cmd := exec.Command("reg.exe", "add", autostartRunKey, "/v", autostartValueName, "/t", "REG_SZ", "/d", target, "/f")
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create autostart: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func autostartRemove() error {
	cmd := exec.Command("reg.exe", "delete", autostartRunKey, "/v", autostartValueName, "/f")
	if output, err := cmd.CombinedOutput(); err != nil && !strings.Contains(strings.ToLower(string(output)), "unable to find") {
		return fmt.Errorf("remove autostart: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := os.Remove(autostartScriptPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove hidden autostart launcher: %w", err)
	}
	return nil
}
