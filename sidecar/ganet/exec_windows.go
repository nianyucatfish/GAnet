//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"syscall"
)

func shellCommand(command string) *exec.Cmd {
	cmd := exec.Command("cmd.exe", "/c", command)
	// The sidecar runs without a console; keep spawned children from flashing one.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return cmd
}

// killProcessTree stops the command shell and everything it started. Plain
// Process.Kill would orphan grandchildren, which then hold the SSH channel's
// pipes open forever.
func killProcessTree(pid int) {
	kill := exec.Command("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(pid))
	kill.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	_ = kill.Run()
}
