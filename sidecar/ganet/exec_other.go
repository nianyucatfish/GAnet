//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func shellCommand(command string) *exec.Cmd {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return cmd
}

func killProcessTree(pid int) {
	// The command runs in its own process group; a negative pid signals the group.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
}
