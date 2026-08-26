//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"syscall"
)

// shellCommand mirrors Windows OpenSSH sshd, which pastes the SSH exec payload
// verbatim into `cmd.exe /c "<payload>"`. Clients craft their command lines for
// exactly that parse: the phone bridge wraps its launcher path in doubled
// quotes so the two cmd layers each strip one pair. Go's default argument
// quoting would instead escape quotes as \" which cmd.exe cannot parse, so the
// raw command line is supplied directly.
func shellCommand(command string) *exec.Cmd {
	cmd := exec.Command("cmd.exe")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// The sidecar runs without a console; keep spawned children from flashing one.
		HideWindow:    true,
		CreationFlags: 0x08000000,
		CmdLine:       `cmd.exe /c "` + command + `"`,
	}
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
