//go:build windows

package main

// The phone's PC bridge sends its exec line pre-quoted for Windows OpenSSH,
// which pastes the payload verbatim into `cmd.exe /c "<payload>"`. These tests
// pin that contract end to end through a real SSH session: doubled quotes
// around a spaced launcher path must survive both cmd parses, and %VAR%
// references must be expanded, or the phone cannot reach atomic-bridge.cmd.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func execOverSSH(t *testing.T, command string) string {
	t.Helper()
	service, keysPath := startTestService(t)
	clientKey, authorizedLine := newClientKey(t)
	authorize(t, keysPath, authorizedLine)
	client, err := dialTestService(t, service, currentUsername(), clientKey)
	if err != nil {
		t.Fatal(err)
	}
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	output, err := session.Output(command)
	if err != nil {
		t.Fatalf("exec %q failed: %v (output %q)", command, err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestExecPhoneBridgeQuotingContract(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "path with spaces")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "bridge.cmd")
	script := "@echo off\r\necho bridge-ok %1\r\n"
	if err := os.WriteFile(launcher, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	command := `cmd.exe /d /s /c ""` + launcher + `"" --check`
	if got := execOverSSH(t, command); got != "bridge-ok --check" {
		t.Fatalf("phone-style doubled quoting broke: got %q", got)
	}
}

func TestExecExpandsEnvironmentVariables(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if got := execOverSSH(t, "echo %USERPROFILE%"); got != home {
		t.Fatalf("%%USERPROFILE%% was not expanded: got %q, want %q", got, home)
	}
}
