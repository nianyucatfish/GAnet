//go:build windows

package main

// The phone's PC bridge sends its exec line pre-quoted for Windows OpenSSH,
// which pastes the payload verbatim into `cmd.exe /c "<payload>"`. These tests
// pin that contract end to end through a real SSH session: doubled quotes
// around a spaced launcher path must survive both cmd parses, and %VAR%
// references must be expanded, or the phone cannot reach atomic-bridge.cmd.

import (
	"bytes"
	"io"
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

// TestExecStdinRequestReplyLikePhoneBridge pins the tool-call shape: the
// client writes the request, half-closes stdin and then waits for the reply.
// Stdin bytes must reach the tool intact (single channel reader) and the EOF
// must not tear the process down, even when the tool outlives the old
// 2-second disconnect grace.
func TestExecStdinRequestReplyLikePhoneBridge(t *testing.T) {
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
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	session.Stdout = &output
	if err := session.Start(`ping -n 4 127.0.0.1 >nul & findstr "^"`); err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("{\"requestId\":\"req_stdin_roundtrip\"}\r\n", 40)
	if _, err := io.WriteString(stdin, payload); err != nil {
		t.Fatal(err)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("exec was torn down after stdin EOF: %v", err)
	}
	if got := strings.TrimSpace(output.String()); got != strings.TrimSpace(payload) {
		t.Fatalf("stdin bytes were lost or corrupted: got %d bytes, want %d",
			len(got), len(strings.TrimSpace(payload)))
	}
}
