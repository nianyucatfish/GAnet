package main

// Contract tests for the embedded SSH service. Every test drives a real SSH
// client from golang.org/x/crypto over an in-memory pipe, so the exact
// handshake, auth and channel semantics the phone will see are what is
// asserted here.

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func newClientKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// startTestService isolates host key and authorized_keys in temp dirs and
// returns the service plus the authorized_keys path tests write into.
func startTestService(t *testing.T) (*sshService, string) {
	t.Helper()
	t.Setenv("GANET_SIDECAR_DIR", t.TempDir())
	keysPath := filepath.Join(t.TempDir(), "authorized_keys")
	t.Setenv("GANET_AUTHORIZED_KEYS", keysPath)
	service, err := newSSHService(log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return service, keysPath
}

func authorize(t *testing.T, keysPath string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(keysPath, []byte(strings.Join(lines, "\n")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

// dialTestService connects a real SSH client to the service over a TCP
// loopback pair. net.Pipe is unusable here: its writes are synchronous, so
// the post-kex phase where both sides send packets concurrently deadlocks.
func dialTestService(t *testing.T, service *sshService, user string, key ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		defer listener.Close()
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			service.handleConn(conn, "test")
		}
	}()
	clientConn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(service.signer.PublicKey()),
		Timeout:         5 * time.Second,
	}
	conn, channels, requests, err := ssh.NewClientConn(clientConn, "127.0.0.1", config)
	if err != nil {
		clientConn.Close()
		return nil, err
	}
	client := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { client.Close() })
	return client, nil
}

func TestHostKeyPersistsAcrossRestart(t *testing.T) {
	t.Setenv("GANET_SIDECAR_DIR", t.TempDir())
	first, err := loadOrCreateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	second, err := loadOrCreateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	if hostPublicKeyLine(first) != hostPublicKeyLine(second) {
		t.Fatal("host key changed between loads; phone pinning would break")
	}
	if first.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("unexpected host key type %s", first.PublicKey().Type())
	}
	published, err := os.ReadFile(hostKeyFile() + ".pub")
	if err != nil {
		t.Fatalf("public half was not mirrored for the Python side: %v", err)
	}
	if strings.TrimSpace(string(published)) != hostPublicKeyLine(first) {
		t.Fatal("mirrored public key does not match the host key")
	}
}

func TestAuthRejectsUnknownKey(t *testing.T) {
	service, keysPath := startTestService(t)
	_, authorizedLine := newClientKey(t)
	authorize(t, keysPath, authorizedLine)
	strangerKey, _ := newClientKey(t)
	if _, err := dialTestService(t, service, currentUsername(), strangerKey); err == nil {
		t.Fatal("handshake succeeded with a key absent from authorized_keys")
	}
}

func TestAuthRejectsWhenNoKeysAuthorized(t *testing.T) {
	service, keysPath := startTestService(t)
	clientKey, _ := newClientKey(t)
	if _, err := dialTestService(t, service, currentUsername(), clientKey); err == nil {
		t.Fatal("handshake succeeded with missing authorized_keys file")
	}
	authorize(t, keysPath, "# comments only, no keys")
	if _, err := dialTestService(t, service, currentUsername(), clientKey); err == nil {
		t.Fatal("handshake succeeded with an empty authorized_keys file")
	}
}

func TestAuthRejectsWrongUsername(t *testing.T) {
	service, keysPath := startTestService(t)
	clientKey, authorizedLine := newClientKey(t)
	authorize(t, keysPath, authorizedLine)
	if _, err := dialTestService(t, service, "someone-else", clientKey); err == nil {
		t.Fatal("handshake succeeded for a username other than the desktop user")
	}
}

func TestAuthSkipsMalformedLinesButAcceptsValidKey(t *testing.T) {
	service, keysPath := startTestService(t)
	clientKey, authorizedLine := newClientKey(t)
	authorize(t, keysPath, "not a key at all", "", "# comment", authorizedLine)
	client, err := dialTestService(t, service, currentUsername(), clientKey)
	if err != nil {
		t.Fatalf("valid key rejected: %v", err)
	}
	client.Close()
}

func TestExecRoundTripAndExitStatus(t *testing.T) {
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
	output, err := session.Output("echo ganet-embedded")
	session.Close()
	if err != nil {
		t.Fatalf("exec failed: %v", err)
	}
	if strings.TrimSpace(string(output)) != "ganet-embedded" {
		t.Fatalf("unexpected exec output %q", output)
	}

	session, err = client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	err = session.Run("exit 3")
	session.Close()
	var exitErr *ssh.ExitError
	if err == nil || !asSSHExit(err, &exitErr) || exitErr.ExitStatus() != 3 {
		t.Fatalf("expected exit status 3, got %v", err)
	}
}

func asSSHExit(err error, target **ssh.ExitError) bool {
	if value, ok := err.(*ssh.ExitError); ok {
		*target = value
		return true
	}
	return false
}

func TestPTYAndShellAreRejected(t *testing.T) {
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
	if err := session.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err == nil {
		t.Fatal("pty-req was accepted; interactive terminals must stay disabled")
	}
	if err := session.Shell(); err == nil {
		t.Fatal("shell request was accepted; only exec and sftp are allowed")
	}
}

func TestPortForwardingIsRejected(t *testing.T) {
	service, keysPath := startTestService(t)
	clientKey, authorizedLine := newClientKey(t)
	authorize(t, keysPath, authorizedLine)
	client, err := dialTestService(t, service, currentUsername(), clientKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Dial("tcp", "127.0.0.1:80"); err == nil {
		t.Fatal("direct-tcpip channel was accepted; forwarding must stay disabled")
	}
}

func TestSFTPRoundTrip(t *testing.T) {
	service, keysPath := startTestService(t)
	clientKey, authorizedLine := newClientKey(t)
	authorize(t, keysPath, authorizedLine)
	client, err := dialTestService(t, service, currentUsername(), clientKey)
	if err != nil {
		t.Fatal(err)
	}
	files, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("sftp subsystem failed to start: %v", err)
	}
	defer files.Close()

	path := filepath.Join(t.TempDir(), "roundtrip.txt")
	remote, err := files.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := remote.Write([]byte("payload via sftp")); err != nil {
		t.Fatal(err)
	}
	remote.Close()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "payload via sftp" {
		t.Fatalf("unexpected file contents %q", got)
	}
}

func TestUnknownSubsystemIsRejected(t *testing.T) {
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
	if err := session.RequestSubsystem("netconf"); err == nil {
		t.Fatal("unknown subsystem was accepted")
	}
}

func TestShellCommandMatchesPlatform(t *testing.T) {
	cmd := shellCommand("echo probe")
	base := strings.ToLower(filepath.Base(cmd.Path))
	if runtime.GOOS == "windows" && base != "cmd.exe" {
		t.Fatalf("expected cmd.exe on windows, got %s", cmd.Path)
	}
	if runtime.GOOS != "windows" && base != "sh" {
		t.Fatalf("expected /bin/sh off windows, got %s", cmd.Path)
	}
}
