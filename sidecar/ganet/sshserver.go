package main

// Embedded SSH/SFTP service for paired phones.
//
// The protocol and crypto layers belong to golang.org/x/crypto/ssh; this file
// owns only the three trust-boundary decisions: which public keys may
// authenticate, how "exec" becomes a local process, and how the SFTP
// subsystem is served. Everything else is deliberately rejected: no PTY, no
// shell, no port or agent forwarding, no unknown subsystems.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

const (
	sshHandshakeTimeout = 30 * time.Second
	sshMaxAuthTries     = 3
)

func authorizedKeysFile() string {
	if value := strings.TrimSpace(os.Getenv("GANET_AUTHORIZED_KEYS")); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".genericagent", "ganet", "authorized_keys")
}

func hostKeyFile() string {
	return filepath.Join(stateDir(), "ssh_host_ed25519_key")
}

// loadOrCreateHostKey returns a stable Ed25519 host key, generating and
// persisting one on first use. The phone pins the public half at pairing, so
// the key must survive restarts and upgrades.
func loadOrCreateHostKey() (ssh.Signer, error) {
	path := hostKeyFile()
	if raw, err := os.ReadFile(path); err == nil {
		signer, parseErr := ssh.ParsePrivateKey(raw)
		if parseErr == nil && signer.PublicKey().Type() == ssh.KeyAlgoED25519 {
			writeHostPublicKey(path, signer)
			return signer, nil
		}
		return nil, fmt.Errorf("stored SSH host key is invalid: %w", parseErr)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(private, "GAnet sidecar host key")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	encoded := pem.EncodeToMemory(block)
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, encoded, 0600); err != nil {
		return nil, err
	}
	if err := os.Rename(temporary, path); err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(encoded)
	if err != nil {
		return nil, err
	}
	writeHostPublicKey(path, signer)
	return signer, nil
}

// writeHostPublicKey mirrors the public half beside the private key so the
// Python side can read it for phone pinning even while the sidecar is down.
func writeHostPublicKey(privatePath string, signer ssh.Signer) {
	line := hostPublicKeyLine(signer) + "\n"
	_ = os.WriteFile(privatePath+".pub", []byte(line), 0600)
}

func hostPublicKeyLine(signer ssh.Signer) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
}

// loadAuthorizedKeys re-reads the pairing-managed key file on every attempt so
// newly paired or removed phones take effect without restarting the sidecar.
func loadAuthorizedKeys() ([]ssh.PublicKey, error) {
	path := authorizedKeysFile()
	if path == "" {
		return nil, errors.New("authorized keys path unavailable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parsed, _, _, _, parseErr := ssh.ParseAuthorizedKey([]byte(line))
		if parseErr != nil || parsed.Type() != ssh.KeyAlgoED25519 {
			continue // never let one malformed line disable the valid ones
		}
		keys = append(keys, parsed)
	}
	return keys, nil
}

func currentUsername() string {
	account, err := user.Current()
	if err != nil {
		return ""
	}
	name := account.Username
	if index := strings.LastIndexByte(name, '\\'); index >= 0 {
		name = name[index+1:]
	}
	return name
}

type sshService struct {
	config *ssh.ServerConfig
	signer ssh.Signer
	logger *log.Logger
}

func newSSHService(logger *log.Logger) (*sshService, error) {
	signer, err := loadOrCreateHostKey()
	if err != nil {
		return nil, fmt.Errorf("ssh host key: %w", err)
	}
	expectedUser := currentUsername()
	config := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-GAnet",
		MaxAuthTries:  sshMaxAuthTries,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if expectedUser == "" || !strings.EqualFold(conn.User(), expectedUser) {
				return nil, errors.New("unknown user")
			}
			if key.Type() != ssh.KeyAlgoED25519 {
				return nil, errors.New("unsupported key type")
			}
			authorized, loadErr := loadAuthorizedKeys()
			if loadErr != nil || len(authorized) == 0 {
				return nil, errors.New("no authorized keys") // empty list always rejects
			}
			marshaled := key.Marshal()
			for _, candidate := range authorized {
				if bytes.Equal(marshaled, candidate.Marshal()) {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errors.New("unknown key")
		},
	}
	config.AddHostKey(signer)
	return &sshService{config: config, signer: signer, logger: logger}, nil
}

func (s *sshService) hostPublicKey() string {
	return hostPublicKeyLine(s.signer)
}

// serve accepts connections until the listener closes.
func (s *sshService) serve(listener net.Listener, origin string, stopping <-chan struct{}) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-stopping:
			default:
				s.logger.Printf("ssh_accept_stop origin=%s type=%T", origin, err)
			}
			return
		}
		go s.handleConn(conn, origin)
	}
}

func (s *sshService) handleConn(conn net.Conn, origin string) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(sshHandshakeTimeout))
	server, channels, requests, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		s.logger.Printf("ssh_handshake_failed origin=%s", origin)
		return
	}
	_ = conn.SetDeadline(time.Time{})
	defer server.Close()
	// connDone closes when the transport dies. Sessions key process cleanup on
	// this, never on stdin EOF: the phone half-closes after sending a request
	// and keeps the connection open while it waits for the reply.
	connDone := make(chan struct{})
	go func() {
		_ = server.Wait()
		close(connDone)
	}()
	// Global requests carry keepalives and forwarding attempts; forwarding is
	// answered with failure by discarding, keepalives need no state.
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.Prohibited, "only session channels are available")
			continue
		}
		channel, channelRequests, acceptErr := newChannel.Accept()
		if acceptErr != nil {
			continue
		}
		go s.handleSession(channel, channelRequests, connDone)
	}
}

type exitStatusMsg struct {
	Status uint32
}

func (s *sshService) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, connDone <-chan struct{}) {
	defer channel.Close()
	started := false
	for request := range requests {
		switch request.Type {
		case "exec":
			if started {
				_ = request.Reply(false, nil)
				continue
			}
			var payload struct{ Command string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
				_ = request.Reply(false, nil)
				continue
			}
			started = true
			_ = request.Reply(true, nil)
			s.runExec(channel, payload.Command, connDone)
			return
		case "subsystem":
			if started {
				_ = request.Reply(false, nil)
				continue
			}
			var payload struct{ Name string }
			if err := ssh.Unmarshal(request.Payload, &payload); err != nil || payload.Name != "sftp" {
				_ = request.Reply(false, nil)
				continue
			}
			started = true
			_ = request.Reply(true, nil)
			s.runSFTP(channel)
			return
		case "env":
			// Accepting arbitrary client environment would let it influence the
			// spawned shell; the phone never needs it.
			_ = request.Reply(false, nil)
		default:
			// pty-req, shell, agent and X11 forwarding all land here.
			_ = request.Reply(false, nil)
		}
	}
}

func (s *sshService) runExec(channel ssh.Channel, command string, connDone <-chan struct{}) {
	cmd := shellCommand(command)
	if home, err := os.UserHomeDir(); err == nil {
		cmd.Dir = home
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		s.exit(channel, 1)
		return
	}
	cmd.Stdout = channel
	cmd.Stderr = channel.Stderr()
	if err := cmd.Start(); err != nil {
		s.logger.Printf("ssh_exec_start_failed type=%T", err)
		s.exit(channel, 127)
		return
	}
	// The single reader of the channel: request bytes flow to the tool, and
	// the client's EOF (a normal request boundary, like sshd) closes the
	// tool's stdin while the tool keeps running and replying.
	go func() {
		_, _ = io.Copy(stdin, channel)
		_ = stdin.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-connDone:
		// The client vanished mid-run; nothing can read the reply anymore,
		// so the process tree must not linger.
		select {
		case waitErr = <-done:
		case <-time.After(2 * time.Second):
			killProcessTree(cmd.Process.Pid)
			waitErr = <-done
		}
	}
	status := 0
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) && exitErr.ExitCode() >= 0 {
			status = exitErr.ExitCode()
		} else {
			status = 1
		}
	}
	s.exit(channel, uint32(status))
}

func (s *sshService) exit(channel ssh.Channel, status uint32) {
	_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(exitStatusMsg{Status: status}))
	_ = channel.Close()
}

func (s *sshService) runSFTP(channel ssh.Channel) {
	// No WithServerWorkingDirectory: on Windows pkg/sftp prefixes it onto
	// absolute C:\ paths and corrupts them. Clients must use absolute paths.
	server, err := sftp.NewServer(channel)
	if err != nil {
		return
	}
	if serveErr := server.Serve(); serveErr != nil && !errors.Is(serveErr, io.EOF) {
		s.logger.Printf("sftp_session_end type=%T", serveErr)
	}
	_ = server.Close()
}
