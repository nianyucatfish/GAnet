package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"tailscale.com/ipn"
	"tailscale.com/tsnet"
)

var (
	version         = "dev"
	commit          = "unknown"
	protocolVersion = "1"
)

const controlAddr = "127.0.0.1:48223"

type runtimeState struct {
	mu             sync.RWMutex
	server         *tsnet.Server
	ip             string
	online         bool
	listening      bool
	loopback       bool
	hostKey        string
	authorizedKeys bool
	startedAt      time.Time
	lastError      string
	controlOK      bool
	enrolled       bool
}

type status struct {
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	ProtocolVersion string `json:"protocolVersion"`
	Installed       bool   `json:"installed"`
	Running         bool   `json:"running"`
	Enrolled        bool   `json:"enrolled"`
	Online          bool   `json:"online"`
	Listening       bool   `json:"listening"`
	LoopbackSSH     bool   `json:"loopbackSsh"`
	SSHHostKey      string `json:"sshHostKey,omitempty"`
	AuthorizedKeys  bool   `json:"authorizedKeys"`
	ControlMatch    bool   `json:"controlMatch"`
	IP              string `json:"ip,omitempty"`
	SSHPort         int    `json:"sshPort"`
	PID             int    `json:"pid,omitempty"`
	ErrorCategory   string `json:"errorCategory,omitempty"`
}

type runtimeConfig struct {
	ControlURL string `json:"controlUrl"`
	Hostname   string `json:"hostname"`
	SSHPort    int    `json:"sshPort"`
}

func dataRoot() string {
	if value := strings.TrimSpace(os.Getenv("GANET_SIDECAR_DIR")); value != "" {
		return value
	}
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserConfigDir()
	}
	return filepath.Join(base, "GenericAgent", "GAnet")
}

func stateDir() string   { return filepath.Join(dataRoot(), "state") }
func logPath() string    { return filepath.Join(dataRoot(), "logs", "sidecar.log") }
func configPath() string { return filepath.Join(dataRoot(), "config.json") }

func loadRuntimeConfig() (runtimeConfig, error) {
	var config runtimeConfig
	value, err := os.ReadFile(configPath())
	if err != nil {
		return config, err
	}
	if err := json.Unmarshal(value, &config); err != nil {
		return config, err
	}
	if config.ControlURL == "" || config.Hostname == "" || config.SSHPort < 1 || config.SSHPort > 65535 {
		return config, errors.New("invalid sidecar configuration")
	}
	return config, nil
}

func saveRuntimeConfig(config runtimeConfig) error {
	if err := os.MkdirAll(dataRoot(), 0700); err != nil {
		return err
	}
	value, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	temporary := configPath() + ".tmp"
	if err := os.WriteFile(temporary, value, 0600); err != nil {
		return err
	}
	return os.Rename(temporary, configPath())
}

func writeJSON(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
}

func buildIdentity() map[string]any {
	return map[string]any{"version": version, "commit": commit, "protocolVersion": protocolVersion}
}

func queryStatus() status {
	client := http.Client{Timeout: 2 * time.Second}
	response, err := client.Get("http://" + controlAddr + "/status")
	if err != nil {
		_, statErr := os.Stat(executablePath())
		config, _ := loadRuntimeConfig()
		return status{Version: version, Commit: commit, ProtocolVersion: protocolVersion,
			Installed: statErr == nil, SSHPort: config.SSHPort}
	}
	defer response.Body.Close()
	var result status
	if json.NewDecoder(response.Body).Decode(&result) != nil {
		return status{Version: version, Commit: commit, ProtocolVersion: protocolVersion, Installed: true}
	}
	return result
}

func executablePath() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	path, _ = filepath.Abs(path)
	return path
}

func autostartScriptPath() string {
	return filepath.Join(stateDir(), "ganet-sidecar-start.vbs")
}

func autostart(action string) error {
	if runtime.GOOS != "windows" {
		return errors.New("autostart is currently supported on Windows only")
	}
	const valueName = "GenericAgent GAnet"
	const runKey = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
	scriptPath := autostartScriptPath()
	switch action {
	case "install":
		if err := os.MkdirAll(stateDir(), 0700); err != nil {
			return fmt.Errorf("create autostart state directory: %w", err)
		}
		command := fmt.Sprintf("\"%s\" run", executablePath())
		// Run with window style 0 so a long-lived tsnet process never flashes a
		// console at logon. Keep diagnostics in the sidecar log instead.
		script := "Set shell = CreateObject(\"WScript.Shell\")\r\n" +
			"shell.Run \"" + strings.ReplaceAll(command, "\"", "\"\"") + "\", 0, False\r\n"
		if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
			return fmt.Errorf("write hidden autostart launcher: %w", err)
		}
		target := fmt.Sprintf("wscript.exe //B //Nologo \"%s\"", scriptPath)
		cmd := exec.Command("reg.exe", "add", runKey, "/v", valueName, "/t", "REG_SZ", "/d", target, "/f")
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("create autostart: %w: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	case "remove":
		cmd := exec.Command("reg.exe", "delete", runKey, "/v", valueName, "/f")
		if output, err := cmd.CombinedOutput(); err != nil && !strings.Contains(strings.ToLower(string(output)), "unable to find") {
			return fmt.Errorf("remove autostart: %w: %s", err, strings.TrimSpace(string(output)))
		}
		if err := os.Remove(scriptPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove hidden autostart launcher: %w", err)
		}
		return nil
	default:
		return errors.New("usage: ganet-sidecar autostart install|remove")
	}
}

func run(controlURL, hostname, authKey string, sshPort int) error {
	if err := os.MkdirAll(stateDir(), 0700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(logPath()), 0700); err != nil {
		return err
	}
	logFile, err := os.OpenFile(logPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	logger := log.New(logFile, "", log.Ldate|log.Ltime|log.LUTC)

	control, err := net.Listen("tcp", controlAddr)
	if err != nil {
		return fmt.Errorf("sidecar already running or control port unavailable: %w", err)
	}
	defer control.Close()

	service, err := newSSHService(logger)
	if err != nil {
		return err
	}

	st := &runtimeState{startedAt: time.Now(), hostKey: service.hostPublicKey()}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, _ *http.Request) {
		st.refresh(controlURL)
		keys, keysErr := loadAuthorizedKeys()
		st.mu.RLock()
		result := status{Version: version, Commit: commit, ProtocolVersion: protocolVersion,
			Installed: true, Running: true, Enrolled: st.enrolled,
			Online: st.online, Listening: st.listening, ControlMatch: st.controlOK,
			LoopbackSSH: st.loopback, SSHHostKey: st.hostKey,
			AuthorizedKeys: keysErr == nil && len(keys) > 0,
			IP:             st.ip, SSHPort: sshPort, PID: os.Getpid(), ErrorCategory: st.lastError}
		st.mu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	go func() { _ = server.Serve(control) }()
	defer server.Shutdown(context.Background())

	stopping := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		close(stopping)
	}()

	// Local processes (the configuration probe) reach the same SSH service via
	// loopback; tsnet listeners are invisible to them because the tailnet
	// address lives only inside this process.
	loopback, loopbackErr := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(sshPort)))
	if loopbackErr != nil {
		logger.Printf("loopback_listen_failed port=%d type=%T", sshPort, loopbackErr)
		st.mu.Lock()
		st.lastError = "loopback_listen"
		st.mu.Unlock()
	} else {
		st.mu.Lock()
		st.loopback = true
		st.mu.Unlock()
		logger.Printf("ssh_listening origin=loopback port=%d", sshPort)
		go func() {
			<-stopping
			_ = loopback.Close()
		}()
		go service.serve(loopback, "loopback", stopping)
	}

	for attempt := 0; ; attempt++ {
		select {
		case <-stopping:
			return nil
		default:
		}
		s := &tsnet.Server{Dir: stateDir(), ControlURL: controlURL, Hostname: hostname,
			AuthKey: authKey, Ephemeral: false}
		st.setServer(s)
		authKey = "" // a single-use enrollment grant must never be replayed on retry
		err := serveNetwork(s, st, controlURL, sshPort, service, logger, stopping)
		s.Close()
		st.setServer(nil)
		select {
		case <-stopping:
			return nil
		default:
		}
		delay := reconnectDelay(attempt)
		logger.Printf("network_retry attempt=%d delay=%s type=%T", attempt+1, delay, err)
		st.setError("network_retry")
		timer := time.NewTimer(delay)
		select {
		case <-stopping:
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

func reconnectDelay(attempt int) time.Duration {
	delays := [...]time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second,
		30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute}
	if attempt >= len(delays) {
		return delays[len(delays)-1]
	}
	return delays[attempt]
}

func serveNetwork(s *tsnet.Server, st *runtimeState, controlURL string, sshPort int,
	service *sshService, logger *log.Logger, stopping <-chan struct{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	up, err := s.Up(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("tsnet up: %w", err)
	}
	st.mu.Lock()
	st.online = true
	st.lastError = ""
	if up != nil && len(up.TailscaleIPs) > 0 {
		st.ip = up.TailscaleIPs[0].String()
	}
	st.mu.Unlock()
	st.refresh(controlURL)
	actualHostname, actualDNSName := "", ""
	if up != nil && up.Self != nil {
		actualHostname = up.Self.HostName
		actualDNSName = strings.TrimSuffix(up.Self.DNSName, ".")
	}
	logger.Printf("network_online ip=%s hostname=%s dns=%s", st.ip, actualHostname, actualDNSName)

	listener, err := s.Listen("tcp", fmt.Sprintf(":%d", sshPort))
	if err != nil {
		return fmt.Errorf("tsnet listen: %w", err)
	}
	defer listener.Close()
	st.mu.Lock()
	st.listening = true
	st.mu.Unlock()
	logger.Printf("ssh_listening origin=tailnet port=%d", sshPort)
	go func() {
		<-stopping
		_ = listener.Close()
	}()
	for failures := 0; ; {
		conn, err := listener.Accept()
		if err == nil {
			failures = 0
			go service.handleConn(conn, "tailnet")
			continue
		}
		select {
		case <-stopping:
			return nil
		default:
		}
		failures++
		st.mu.Lock()
		st.listening = false
		st.lastError = "listener_accept"
		st.mu.Unlock()
		if failures >= 5 {
			return fmt.Errorf("tsnet listener stopped after repeated accept failures: %w", err)
		}
		delay := time.Duration(failures*failures) * 250 * time.Millisecond
		logger.Printf("listener_accept_retry attempt=%d delay=%s type=%T", failures, delay, err)
		time.Sleep(delay)
	}
}

func (st *runtimeState) setServer(server *tsnet.Server) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.server = server
	if server == nil {
		st.online = false
		st.listening = false
		st.ip = ""
	}
}

func (st *runtimeState) setError(category string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.lastError = category
	st.online = false
	st.listening = false
}

func (st *runtimeState) refresh(expectedControlURL string) {
	st.mu.RLock()
	server := st.server
	st.mu.RUnlock()
	if server == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client, err := server.LocalClient()
	if err != nil {
		st.mu.Lock()
		st.online = false
		st.lastError = "local_api"
		st.mu.Unlock()
		return
	}
	current, _, profileErr := client.ProfileStatus(ctx)
	backend, statusErr := client.StatusWithoutPeers(ctx)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.enrolled = profileErr == nil && current.ID != "" && current.NodeID != ""
	st.controlOK = profileErr == nil && strings.TrimSuffix(current.ControlURL, "/") == strings.TrimSuffix(expectedControlURL, "/")
	st.online = statusErr == nil && backend.BackendState == ipn.Running.String()
	if statusErr == nil && len(backend.TailscaleIPs) > 0 {
		st.ip = backend.TailscaleIPs[0].String()
	}
	if profileErr != nil {
		st.lastError = "profile_status"
	} else if statusErr != nil {
		st.lastError = "backend_status"
	} else {
		st.lastError = ""
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ganet-sidecar <run|status|version|host-key|autostart>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "version":
		writeJSON(buildIdentity())
	case "status":
		writeJSON(queryStatus())
	case "host-key":
		// Setup needs the host public key before the sidecar's first run: the
		// enrollment request already carries it for phone-side pinning.
		signer, err := loadOrCreateHostKey()
		if err != nil {
			writeJSON(map[string]any{"ok": false, "error": err.Error()})
			os.Exit(1)
		}
		writeJSON(map[string]any{"ok": true, "hostKey": hostPublicKeyLine(signer)})
	case "autostart":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: ganet-sidecar autostart install|remove")
			os.Exit(2)
		}
		if err := autostart(os.Args[2]); err != nil {
			writeJSON(map[string]any{"ok": false, "error": err.Error()})
			os.Exit(1)
		}
		writeJSON(map[string]any{"ok": true, "action": os.Args[2]})
	case "run":
		flags := flag.NewFlagSet("run", flag.ExitOnError)
		controlURL := flags.String("control-url", os.Getenv("GANET_CONTROL_URL"), "Headscale control URL")
		hostname := flags.String("hostname", os.Getenv("GANET_HOSTNAME"), "stable node hostname")
		sshPort := flags.Int("ssh-port", 0, "embedded SSH listen port")
		authStdin := flags.Bool("auth-key-stdin", false, "read one-time enrollment grant from stdin")
		_ = flags.Parse(os.Args[2:])
		authKey := ""
		if *authStdin {
			value, _ := io.ReadAll(io.LimitReader(os.Stdin, 8192))
			authKey = strings.TrimSpace(string(value))
		}
		config, configErr := loadRuntimeConfig()
		if *controlURL != "" {
			config.ControlURL = *controlURL
		}
		if *hostname != "" {
			config.Hostname = *hostname
		}
		if *sshPort != 0 {
			config.SSHPort = *sshPort
		}
		if config.SSHPort == 0 {
			config.SSHPort = 48222
		}
		if config.ControlURL == "" || config.Hostname == "" {
			if configErr != nil {
				fmt.Fprintln(os.Stderr, "control URL and hostname are required for initial enrollment")
			} else {
				fmt.Fprintln(os.Stderr, "saved sidecar configuration is invalid")
			}
			os.Exit(2)
		}
		if *controlURL != "" || *hostname != "" || *sshPort != 0 {
			if err := saveRuntimeConfig(config); err != nil {
				fmt.Fprintln(os.Stderr, "save sidecar configuration:", err)
				os.Exit(1)
			}
		}
		if err := run(config.ControlURL, config.Hostname, authKey, config.SSHPort); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown command")
		os.Exit(2)
	}
}
