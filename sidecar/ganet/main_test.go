package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withDataRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	t.Setenv("GANET_SIDECAR_DIR", root)
	return root
}

func TestRuntimeConfigRoundTrip(t *testing.T) {
	withDataRoot(t)
	want := runtimeConfig{ControlURL: "https://ganet.example", Hostname: "pc-a", SSHPort: 48222}
	if err := saveRuntimeConfig(want); err != nil {
		t.Fatal(err)
	}
	got, err := loadRuntimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
	data, err := os.ReadFile(configPath())
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("saved config is not valid JSON")
	}
}

func TestRuntimeConfigRejectsInvalidPort(t *testing.T) {
	root := withDataRoot(t)
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"controlUrl":"x","hostname":"pc","sshPort":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadRuntimeConfig(); err == nil {
		t.Fatal("invalid config was accepted")
	}
}

func TestReconnectDelayBackoffAndCap(t *testing.T) {
	want := []time.Duration{time.Second, 2 * time.Second, 5 * time.Second, 10 * time.Second,
		30 * time.Second, time.Minute, 2 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	for attempt, expected := range want {
		if got := reconnectDelay(attempt); got != expected {
			t.Fatalf("attempt %d: got %s, want %s", attempt, got, expected)
		}
	}
}

func TestVersionCommandCarriesBuildIdentity(t *testing.T) {
	got := buildIdentity()
	if got["version"] != version || got["commit"] != commit ||
		got["protocolVersion"] != protocolVersion {
		t.Fatalf("unexpected build identity: %#v", got)
	}
}

func TestClassifyHealthMapsMessagesToStableCodesWithoutLeakingText(t *testing.T) {
	messages := []string{
		"Tailscale could not connect to the 'GAnet Shanghai' relay server. Your Internet connection might be down, or the server might be temporarily unavailable.",
		"You are logged out. The last login error was: fetch control key: Get \"https://ganet.gaagent.ai/key?v=142\": EOF",
		"Tailscale is starting. Please wait.",
		"Not connected to the control server; retrying.",
		"something entirely new",
		"Tailscale could not connect to the 'GAnet Shanghai' relay server.",
	}
	got := classifyHealth(messages)
	want := []string{healthRelayUnreachable, healthLoggedOut, healthStarting, healthControlUnreachable, healthOther}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
		if strings.Contains(got[i], "gaagent") || strings.Contains(got[i], "Shanghai") {
			t.Fatalf("health code leaks server detail: %q", got[i])
		}
	}
	if empty := classifyHealth(nil); empty == nil || len(empty) != 0 {
		t.Fatalf("healthy node must report an empty (non-nil) list, got %#v", empty)
	}
}

func TestStatusJSONCarriesBuildIdentity(t *testing.T) {
	got := status{Version: version, Commit: commit, ProtocolVersion: protocolVersion, Installed: true}
	value, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(value, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["version"] != version || decoded["commit"] != commit ||
		decoded["protocolVersion"] != protocolVersion {
		t.Fatalf("unexpected build status: %s", value)
	}
}