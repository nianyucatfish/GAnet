package main

import (
	"encoding/json"
	"os"
	"path/filepath"
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