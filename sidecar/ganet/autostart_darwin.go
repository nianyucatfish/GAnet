//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// launchdLabel must match ganet/device_connection/sidecar_paths.py.
const launchdLabel = "ai.gaagent.ganet-sidecar"

func launchdAgentPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "LaunchAgents", launchdLabel+".plist")
}

func launchdServiceTarget() string {
	return fmt.Sprintf("gui/%d/%s", os.Getuid(), launchdLabel)
}

func xmlEscape(value string) string {
	replacer := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return replacer.Replace(value)
}

// launchdPlist describes a per-user background agent: start at login, restart
// only after abnormal exits, never elevate. Logs go beside the sidecar log so
// a crash before logging is initialised still leaves a trace.
func launchdPlist() string {
	logsDir := filepath.Join(dataRoot(), "logs")
	var env string
	if value := strings.TrimSpace(os.Getenv("GANET_SIDECAR_DIR")); value != "" {
		env = "\t<key>EnvironmentVariables</key>\n\t<dict>\n\t\t<key>GANET_SIDECAR_DIR</key>\n\t\t<string>" +
			xmlEscape(value) + "</string>\n\t</dict>\n"
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + launchdLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + xmlEscape(executablePath()) + `</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ProcessType</key>
	<string>Background</string>
	<key>WorkingDirectory</key>
	<string>` + xmlEscape(dataRoot()) + `</string>
	<key>StandardOutPath</key>
	<string>` + xmlEscape(filepath.Join(logsDir, "launchd.out.log")) + `</string>
	<key>StandardErrorPath</key>
	<string>` + xmlEscape(filepath.Join(logsDir, "launchd.err.log")) + `</string>
` + env + `</dict>
</plist>
`
}

func launchctl(arguments ...string) (string, error) {
	output, err := exec.Command("launchctl", arguments...).CombinedOutput()
	return strings.TrimSpace(string(output)), err
}

// autostartInstall writes the agent and loads it unless a sidecar is already
// serving. Loading while another instance holds the control port would make
// launchd spawn a second copy that fails and is retried every few seconds; the
// caller hands over explicitly (stop the old one, then bootstrap) instead.
func autostartInstall() error {
	plistPath := launchdAgentPath()
	if plistPath == "" {
		return errors.New("cannot resolve the user LaunchAgents directory")
	}
	if err := os.MkdirAll(filepath.Dir(plistPath), 0700); err != nil {
		return fmt.Errorf("create LaunchAgents directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dataRoot(), "logs"), 0700); err != nil {
		return fmt.Errorf("create sidecar log directory: %w", err)
	}
	temporary := plistPath + ".tmp"
	if err := os.WriteFile(temporary, []byte(launchdPlist()), 0600); err != nil {
		return fmt.Errorf("write launch agent: %w", err)
	}
	if err := os.Rename(temporary, plistPath); err != nil {
		return fmt.Errorf("install launch agent: %w", err)
	}
	// A stale registration (older path or arguments) must be replaced, not merged.
	_, _ = launchctl("bootout", launchdServiceTarget())
	if queryStatus().Running {
		return nil
	}
	if output, err := launchctl("bootstrap", fmt.Sprintf("gui/%d", os.Getuid()), plistPath); err != nil {
		return fmt.Errorf("load launch agent: %w: %s", err, output)
	}
	return nil
}

func autostartRemove() error {
	_, _ = launchctl("bootout", launchdServiceTarget())
	plistPath := launchdAgentPath()
	if plistPath == "" {
		return nil
	}
	if err := os.Remove(plistPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove launch agent: %w", err)
	}
	return nil
}
