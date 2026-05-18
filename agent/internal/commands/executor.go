package commands

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/opendirectory/agent/internal/config"
)

// Command represents a pending MDM command from the server.
type Command struct {
	ID      string                 `json:"id"`
	Command string                 `json:"command"`
	Payload map[string]interface{} `json:"payload"`
	Status  string                 `json:"status"`
}

// PollAndExecute fetches pending commands and executes each one.
func PollAndExecute(ctx context.Context, cfg *config.Config) error {
	url := fmt.Sprintf("%s/api/devices/%s/commands/pending", cfg.ServerURL, cfg.DeviceID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.DeviceToken)

	client := httpClient(cfg)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("poll commands: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		return nil // no pending commands
	}

	var cmds []Command
	if err := json.NewDecoder(resp.Body).Decode(&cmds); err != nil {
		return fmt.Errorf("decode commands: %w", err)
	}

	for _, cmd := range cmds {
		log.Printf("[commands] executing %q (id=%s)", cmd.Command, cmd.ID)
		result, execErr := execute(ctx, cfg, cmd)
		status := "completed"
		if execErr != nil {
			status = "failed"
			result = execErr.Error()
			log.Printf("[commands] %q failed: %v", cmd.Command, execErr)
		}
		reportResult(ctx, cfg, cmd.ID, status, result)
	}
	return nil
}

func execute(ctx context.Context, cfg *config.Config, cmd Command) (string, error) {
	switch cmd.Command {
	case "lock":
		return lockScreen()
	case "unlock":
		return "unlock requires user interaction at the console", nil
	case "restart":
		return restart()
	case "collect_logs":
		return collectLogs()
	case "update_policy":
		return applyPolicy(cmd.Payload)
	case "install_app":
		return installApp(cmd.Payload)
	case "uninstall_app":
		return uninstallApp(cmd.Payload)
	case "wipe":
		return wipeDevice()
	case "run_av_scan":
		return runClamAVScan(ctx, cfg, cmd.Payload)
	default:
		return "", fmt.Errorf("unknown command: %s", cmd.Command)
	}
}

func runClamAVScan(ctx context.Context, cfg *config.Config, payload map[string]interface{}) (string, error) {
	// Determine scan paths from payload or use defaults
	paths := []string{"/tmp", "/home", "/var/tmp"}
	if p, ok := payload["paths"].([]interface{}); ok {
		paths = make([]string, 0, len(p))
		for _, v := range p {
			if s, ok := v.(string); ok {
				paths = append(paths, s)
			}
		}
	}

	switch runtime.GOOS {
	case "windows":
		return runWindowsDefenderScan(ctx, cfg, payload)
	default:
		return runClamScan(ctx, cfg, paths)
	}
}

func runClamScan(ctx context.Context, cfg *config.Config, paths []string) (string, error) {
	// Check clamscan is available
	if _, err := exec.LookPath("clamscan"); err != nil {
		return "", fmt.Errorf("clamscan not found: install clamav package")
	}

	args := append([]string{"--infected", "--no-summary", "--recursive", "--stdout"}, paths...)
	out, err := exec.CommandContext(ctx, "clamscan", args...).Output()
	// clamscan exits 1 if infections found — that's not an error for us
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return "", fmt.Errorf("clamscan exec: %w", err)
		}
	}

	output := string(out)
	threats := parseClamAVOutput(output)

	// Report to antivirus service
	reportAVScan(ctx, cfg, threats, output)

	if exitCode == 1 {
		return fmt.Sprintf("scan complete — %d threat(s) found", len(threats)), nil
	}
	return "scan complete — no threats found", nil
}

// AVThreat holds a single detected threat from a ClamAV scan.
type AVThreat struct {
	Path      string `json:"path"`
	Signature string `json:"signature"`
}

func parseClamAVOutput(output string) []AVThreat {
	var threats []AVThreat
	for _, line := range strings.Split(output, "\n") {
		// Format: /path/to/file: Signature.Name FOUND
		if strings.HasSuffix(line, "FOUND") {
			parts := strings.Split(line, ": ")
			if len(parts) >= 2 {
				path := parts[0]
				sig := strings.TrimSuffix(strings.Join(parts[1:], ": "), " FOUND")
				threats = append(threats, AVThreat{Path: path, Signature: sig})
			}
		}
	}
	return threats
}

func reportAVScan(ctx context.Context, cfg *config.Config, threats []AVThreat, rawOutput string) {
	url := fmt.Sprintf("%s/api/antivirus/devices/%s/report", cfg.ServerURL, cfg.DeviceID)
	body, _ := json.Marshal(map[string]interface{}{
		"deviceId":  cfg.DeviceID,
		"platform":  runtime.GOOS,
		"threats":   threats,
		"rawOutput": rawOutput,
		"scannedAt": time.Now().UTC().Format(time.RFC3339),
		"clean":     len(threats) == 0,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[av] reportAVScan: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.DeviceToken)
	resp, err := httpClient(cfg).Do(req)
	if err != nil {
		log.Printf("[av] reportAVScan send: %v", err)
		return
	}
	resp.Body.Close()
}

func runWindowsDefenderScan(ctx context.Context, cfg *config.Config, payload map[string]interface{}) (string, error) {
	out, err := exec.CommandContext(ctx, "powershell", "-Command",
		"Start-MpScan -ScanType QuickScan; Get-MpThreat | ConvertTo-Json").Output()
	if err != nil {
		return "", fmt.Errorf("Windows Defender scan: %w", err)
	}
	// Report raw output to server
	reportAVScan(ctx, cfg, nil, string(out))
	return "Windows Defender scan initiated", nil
}

func lockScreen() (string, error) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("rundll32.exe", "user32.dll,LockWorkStation")
	case "darwin":
		c = exec.Command("osascript", "-e",
			`tell application "System Events" to keystroke "q" using {command down, control down}`)
	default: // linux
		c = exec.Command("loginctl", "lock-sessions")
	}
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("lock screen: %w", err)
	}
	return "lock initiated", nil
}

func restart() (string, error) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("shutdown", "/r", "/t", "30", "/c", "OpenDirectory scheduled restart")
	default: // darwin + linux
		c = exec.Command("sudo", "shutdown", "-r", "+1")
	}
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("restart: %w", err)
	}
	return "restart scheduled in 1 minute", nil
}

func collectLogs() (string, error) {
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("powershell", "-Command",
			"Get-EventLog -LogName System -Newest 50 | ConvertTo-Json")
	case "darwin":
		c = exec.Command("log", "show", "--last", "1h",
			"--predicate", "subsystem == 'com.apple.security'")
	default:
		c = exec.Command("journalctl", "-n", "100", "--no-pager", "-o", "json")
	}
	out, err := c.Output()
	if err != nil {
		return "", fmt.Errorf("collect logs: %w", err)
	}
	// Cap output to 4 KiB to avoid huge payloads
	if len(out) > 4096 {
		out = out[:4096]
	}
	return string(out), nil
}

func applyPolicy(payload map[string]interface{}) (string, error) {
	log.Printf("[commands] applying policy: %v", payload)
	// Future: write policy file, trigger system reload, etc.
	return "policy applied (stub — no-op in agent v1)", nil
}

func installApp(payload map[string]interface{}) (string, error) {
	name, _ := payload["name"].(string)
	downloadURL, _ := payload["downloadUrl"].(string)
	if downloadURL == "" {
		return "", fmt.Errorf("installApp: downloadUrl required")
	}
	log.Printf("[commands] queuing install: %s from %s", name, downloadURL)
	// Future: download, verify hash, install via OS package manager
	return fmt.Sprintf("install queued for %s", name), nil
}

func uninstallApp(payload map[string]interface{}) (string, error) {
	name, _ := payload["name"].(string)
	if name == "" {
		return "", fmt.Errorf("uninstallApp: name required")
	}
	log.Printf("[commands] queuing uninstall: %s", name)
	return fmt.Sprintf("uninstall queued for %s", name), nil
}

func wipeDevice() (string, error) {
	log.Println("[commands] WIPE COMMAND RECEIVED — initiating factory reset")
	var c *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		c = exec.Command("powershell", "-Command", "Reset-Computer -ForceReboot")
	case "darwin":
		c = exec.Command("sudo", "eraseinstall")
	default:
		// Linux wipe is environment-specific; log and return
		return "wipe: not implemented for Linux in agent v1", nil
	}
	if err := c.Start(); err != nil {
		return "", fmt.Errorf("wipe start: %w", err)
	}
	return "wipe initiated", nil
}

func reportResult(ctx context.Context, cfg *config.Config, cmdID, status, result string) {
	url := fmt.Sprintf("%s/api/devices/%s/commands/%s", cfg.ServerURL, cfg.DeviceID, cmdID)
	payload, _ := json.Marshal(map[string]string{
		"status": status,
		"result": result,
	})
	req, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("[commands] reportResult build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.DeviceToken)
	resp, err := httpClient(cfg).Do(req)
	if err != nil {
		log.Printf("[commands] reportResult send: %v", err)
		return
	}
	resp.Body.Close()
}

func httpClient(cfg *config.Config) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec
		},
	}
}
