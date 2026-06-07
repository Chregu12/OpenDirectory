package compliance

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

// Settings is a flat key→value map of compliance data points.
type Settings map[string]string

// CheckAndReport collects platform settings and POSTs them to the server.
func CheckAndReport(ctx context.Context, cfg *config.Config) error {
	settings := collectSettings()

	url := fmt.Sprintf("%s/api/devices/%s/compliance-check", cfg.ServerURL, cfg.DeviceID)
	payload, err := json.Marshal(map[string]interface{}{
		"settings": settings,
		"platform": runtime.GOOS,
		"arch":     runtime.GOARCH,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.DeviceToken)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("compliance report failed: %w", err)
	}
	resp.Body.Close()
	log.Printf("[compliance] reported %d settings — HTTP %d", len(settings), resp.StatusCode)
	return nil
}

func collectSettings() Settings {
	s := Settings{
		"platform": runtime.GOOS,
		"arch":     runtime.GOARCH,
	}
	switch runtime.GOOS {
	case "linux":
		collectLinux(s)
	case "darwin":
		collectMacOS(s)
	case "windows":
		collectWindows(s)
	}
	return s
}

// run executes a command and returns trimmed stdout; empty string on error.
func run(cmd string, args ...string) string {
	out, err := exec.Command(cmd, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func collectLinux(s Settings) {
	// Firewall (ufw)
	ufwStatus := run("ufw", "status")
	s["firewall_enabled"] = boolStr(strings.Contains(ufwStatus, "Status: active"))

	// Unattended upgrades
	_, err := exec.LookPath("unattended-upgrade")
	s["auto_update_enabled"] = boolStr(err == nil)

	// Full-disk encryption (LUKS)
	lsblk := run("lsblk", "-o", "TYPE")
	s["full_disk_encryption"] = boolStr(strings.Contains(lsblk, "crypt"))

	// SSH root login disabled
	sshConfig := run("cat", "/etc/ssh/sshd_config")
	s["ssh_root_login_disabled"] = boolStr(!strings.Contains(sshConfig, "PermitRootLogin yes"))

	// SELinux / AppArmor
	selinux := run("getenforce")
	s["selinux_enforcing"] = boolStr(strings.EqualFold(selinux, "Enforcing"))
	apparmor := run("aa-status", "--enabled")
	s["apparmor_enabled"] = boolStr(apparmor != "")
}

func collectMacOS(s Settings) {
	// FileVault encryption
	fv := run("fdesetup", "status")
	s["filevault_enabled"] = boolStr(strings.Contains(fv, "FileVault is On"))

	// macOS firewall
	fw := run("defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate")
	s["firewall_enabled"] = boolStr(fw == "1" || fw == "2")

	// Gatekeeper
	gk := run("spctl", "--status")
	s["gatekeeper_enabled"] = boolStr(strings.Contains(gk, "assessments enabled"))

	// Automatic updates
	au := run("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled")
	s["auto_update_enabled"] = boolStr(au == "1")

	// Screen saver lock
	sl := run("defaults", "read", "com.apple.screensaver", "askForPassword")
	s["screen_lock_enabled"] = boolStr(sl == "1")

	// SIP (System Integrity Protection)
	sip := run("csrutil", "status")
	s["sip_enabled"] = boolStr(strings.Contains(sip, "enabled"))
}

func collectWindows(s Settings) {
	// Windows Firewall — count disabled profiles
	fw := run("powershell", "-NonInteractive", "-Command",
		"(Get-NetFirewallProfile -Profile Domain,Public,Private | Where-Object {$_.Enabled -eq $false}).Count")
	s["firewall_enabled"] = boolStr(fw == "" || fw == "0")

	// BitLocker
	bl := run("manage-bde", "-status", "C:")
	s["bitlocker_enabled"] = boolStr(strings.Contains(bl, "Protection On"))

	// Windows Update policy
	au := run("powershell", "-NonInteractive", "-Command",
		"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -ErrorAction SilentlyContinue).NoAutoUpdate")
	s["auto_update_enabled"] = boolStr(au != "1")

	// Windows Defender antivirus
	av := run("powershell", "-NonInteractive", "-Command",
		"Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled")
	s["antivirus_enabled"] = boolStr(strings.TrimSpace(av) == "True")

	// UAC enabled
	uac := run("powershell", "-NonInteractive", "-Command",
		"(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').EnableLUA")
	s["uac_enabled"] = boolStr(strings.TrimSpace(uac) == "1")
}
