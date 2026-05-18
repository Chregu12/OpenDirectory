package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// Config holds agent configuration loaded from file and environment.
type Config struct {
	ServerURL               string `json:"serverUrl"`
	EnrollmentToken         string `json:"enrollmentToken"`
	DeviceToken             string `json:"deviceToken"`
	DeviceID                string `json:"deviceId"`
	HeartbeatIntervalSecs   int    `json:"heartbeatIntervalSecs"`
	CommandPollIntervalSecs int    `json:"commandPollIntervalSecs"`
	ComplianceIntervalSecs  int    `json:"complianceIntervalSecs"`
	InsecureSkipVerify      bool   `json:"insecureSkipVerify"`
	configPath              string
}

func defaultConfigPath() string {
	switch runtime.GOOS {
	case "windows":
		return filepath.Join(os.Getenv("PROGRAMDATA"), "OpenDirectory", "agent.json")
	case "darwin":
		return "/Library/Application Support/OpenDirectory/agent.json"
	default:
		return "/etc/opendirectory/agent.json"
	}
}

// Load reads config from disk (if available) and then overlays environment variables.
func Load() *Config {
	cfg := &Config{
		HeartbeatIntervalSecs:   60,
		CommandPollIntervalSecs: 30,
		ComplianceIntervalSecs:  300,
	}
	cfg.configPath = defaultConfigPath()

	// Load from file (ignore error — may not exist yet)
	if data, err := os.ReadFile(cfg.configPath); err == nil {
		_ = json.Unmarshal(data, cfg)
	}

	// Override from environment variables
	if v := os.Getenv("OD_SERVER_URL"); v != "" {
		cfg.ServerURL = v
	}
	if v := os.Getenv("OD_ENROLLMENT_TOKEN"); v != "" {
		cfg.EnrollmentToken = v
	}
	if v := os.Getenv("OD_DEVICE_TOKEN"); v != "" {
		cfg.DeviceToken = v
	}
	if v := os.Getenv("OD_DEVICE_ID"); v != "" {
		cfg.DeviceID = v
	}
	if os.Getenv("OD_INSECURE") == "true" {
		cfg.InsecureSkipVerify = true
	}
	if v := os.Getenv("OD_HEARTBEAT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.HeartbeatIntervalSecs = n
		}
	}
	if v := os.Getenv("OD_POLL_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CommandPollIntervalSecs = n
		}
	}
	if v := os.Getenv("OD_COMPLIANCE_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.ComplianceIntervalSecs = n
		}
	}

	return cfg
}

// Save persists the current config to disk.
func (c *Config) Save() error {
	dir := filepath.Dir(c.configPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.configPath, data, 0600)
}
