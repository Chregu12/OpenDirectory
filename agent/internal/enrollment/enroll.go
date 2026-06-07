package enrollment

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/opendirectory/agent/internal/config"
)

type enrollRequest struct {
	Token    string `json:"token"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Serial   string `json:"serial"`
}

type enrollResponse struct {
	DeviceID    string `json:"deviceId"`
	DeviceToken string `json:"deviceToken"`
	Message     string `json:"message"`
}

// Enroll registers the device with the OpenDirectory server and saves credentials.
func Enroll(ctx context.Context, cfg *config.Config) error {
	if cfg.EnrollmentToken == "" {
		return fmt.Errorf("OD_ENROLLMENT_TOKEN not set — obtain a token from the OpenDirectory admin console")
	}

	hostname, _ := os.Hostname()
	serial := getSerial()

	payload, err := json.Marshal(enrollRequest{
		Token:    cfg.EnrollmentToken,
		Platform: runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: hostname,
		OS:       runtime.GOOS + "/" + runtime.GOARCH,
		Serial:   serial,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal enrollment request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec
		},
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		cfg.ServerURL+"/api/enrollment/register", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("enrollment failed with HTTP %d", resp.StatusCode)
	}

	var result enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to parse enrollment response: %w", err)
	}
	if result.DeviceID == "" || result.DeviceToken == "" {
		return fmt.Errorf("server returned empty deviceId or deviceToken")
	}

	cfg.DeviceID = result.DeviceID
	cfg.DeviceToken = result.DeviceToken
	return cfg.Save()
}
