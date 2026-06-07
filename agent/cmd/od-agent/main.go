package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/opendirectory/agent/internal/commands"
	"github.com/opendirectory/agent/internal/compliance"
	"github.com/opendirectory/agent/internal/config"
	"github.com/opendirectory/agent/internal/enrollment"
)

const version = "1.0.0"

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("[od-agent] ")
	log.Printf("OpenDirectory Agent v%s (%s/%s)", version, runtime.GOOS, runtime.GOARCH)

	cfg := config.Load()
	if cfg.ServerURL == "" {
		log.Fatal("OD_SERVER_URL environment variable required (e.g. https://opendirectory.company.local)")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Graceful shutdown on SIGTERM / SIGINT
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("Received %s — shutting down", sig)
		cancel()
	}()

	// Enroll if no credentials are stored yet
	if cfg.DeviceToken == "" || cfg.DeviceID == "" {
		log.Println("Device not enrolled. Starting enrollment...")
		if err := enrollment.Enroll(ctx, cfg); err != nil {
			log.Fatalf("Enrollment failed: %v", err)
		}
	}
	log.Printf("Running as device %s", cfg.DeviceID)

	runAgent(ctx, cfg)
	log.Println("Agent stopped.")
}

func runAgent(ctx context.Context, cfg *config.Config) {
	hbTicker := time.NewTicker(time.Duration(cfg.HeartbeatIntervalSecs) * time.Second)
	cmdTicker := time.NewTicker(time.Duration(cfg.CommandPollIntervalSecs) * time.Second)
	compTicker := time.NewTicker(time.Duration(cfg.ComplianceIntervalSecs) * time.Second)
	avTicker := time.NewTicker(time.Duration(cfg.AVReportIntervalSecs) * time.Second)
	defer hbTicker.Stop()
	defer cmdTicker.Stop()
	defer compTicker.Stop()
	defer avTicker.Stop()

	// Initial compliance check in background so we don't block startup
	go func() {
		if err := compliance.CheckAndReport(ctx, cfg); err != nil {
			log.Printf("Initial compliance check failed: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-hbTicker.C:
			if err := sendHeartbeat(ctx, cfg); err != nil {
				log.Printf("Heartbeat failed: %v", err)
			}
		case <-cmdTicker.C:
			if err := commands.PollAndExecute(ctx, cfg); err != nil {
				log.Printf("Command poll failed: %v", err)
			}
		case <-compTicker.C:
			if err := compliance.CheckAndReport(ctx, cfg); err != nil {
				log.Printf("Compliance check failed: %v", err)
			}
		case <-avTicker.C:
			go func() {
				if err := reportAVStatus(ctx, cfg); err != nil {
					log.Printf("AV status report failed: %v", err)
				}
			}()
		}
	}
}

func reportAVStatus(ctx context.Context, cfg *config.Config) error {
	// Check ClamAV version
	var clamVersion, sigVersion string
	if out, err := exec.CommandContext(ctx, "clamscan", "--version").Output(); err == nil {
		clamVersion = strings.TrimSpace(string(out))
	} else if runtime.GOOS == "windows" {
		clamVersion = "Windows Defender"
	}
	if out, err := exec.CommandContext(ctx, "freshclam", "--version").Output(); err == nil {
		sigVersion = strings.TrimSpace(string(out))
	}

	payload := map[string]interface{}{
		"deviceId":        cfg.DeviceID,
		"platform":        runtime.GOOS,
		"clamavVersion":   clamVersion,
		"sigVersion":      sigVersion,
		"realtimeEnabled": false, // ClamAV daemon check would go here
		"reportedAt":      time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("%s/api/antivirus/devices/%s/status", cfg.ServerURL, cfg.DeviceID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.DeviceToken)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func sendHeartbeat(ctx context.Context, cfg *config.Config) error {
	payload, err := json.Marshal(map[string]interface{}{
		"deviceId":     cfg.DeviceID,
		"platform":     runtime.GOOS,
		"arch":         runtime.GOARCH,
		"timestamp":    time.Now().UTC().Format(time.RFC3339),
		"agentVersion": version,
	})
	if err != nil {
		return fmt.Errorf("heartbeat marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST",
		cfg.ServerURL+"/api/enrollment/heartbeat", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.DeviceToken)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify}, //nolint:gosec
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat send: %w", err)
	}
	resp.Body.Close()
	return nil
}
