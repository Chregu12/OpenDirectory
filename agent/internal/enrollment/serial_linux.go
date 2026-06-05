//go:build linux

package enrollment

import (
	"os/exec"
	"strings"
)

func getSerial() string {
	out, err := exec.Command("dmidecode", "-s", "system-serial-number").Output()
	if err != nil {
		return "unknown"
	}
	s := strings.TrimSpace(string(out))
	if s == "" {
		return "unknown"
	}
	return s
}
