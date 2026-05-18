//go:build windows

package enrollment

import (
	"os/exec"
	"strings"
)

func getSerial() string {
	out, err := exec.Command("wmic", "bios", "get", "serialnumber", "/value").Output()
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "SerialNumber=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "SerialNumber="))
		}
	}
	return "unknown"
}
