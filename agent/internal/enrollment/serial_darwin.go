//go:build darwin

package enrollment

import (
	"os/exec"
	"strings"
)

func getSerial() string {
	out, err := exec.Command("system_profiler", "SPHardwareDataType").Output()
	if err != nil {
		return "unknown"
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "Serial Number") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return "unknown"
}
