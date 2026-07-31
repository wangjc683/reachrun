//go:build darwin

package resolverinventory

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/wangjc683/reachrun/internal/probe"
)

var macOSSource = probe.Source{
	Backend:    "macos-scutil",
	Capability: probe.CapabilityNative,
}

func collectPlatform(ctx context.Context) (collected, error) {
	command := exec.CommandContext(ctx, "/usr/sbin/scutil", "--dns")
	output, err := command.Output()
	if err != nil {
		return collected{source: macOSSource}, &collectError{
			code:   FailureUnavailable,
			source: macOSSource,
			err:    fmt.Errorf("run /usr/sbin/scutil --dns: %w", err),
		}
	}
	evidence, err := parseScutilDNS(string(output))
	if err != nil {
		return collected{source: macOSSource}, &collectError{
			code:   FailureInvalid,
			source: macOSSource,
			err:    fmt.Errorf("parse scutil DNS configuration: %w", err),
		}
	}
	return collected{evidence: evidence, source: macOSSource}, nil
}
