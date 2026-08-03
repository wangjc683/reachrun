//go:build linux

package browseropener

import (
	"context"
	"os/exec"
)

const platformBackend = "linux-xdg-open"

func launchPlatform(ctx context.Context, rawURL string) error {
	return exec.CommandContext(ctx, "xdg-open", rawURL).Run()
}
