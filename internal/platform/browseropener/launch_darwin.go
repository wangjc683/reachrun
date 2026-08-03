//go:build darwin

package browseropener

import (
	"context"
	"os/exec"
)

const platformBackend = "darwin-open"

func launchPlatform(ctx context.Context, rawURL string) error {
	return exec.CommandContext(ctx, "/usr/bin/open", rawURL).Run()
}
