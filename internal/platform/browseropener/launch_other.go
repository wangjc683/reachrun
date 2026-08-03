//go:build !darwin && !linux && !windows

package browseropener

import (
	"context"
	"errors"
	"fmt"
	"runtime"
)

const platformBackend = "unsupported-browser-platform"

func launchPlatform(context.Context, string) error {
	return errors.Join(errUnsupportedPlatform, fmt.Errorf("GOOS %q", runtime.GOOS))
}
