//go:build windows

package browseropener

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

const platformBackend = "windows-shell-execute"

func launchPlatform(ctx context.Context, rawURL string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	verb, err := windows.UTF16PtrFromString("open")
	if err != nil {
		return fmt.Errorf("encode ShellExecute verb: %w", err)
	}
	target, err := windows.UTF16PtrFromString(rawURL)
	if err != nil {
		return fmt.Errorf("encode ShellExecute URL: %w", err)
	}
	if err := windows.ShellExecute(0, verb, target, nil, nil, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("ShellExecuteW: %w", err)
	}
	return ctx.Err()
}
