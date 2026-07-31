//go:build !darwin && !windows && !linux

package resolverinventory

import (
	"context"
	"errors"

	"github.com/wangjc683/reachrun/internal/probe"
)

var unsupportedPlatformSource = probe.Source{
	Backend:    "unsupported-resolver-inventory-platform",
	Capability: probe.CapabilityDegraded,
	Reason:     "platform_inventory_unsupported",
}

func collectPlatform(context.Context) (collected, error) {
	err := errors.New("resolver inventory is not supported on this platform")
	return collected{source: unsupportedPlatformSource}, &collectError{
		code:   FailureUnavailable,
		source: unsupportedPlatformSource,
		err:    err,
	}
}
