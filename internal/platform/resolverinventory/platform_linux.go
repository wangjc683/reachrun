//go:build linux

package resolverinventory

import (
	"context"
	"fmt"
	"os"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	linuxResolvConfReason = "resolv_conf_does_not_expose_per_link_resolvers"
	linuxLocalStubReason  = "local_stub_hides_upstream_resolvers"
)

func collectPlatform(ctx context.Context) (collected, error) {
	source := linuxSource(linuxResolvConfReason)
	if err := ctx.Err(); err != nil {
		return collected{source: source}, err
	}
	contents, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return collected{source: source}, &collectError{
			code:   FailureUnavailable,
			source: source,
			err:    fmt.Errorf("read /etc/resolv.conf: %w", err),
		}
	}
	if err := ctx.Err(); err != nil {
		return collected{source: source}, err
	}

	evidence, localStub, err := parseResolvConf(string(contents))
	if localStub {
		source = linuxSource(linuxLocalStubReason)
	}
	if err != nil {
		return collected{source: source}, &collectError{
			code:   FailureInvalid,
			source: source,
			err:    fmt.Errorf("parse /etc/resolv.conf: %w", err),
		}
	}
	return collected{evidence: evidence, source: source}, nil
}

func linuxSource(reason string) probe.Source {
	return probe.Source{
		Backend:    "linux-resolv-conf",
		Capability: probe.CapabilityDegraded,
		Reason:     reason,
	}
}
