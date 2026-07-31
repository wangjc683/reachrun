//go:build linux

package resolverinventory

import (
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestLinuxResolverInventorySourceContract(t *testing.T) {
	result := observeInventory(t)
	if result.Source.Backend != "linux-resolv-conf" || result.Source.Capability != probe.CapabilityDegraded {
		t.Fatalf("source = %#v, want degraded linux-resolv-conf", result.Source)
	}
	if result.Source.Reason != linuxResolvConfReason && result.Source.Reason != linuxLocalStubReason {
		t.Fatalf("source reason = %q, want a documented resolv.conf limitation", result.Source.Reason)
	}
}
