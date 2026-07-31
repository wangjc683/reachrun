//go:build darwin

package resolverinventory

import (
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestDarwinResolverInventorySourceContract(t *testing.T) {
	result := observeInventory(t)
	if result.Source.Backend != "macos-scutil" || result.Source.Capability != probe.CapabilityNative {
		t.Fatalf("source = %#v, want native macos-scutil", result.Source)
	}
}
