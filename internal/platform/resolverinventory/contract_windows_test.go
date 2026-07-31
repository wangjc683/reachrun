//go:build windows

package resolverinventory

import (
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestWindowsResolverInventorySourceContract(t *testing.T) {
	result := observeInventory(t)
	if result.Source.Backend != "windows-ip-helper" || result.Source.Capability != probe.CapabilityNative {
		t.Fatalf("source = %#v, want native windows-ip-helper", result.Source)
	}
	for _, group := range result.Evidence.Groups {
		if group.Scope != ScopeScoped {
			t.Fatalf("group scope = %q, want scoped adapter configuration", group.Scope)
		}
		if group.Interface == "" && group.InterfaceIndex == 0 {
			t.Fatal("Windows resolver group lost both interface name and index")
		}
	}
}
