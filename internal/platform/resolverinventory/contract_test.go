package resolverinventory

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestResolverInventoryContract(t *testing.T) {
	result := observeInventory(t)
	if result.Platform.OS != runtime.GOOS || result.Platform.Arch != runtime.GOARCH {
		t.Fatalf("platform = %#v, want %s/%s", result.Platform, runtime.GOOS, runtime.GOARCH)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		t.Fatalf("outcome = %q, failure = %#v", result.Outcome, result.Failure)
	}
	if len(result.Evidence.Groups) == 0 {
		t.Fatal("resolver inventory returned no groups")
	}
	serverCount := 0
	for _, group := range result.Evidence.Groups {
		serverCount += len(group.Servers)
	}
	if serverCount == 0 {
		t.Fatal("resolver inventory returned no servers")
	}
}

func observeInventory(t *testing.T) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := New().Observe(ctx)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	return result
}
