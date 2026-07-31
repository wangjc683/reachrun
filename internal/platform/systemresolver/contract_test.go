package systemresolver

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestSystemResolverContract(t *testing.T) {
	result := resolveLocalhost(t)

	if result.Platform.OS != runtime.GOOS || result.Platform.Arch != runtime.GOARCH {
		t.Fatalf("platform = %#v, want %s/%s", result.Platform, runtime.GOOS, runtime.GOARCH)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		t.Fatalf("outcome = %q, failure = %#v", result.Outcome, result.Failure)
	}
	if len(result.Evidence.Addresses) == 0 {
		t.Fatal("localhost returned no addresses")
	}
}

func assertNativeResolverContract(t *testing.T) {
	t.Helper()
	mode := netDNSMode(os.Getenv("GODEBUG"))
	if mode == "go" || mode == "conditional" {
		t.Skip("GODEBUG does not provide an unconditional native resolver")
	}

	result := resolveLocalhost(t)
	if result.Source.Capability != probe.CapabilityNative {
		t.Fatalf("source = %#v, want native platform resolver", result.Source)
	}
}

func resolveLocalhost(t *testing.T) Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result := New().Resolve(ctx, "localhost")
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	return result
}
