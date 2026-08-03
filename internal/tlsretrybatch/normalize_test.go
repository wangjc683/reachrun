package tlsretrybatch

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

func TestNormalizeRequestCanonicalizesDeduplicatesAndLocksPolicy(t *testing.T) {
	t.Parallel()

	input, err := normalizeRequest(Request{Targets: []string{
		" 8.8.8.8 ",
		"::ffff:8.8.8.8",
		"2606:4700:4700::1111",
	}})
	if err != nil {
		t.Fatalf("normalizeRequest() error = %v", err)
	}
	wantTargets := []string{"8.8.8.8", "2606:4700:4700::1111"}
	if !reflect.DeepEqual(input.Targets, wantTargets) {
		t.Fatalf("targets = %#v, want %#v", input.Targets, wantTargets)
	}
	if input.TargetLimit != targetLimit || input.ConcurrencyLimit != concurrencyLimit ||
		input.AttemptLimit != attemptLimit || input.RetryLimit != retryLimit ||
		input.Port != tlsobservation.Port ||
		input.SNIMode != tlsobservation.SNIOmittedNoHostname ||
		input.IdentityVerification != tlsobservation.IdentityNotPerformedNoHostname ||
		input.PerAttemptTimeoutMS != perAttemptTimeout.Milliseconds() ||
		input.BackoffMinMS != backoffMin.Milliseconds() ||
		input.BackoffMaxMS != backoffMax.Milliseconds() {
		t.Fatalf("fixed policy = %#v", input)
	}
}

func TestNormalizeRequestRejectsUnsafeOrUnboundedTargets(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"empty":     nil,
		"invalid":   {"not-an-ip"},
		"private":   {"192.168.1.1"},
		"IPv6 zone": {"2606:4700:4700::1111%en0"},
		"too many":  uniquePublicTargets(requestTargetLimit + 1),
	}
	for name, targets := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input, err := normalizeRequest(Request{Targets: targets})
			if err == nil {
				t.Fatalf("normalizeRequest(%#v) error = nil", targets)
			}
			if input.Targets == nil {
				t.Fatal("normalized targets = nil, want an array")
			}
		})
	}
}

func uniquePublicTargets(count int) []string {
	targets := make([]string, count)
	for index := range count {
		targets[index] = fmt.Sprintf("8.8.8.%d", index+1)
	}
	return targets
}
