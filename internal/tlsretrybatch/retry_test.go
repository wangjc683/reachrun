package tlsretrybatch

import (
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

func TestShouldRetryOnlyDeclaredTransientTLSResults(t *testing.T) {
	t.Parallel()

	target := "8.8.8.8"
	tests := map[string]struct {
		result tlsobservation.Result
		want   bool
	}{
		"TCP timeout": {
			result: testTLSFailure(target, probe.OutcomeFailed, tlsobservation.FailureTCPTimeout),
			want:   true,
		},
		"TCP reset": {
			result: testTLSFailure(target, probe.OutcomeFailed, tlsobservation.FailureTCPConnectionReset),
			want:   true,
		},
		"handshake timeout": {
			result: testTLSUnconfirmed(target, tlsobservation.UnconfirmedHandshakeTimeout),
			want:   true,
		},
		"handshake reset": {
			result: testTLSUnconfirmed(target, tlsobservation.UnconfirmedConnectionReset),
			want:   true,
		},
		"completed": {
			result: testTLSCompleted(target),
		},
		"connection refused": {
			result: testTLSFailure(target, probe.OutcomeFailed, tlsobservation.FailureTCPConnectionRefused),
		},
		"no route": {
			result: testTLSFailure(target, probe.OutcomeFailed, tlsobservation.FailureTCPNoRoute),
		},
		"certificate-independent handshake failure": {
			result: testTLSUnconfirmed(target, tlsobservation.UnconfirmedHandshakeFailure),
		},
		"cancelled": {
			result: testTLSFailure(target, probe.OutcomeCancelled, probe.FailureCancelled),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := shouldRetry(test.result); got != test.want {
				t.Fatalf("shouldRetry() = %t, want %t", got, test.want)
			}
		})
	}
}
