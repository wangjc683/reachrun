package tlsobservation

import (
	"context"
	"fmt"
	"io"
	"syscall"
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestClassifyTCPFailurePreservesStableNetworkReasons(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		code probe.FailureCode
	}{
		"refused":  {fmt.Errorf("dial: %w", syscall.ECONNREFUSED), FailureTCPConnectionRefused},
		"no route": {fmt.Errorf("dial: %w", syscall.ENETUNREACH), FailureTCPNoRoute},
		"reset":    {fmt.Errorf("dial: %w", syscall.ECONNRESET), FailureTCPConnectionReset},
		"timeout":  {context.DeadlineExceeded, FailureTCPTimeout},
		"other":    {fmt.Errorf("dial failed"), FailureTCP},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			outcome, code := classifyTCPFailure(context.Background(), context.Background(), test.err)
			if outcome != probe.OutcomeFailed || code != test.code {
				t.Fatalf("classifyTCPFailure() = %q/%q, want failed/%q", outcome, code, test.code)
			}
		})
	}
}

func TestClassifyUnconfirmedReasonDoesNotClaimMissingSNICausedFailure(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		want UnconfirmedReason
	}{
		"timeout": {context.DeadlineExceeded, UnconfirmedHandshakeTimeout},
		"reset":   {fmt.Errorf("read: %w", syscall.ECONNRESET), UnconfirmedConnectionReset},
		"closed":  {io.EOF, UnconfirmedConnectionClosed},
		"other":   {fmt.Errorf("remote error: tls alert"), UnconfirmedHandshakeFailure},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := classifyUnconfirmedReason(test.err); got != test.want {
				t.Fatalf("classifyUnconfirmedReason() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestClassifyTCPFailureMakesCancellationTerminal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, code := classifyTCPFailure(ctx, ctx, ctx.Err())
	if outcome != probe.OutcomeCancelled || code != probe.FailureCancelled {
		t.Fatalf("classifyTCPFailure() = %q/%q, want cancelled", outcome, code)
	}
}
