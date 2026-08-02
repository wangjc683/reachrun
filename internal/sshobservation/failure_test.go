package sshobservation

import (
	"context"
	"fmt"
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

func TestClassifyTCPFailureMakesCancellationTerminal(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome, code := classifyTCPFailure(ctx, ctx, ctx.Err())
	if outcome != probe.OutcomeCancelled || code != probe.FailureCancelled {
		t.Fatalf("classifyTCPFailure() = %q/%q, want cancelled", outcome, code)
	}
}
