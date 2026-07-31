package resolverinventory

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

var testInventorySource = probe.Source{
	Backend:    "test-resolver-inventory",
	Capability: probe.CapabilityNative,
}

func TestObserveReturnsNormalizedTerminalEvidence(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.August, 1, 8, 0, 0, 0, time.FixedZone("test", 8*60*60))
	finishedAt := startedAt.Add(12 * time.Millisecond)
	collect := func(context.Context) (collected, error) {
		return collected{
			source: testInventorySource,
			evidence: Evidence{Groups: []Group{{
				Servers:       []Server{{Address: "::ffff:192.0.2.53"}},
				SearchDomains: []string{"Example.COM."},
			}}},
		}, nil
	}

	observer := newObserver(collect, inventorySequenceClock(startedAt, finishedAt))
	result := observer.Observe(context.Background())
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Platform.OS != runtime.GOOS || result.Platform.Arch != runtime.GOARCH {
		t.Fatalf("platform = %#v, want %s/%s", result.Platform, runtime.GOOS, runtime.GOARCH)
	}
	if result.ObservedAt != finishedAt.UTC() || result.DurationMS != 12 {
		t.Fatalf("timing = %v/%d, want %v/12", result.ObservedAt, result.DurationMS, finishedAt.UTC())
	}
	server := result.Evidence.Groups[0].Servers[0]
	if server.Address != "192.0.2.53" || server.Port != 53 {
		t.Fatalf("server = %#v, want canonical 192.0.2.53:53", server)
	}
}

func TestObserveNormalizesFailureAndCancellation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ctx     func() context.Context
		collect collectFunc
		outcome probe.Outcome
		code    probe.FailureCode
	}{
		"unavailable": {
			ctx: context.Background,
			collect: func(context.Context) (collected, error) {
				err := errors.New("source unavailable")
				return collected{source: testInventorySource}, &collectError{
					code: FailureUnavailable, source: testInventorySource, err: err,
				}
			},
			outcome: probe.OutcomeFailed,
			code:    FailureUnavailable,
		},
		"invalid evidence": {
			ctx: context.Background,
			collect: func(context.Context) (collected, error) {
				return collected{source: testInventorySource, evidence: Evidence{}}, nil
			},
			outcome: probe.OutcomeFailed,
			code:    FailureInvalid,
		},
		"timeout": {
			ctx: context.Background,
			collect: func(context.Context) (collected, error) {
				return collected{source: testInventorySource}, context.DeadlineExceeded
			},
			outcome: probe.OutcomeFailed,
			code:    probe.FailureTimeout,
		},
		"cancelled": {
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			collect: func(context.Context) (collected, error) {
				return collected{source: testInventorySource}, errors.New("platform stopped")
			},
			outcome: probe.OutcomeCancelled,
			code:    probe.FailureCancelled,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := time.Now()
			result := newObserver(test.collect, inventorySequenceClock(now, now)).Observe(test.ctx())
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Outcome != test.outcome || result.Failure.Code != test.code {
				t.Fatalf("terminal = %q/%q, want %q/%q", result.Outcome, result.Failure.Code, test.outcome, test.code)
			}
		})
	}
}

func TestObserveDiscardsLateSuccessAfterCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	collect := func(context.Context) (collected, error) {
		cancel()
		return collected{
			source: testInventorySource,
			evidence: Evidence{Groups: []Group{{
				Servers: []Server{{Address: "192.0.2.53", Port: 53}},
			}}},
		}, nil
	}
	now := time.Now()
	result := newObserver(collect, inventorySequenceClock(now, now)).Observe(ctx)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Outcome != probe.OutcomeCancelled || result.Evidence != nil {
		t.Fatalf("result = %#v, want cancelled without evidence", result)
	}
}

func TestObserveChecksCancellationAtSuccessCommit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	collect := func(context.Context) (collected, error) {
		return collected{
			source: testInventorySource,
			evidence: Evidence{Groups: []Group{{
				Servers: []Server{{Address: "192.0.2.53", Port: 53}},
			}}},
		}, nil
	}
	now := time.Now()
	observer := newObserver(collect, inventorySequenceClock(now, now)).(*nativeObserver)
	observer.beforeSuccessCommit = cancel

	result := observer.Observe(ctx)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Outcome != probe.OutcomeCancelled || result.Evidence != nil {
		t.Fatalf("result = %#v, want cancellation to win at success commit", result)
	}
}

func inventorySequenceClock(times ...time.Time) func() time.Time {
	index := 0
	return func() time.Time {
		if index >= len(times) {
			panic("test clock exhausted")
		}
		value := times[index]
		index++
		return value
	}
}
