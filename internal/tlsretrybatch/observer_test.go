package tlsretrybatch

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

func TestNewNormalizesConfigAndDependencies(t *testing.T) {
	t.Parallel()

	observer, err := newObserver(Config{}, dependencies{tls: tlsObserverFunc(func(
		context.Context,
		tlsobservation.Request,
	) tlsobservation.Result {
		return tlsobservation.Result{}
	})})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	if observer.timeout != defaultTimeout {
		t.Fatalf("timeout = %s, want %s", observer.timeout, defaultTimeout)
	}
	for _, timeout := range []time.Duration{-time.Nanosecond, maximumTimeout + time.Nanosecond} {
		if _, err := newObserver(Config{Timeout: timeout}, dependencies{tls: observer.tls}); err == nil {
			t.Fatalf("newObserver(%s) error = nil", timeout)
		}
	}
	if _, err := newObserver(Config{}, dependencies{}); err == nil {
		t.Fatal("newObserver() error = nil without TLS dependency")
	}
	if _, err := newObserver(Config{}, dependencies{
		platform: probe.Platform{OS: "test"},
		tls:      observer.tls,
	}); err == nil {
		t.Fatal("newObserver() error = nil with partial platform")
	}
}

func TestObserveRetriesTransientResultsAndSettlesDeterministicResults(t *testing.T) {
	t.Parallel()

	first := "8.8.8.8"
	second := "1.1.1.1"
	tls := &keyedTLSObserver{results: map[string][]tlsobservation.Result{
		first: {
			testTLSFailure(first, probe.OutcomeFailed, tlsobservation.FailureTCPTimeout),
			testTLSCompleted(first),
		},
		second: {
			testTLSFailure(second, probe.OutcomeFailed, tlsobservation.FailureTCPConnectionRefused),
		},
	}}
	var waitsMu sync.Mutex
	var waits []time.Duration
	observer := testObserver(t, tls, func(deps *dependencies) {
		deps.wait = func(_ context.Context, delay time.Duration) error {
			waitsMu.Lock()
			waits = append(waits, delay)
			waitsMu.Unlock()
			return nil
		}
	})

	result := observer.Observe(context.Background(), Request{Targets: []string{first, second}})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCompleted || result.TargetsOmitted != 0 {
		t.Fatalf("terminal = %#v, want completed", result)
	}
	if got := len(result.Targets[0].Attempts); got != 2 {
		t.Fatalf("first attempts = %d, want 2", got)
	}
	if result.Targets[0].Attempts[1].RetryDelayMS != 125 {
		t.Fatalf("retry delay = %d, want 125", result.Targets[0].Attempts[1].RetryDelayMS)
	}
	if got := len(result.Targets[1].Attempts); got != 1 {
		t.Fatalf("connection-refused attempts = %d, want 1", got)
	}
	waitsMu.Lock()
	defer waitsMu.Unlock()
	if len(waits) != 1 || waits[0] != 125*time.Millisecond {
		t.Fatalf("waits = %#v, want one 125ms jitter", waits)
	}
}

func TestObserveExhaustsTheFixedAttemptLimit(t *testing.T) {
	t.Parallel()

	target := "8.8.8.8"
	reset := testTLSFailure(target, probe.OutcomeFailed, tlsobservation.FailureTCPConnectionReset)
	tls := &keyedTLSObserver{results: map[string][]tlsobservation.Result{
		target: {reset, reset, reset},
	}}
	result := testObserver(t, tls).Observe(context.Background(), Request{Targets: []string{target}})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCompleted || len(result.Targets[0].Attempts) != attemptLimit {
		t.Fatalf("result = %#v, want completed after %d attempts", result, attemptLimit)
	}
}

func TestObserveEnforcesTargetAndConcurrencyLimits(t *testing.T) {
	t.Parallel()

	targets := []string{"8.8.8.8", "1.1.1.1", "9.9.9.9", "208.67.222.222", "4.2.2.2"}
	started := make(chan struct{}, len(targets))
	release := make(chan struct{})
	var active atomic.Int32
	var maximum atomic.Int32
	tls := tlsObserverFunc(func(
		_ context.Context,
		request tlsobservation.Request,
	) tlsobservation.Result {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		started <- struct{}{}
		<-release
		active.Add(-1)
		return testTLSFailure(
			request.DialIP,
			probe.OutcomeFailed,
			tlsobservation.FailureTCPConnectionRefused,
		)
	})
	observer := testObserver(t, tls)
	resultChannel := make(chan Result, 1)
	go func() {
		resultChannel <- observer.Observe(context.Background(), Request{Targets: targets})
	}()

	for range concurrencyLimit {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("bounded workers did not start")
		}
	}
	select {
	case <-started:
		t.Fatal("more than two TLS attempts started before a worker was released")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	result := <-resultChannel
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if maximum.Load() != concurrencyLimit {
		t.Fatalf("maximum concurrency = %d, want %d", maximum.Load(), concurrencyLimit)
	}
	if result.TargetsOmitted != 1 || len(result.Targets) != targetLimit {
		t.Fatalf("targets/omitted = %d/%d, want %d/1", len(result.Targets), result.TargetsOmitted, targetLimit)
	}
}

func TestObserveCancelsInFlightBatchAndPendingRetry(t *testing.T) {
	t.Parallel()

	first := "8.8.8.8"
	second := "1.1.1.1"
	parent, cancelParent := context.WithCancel(context.Background())
	defer cancelParent()
	bothStarted := make(chan struct{})
	var started atomic.Int32
	var closeOnce sync.Once
	tls := tlsObserverFunc(func(
		ctx context.Context,
		request tlsobservation.Request,
	) tlsobservation.Result {
		if started.Add(1) == 2 {
			closeOnce.Do(func() { close(bothStarted) })
		}
		<-bothStarted
		if request.DialIP == first {
			return testTLSFailure(first, probe.OutcomeFailed, tlsobservation.FailureTCPTimeout)
		}
		<-ctx.Done()
		return testTLSFailure(second, probe.OutcomeCancelled, probe.FailureCancelled)
	})
	observer := testObserver(t, tls, func(deps *dependencies) {
		deps.wait = func(ctx context.Context, _ time.Duration) error {
			cancelParent()
			<-ctx.Done()
			return ctx.Err()
		}
	})

	result := observer.Observe(parent, Request{Targets: []string{first, second}})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCancelled || result.StopReason != StopCancelled {
		t.Fatalf("terminal = %s/%s, want cancelled", result.Status, result.StopReason)
	}
	if result.Targets[0].Status != TargetInterrupted || len(result.Targets[0].Attempts) != 1 {
		t.Fatalf("first target = %#v, want one transient attempt then interruption", result.Targets[0])
	}
	if result.Targets[1].Status != TargetInterrupted ||
		len(result.Targets[1].Attempts) != 1 ||
		result.Targets[1].Attempts[0].Observation.Outcome != probe.OutcomeCancelled {
		t.Fatalf("second target = %#v, want cancelled in-flight attempt", result.Targets[1])
	}
}

func TestObserveBatchDeadlineStopsWithPartialEvidence(t *testing.T) {
	t.Parallel()

	target := "8.8.8.8"
	tls := tlsObserverFunc(func(
		ctx context.Context,
		_ tlsobservation.Request,
	) tlsobservation.Result {
		<-ctx.Done()
		return testTLSFailure(target, probe.OutcomeFailed, tlsobservation.FailureTCPTimeout)
	})
	startedAt := time.Now()
	observer, err := newObserver(Config{Timeout: 10 * time.Millisecond}, dependencies{
		now:        sequenceClock(startedAt, startedAt.Add(10*time.Millisecond)),
		platform:   testPlatform,
		tls:        tls,
		retryDelay: func() time.Duration { return backoffMin },
		wait:       func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	result := observer.Observe(context.Background(), Request{Targets: []string{target}})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusStopped || result.StopReason != StopBatchTimeout ||
		result.Targets[0].Status != TargetInterrupted {
		t.Fatalf("result = %#v, want stopped/batch_timeout partial evidence", result)
	}
}

func TestObserveInvalidNestedEvidenceCancelsTheBatch(t *testing.T) {
	t.Parallel()

	first := "8.8.8.8"
	second := "1.1.1.1"
	bothStarted := make(chan struct{})
	var started atomic.Int32
	var closeOnce sync.Once
	tls := tlsObserverFunc(func(
		ctx context.Context,
		request tlsobservation.Request,
	) tlsobservation.Result {
		if started.Add(1) == 2 {
			closeOnce.Do(func() { close(bothStarted) })
		}
		<-bothStarted
		if request.DialIP == first {
			return tlsobservation.Result{}
		}
		<-ctx.Done()
		return testTLSFailure(second, probe.OutcomeCancelled, probe.FailureCancelled)
	})
	result := testObserver(t, tls).Observe(
		context.Background(),
		Request{Targets: []string{first, second}},
	)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusStopped || result.StopReason != StopInvalidProbeEvidence {
		t.Fatalf("terminal = %s/%s, want stopped/invalid_probe_evidence", result.Status, result.StopReason)
	}
}

func TestObserveRejectsInvalidSchedulerDelay(t *testing.T) {
	t.Parallel()

	target := "8.8.8.8"
	tls := &keyedTLSObserver{results: map[string][]tlsobservation.Result{
		target: {testTLSFailure(target, probe.OutcomeFailed, tlsobservation.FailureTCPTimeout)},
	}}
	result := testObserver(t, tls, func(deps *dependencies) {
		deps.retryDelay = func() time.Duration { return backoffMin - time.Millisecond }
	}).Observe(context.Background(), Request{Targets: []string{target}})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusStopped || result.StopReason != StopSchedulerFailure {
		t.Fatalf("terminal = %s/%s, want scheduler failure", result.Status, result.StopReason)
	}
}

func TestObserveCancellationWinsAtSuccessCommit(t *testing.T) {
	t.Parallel()

	target := "8.8.8.8"
	ctx, cancel := context.WithCancel(context.Background())
	tls := &keyedTLSObserver{results: map[string][]tlsobservation.Result{
		target: {testTLSCompleted(target)},
	}}
	result := testObserver(t, tls, func(deps *dependencies) {
		deps.beforeSuccessCommit = cancel
	}).Observe(ctx, Request{Targets: []string{target}})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCancelled || result.Targets[0].Status != TargetCompleted {
		t.Fatalf("result = %#v, want cancellation to replace aggregate success", result)
	}
}

func TestObserveInvalidInputReturnsNoAttempts(t *testing.T) {
	t.Parallel()

	tls := &keyedTLSObserver{results: map[string][]tlsobservation.Result{}}
	result := testObserver(t, tls).Observe(
		context.Background(),
		Request{Targets: []string{"192.168.1.1"}},
	)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusStopped || result.StopReason != StopInvalidInput || len(tls.calls) != 0 {
		t.Fatalf("result/calls = %#v/%#v, want invalid input without TLS attempts", result, tls.calls)
	}
}

func TestObservePreCancelledContextStartsNoTargets(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	target := "8.8.8.8"
	tls := &keyedTLSObserver{results: map[string][]tlsobservation.Result{}}
	result := testObserver(t, tls).Observe(ctx, Request{Targets: []string{target}})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCancelled || result.Targets[0].Status != TargetNotStarted || len(tls.calls) != 0 {
		t.Fatalf("result/calls = %#v/%#v, want pre-cancelled batch", result, tls.calls)
	}
}

func TestWaitForRetryHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := waitForRetry(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForRetry() error = %v, want context.Canceled", err)
	}
}
