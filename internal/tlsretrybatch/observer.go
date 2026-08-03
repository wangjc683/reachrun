package tlsretrybatch

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"runtime"
	"sync"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

const (
	defaultTimeout    = 30 * time.Second
	maximumTimeout    = 45 * time.Second
	perAttemptTimeout = 5 * time.Second
	backoffMin        = 100 * time.Millisecond
	backoffMax        = 300 * time.Millisecond
)

type retryDelayFunc func() time.Duration
type waitFunc func(context.Context, time.Duration) error

type dependencies struct {
	now                 func() time.Time
	platform            probe.Platform
	tls                 tlsobservation.Observer
	retryDelay          retryDelayFunc
	wait                waitFunc
	beforeSuccessCommit func()
}

type observer struct {
	timeout             time.Duration
	now                 func() time.Time
	platform            probe.Platform
	tls                 tlsobservation.Observer
	retryDelay          retryDelayFunc
	wait                waitFunc
	beforeSuccessCommit func()
}

type runState struct {
	mu            sync.Mutex
	cancel        context.CancelFunc
	failure       error
	failureReason StopReason
	source        probe.Source
	hasSource     bool
}

type terminal struct {
	status Status
	reason StopReason
	detail string
}

// New creates the production TLS retry batch. Every nested observation still
// creates a fresh TCP/TLS connection through tlsobservation.Observer.
func New(config Config) (Observer, error) {
	timeout, err := normalizeTimeout(config.Timeout)
	if err != nil {
		return nil, err
	}
	tls, err := tlsobservation.New(tlsobservation.Config{
		Timeout: min(timeout, perAttemptTimeout),
	})
	if err != nil {
		return nil, fmt.Errorf("create TLS observation adapter: %w", err)
	}
	return newObserver(config, dependencies{now: time.Now, tls: tls})
}

func newObserver(config Config, deps dependencies) (*observer, error) {
	timeout, err := normalizeTimeout(config.Timeout)
	if err != nil {
		return nil, err
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.platform.OS == "" && deps.platform.Arch == "" {
		deps.platform = probe.Platform{OS: runtime.GOOS, Arch: runtime.GOARCH}
	}
	if deps.platform.OS == "" || deps.platform.Arch == "" {
		return nil, errors.New("platform dependency must include OS and architecture")
	}
	if deps.tls == nil {
		return nil, errors.New("TLS observation dependency must not be nil")
	}
	if deps.retryDelay == nil {
		deps.retryDelay = randomRetryDelay
	}
	if deps.wait == nil {
		deps.wait = waitForRetry
	}
	return &observer{
		timeout:             timeout,
		now:                 deps.now,
		platform:            deps.platform,
		tls:                 deps.tls,
		retryDelay:          deps.retryDelay,
		wait:                deps.wait,
		beforeSuccessCommit: deps.beforeSuccessCommit,
	}, nil
}

func normalizeTimeout(timeout time.Duration) (time.Duration, error) {
	if timeout == 0 {
		return defaultTimeout, nil
	}
	if timeout < 0 || timeout > maximumTimeout {
		return 0, fmt.Errorf("timeout must be between zero and %s", maximumTimeout)
	}
	return timeout, nil
}

func randomRetryDelay() time.Duration {
	span := int64(backoffMax - backoffMin)
	return backoffMin + time.Duration(rand.Int64N(span+1))
}

func waitForRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (o *observer) Observe(ctx context.Context, request Request) Result {
	startedAt := o.now()
	input, err := normalizeRequest(request)
	if err != nil {
		return o.finish(startedAt, input, 0, []TargetResult{}, terminal{
			status: StatusStopped, reason: StopInvalidInput, detail: err.Error(),
		})
	}

	targets := initializeTargets(input)
	omitted := omittedTargets(input)
	if state, ok := parentTerminal(ctx); ok {
		return o.finish(startedAt, input, omitted, targets, state)
	}

	batchCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	state := &runState{cancel: cancel}
	jobs := make(chan int, len(targets))
	for index := range targets {
		jobs <- index
	}
	close(jobs)

	var workers sync.WaitGroup
	for range min(concurrencyLimit, len(targets)) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if batchCtx.Err() != nil {
					return
				}
				o.runTarget(batchCtx, &targets[index], state)
			}
		}()
	}
	workers.Wait()

	if reason, err := state.getFailure(); err != nil {
		return o.finish(startedAt, input, omitted, targets, terminal{
			status: StatusStopped, reason: reason, detail: err.Error(),
		})
	}
	if state, ok := batchTerminal(ctx, batchCtx); ok {
		return o.finish(startedAt, input, omitted, targets, state)
	}
	for index := range targets {
		if targets[index].Status != TargetCompleted {
			return o.finish(startedAt, input, omitted, targets, terminal{
				status: StatusStopped,
				reason: StopSchedulerFailure,
				detail: fmt.Sprintf("target %d ended as %q without a terminal context", index, targets[index].Status),
			})
		}
	}

	if o.beforeSuccessCommit != nil {
		o.beforeSuccessCommit()
	}
	if state, ok := batchTerminal(ctx, batchCtx); ok {
		return o.finish(startedAt, input, omitted, targets, state)
	}
	return o.finish(startedAt, input, omitted, targets, terminal{status: StatusCompleted})
}

func initializeTargets(input Input) []TargetResult {
	values := boundedTargets(input)
	targets := make([]TargetResult, len(values))
	for index, value := range values {
		targets[index] = TargetResult{
			DialIP:   value,
			Family:   targetFamily(value),
			Status:   TargetNotStarted,
			Attempts: []Attempt{},
		}
	}
	return targets
}

func (o *observer) runTarget(
	ctx context.Context,
	target *TargetResult,
	state *runState,
) {
	var retryDelay time.Duration
	for attemptNumber := 1; attemptNumber <= attemptLimit; attemptNumber++ {
		if ctx.Err() != nil {
			interruptTarget(target)
			return
		}
		if attemptNumber > 1 {
			retryDelay = o.retryDelay()
			if retryDelay < backoffMin || retryDelay > backoffMax {
				state.fail(StopSchedulerFailure, fmt.Errorf("retry delay %s is outside fixed bounds", retryDelay))
				interruptTarget(target)
				return
			}
			if err := o.wait(ctx, retryDelay); err != nil {
				if ctx.Err() == nil {
					state.fail(StopSchedulerFailure, fmt.Errorf("wait before target %q attempt %d: %w", target.DialIP, attemptNumber, err))
				}
				interruptTarget(target)
				return
			}
		}

		attemptCtx, cancel := context.WithTimeout(ctx, perAttemptTimeout)
		observation := o.tls.Observe(attemptCtx, tlsobservation.Request{DialIP: target.DialIP})
		cancel()
		if ctx.Err() != nil && observation.Outcome == probe.OutcomeSucceeded {
			interruptTarget(target)
			return
		}
		if err := o.validateObservation(observation, target, state); err != nil {
			state.fail(StopInvalidProbeEvidence, err)
			interruptTarget(target)
			return
		}
		target.Attempts = append(target.Attempts, Attempt{
			Number:       attemptNumber,
			RetryDelayMS: retryDelay.Milliseconds(),
			Observation:  observation,
		})
		if ctx.Err() != nil {
			interruptTarget(target)
			return
		}
		if observation.Outcome == probe.OutcomeCancelled {
			state.fail(StopInvalidProbeEvidence, fmt.Errorf("target %q returned cancellation while the batch was active", target.DialIP))
			interruptTarget(target)
			return
		}
		if !shouldRetry(observation) || attemptNumber == attemptLimit {
			target.Status = TargetCompleted
			return
		}
	}
}

func interruptTarget(target *TargetResult) {
	if len(target.Attempts) == 0 {
		target.Status = TargetNotStarted
		return
	}
	target.Status = TargetInterrupted
}

func (o *observer) validateObservation(
	result tlsobservation.Result,
	target *TargetResult,
	state *runState,
) error {
	if err := tlsobservation.Validate(result); err != nil {
		return fmt.Errorf("target %q returned invalid TLS Observation: %w", target.DialIP, err)
	}
	if result.Platform != o.platform || result.Input != expectedTLSInput(target.DialIP) {
		return fmt.Errorf("target %q changes the fixed platform or TLS request", target.DialIP)
	}
	if err := state.acceptSource(result.Source); err != nil {
		return err
	}
	return nil
}

func (s *runState) acceptSource(source probe.Source) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.hasSource {
		s.source = source
		s.hasSource = true
		return nil
	}
	if source != s.source {
		return errors.New("TLS Observation changes the configured adapter")
	}
	return nil
}

func (s *runState) fail(reason StopReason, err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.failure == nil {
		s.failure = err
		s.failureReason = reason
	}
	s.mu.Unlock()
	s.cancel()
}

func (s *runState) getFailure() (StopReason, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failureReason, s.failure
}

func parentTerminal(ctx context.Context) (terminal, bool) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return terminal{status: StatusCancelled, reason: StopCancelled, detail: ctx.Err().Error()}, true
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return terminal{status: StatusStopped, reason: StopBatchTimeout, detail: ctx.Err().Error()}, true
	}
	return terminal{}, false
}

func batchTerminal(parent, batch context.Context) (terminal, bool) {
	if state, ok := parentTerminal(parent); ok {
		return state, true
	}
	if errors.Is(batch.Err(), context.DeadlineExceeded) {
		return terminal{status: StatusStopped, reason: StopBatchTimeout, detail: batch.Err().Error()}, true
	}
	if errors.Is(batch.Err(), context.Canceled) {
		return terminal{status: StatusCancelled, reason: StopCancelled, detail: batch.Err().Error()}, true
	}
	return terminal{}, false
}

func (o *observer) finish(
	startedAt time.Time,
	input Input,
	omitted int,
	targets []TargetResult,
	state terminal,
) Result {
	finishedAt := o.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	resultTargets := make([]TargetResult, len(targets))
	for index, target := range targets {
		attempts := make([]Attempt, len(target.Attempts))
		copy(attempts, target.Attempts)
		target.Attempts = attempts
		resultTargets[index] = target
	}
	input.Targets = append([]string(nil), input.Targets...)
	return Result{
		SchemaVersion:  SchemaVersion,
		Operation:      Operation,
		ObservedAt:     finishedAt.UTC(),
		DurationMS:     duration,
		Platform:       o.platform,
		Input:          input,
		Status:         state.status,
		StopReason:     state.reason,
		Detail:         state.detail,
		TargetsOmitted: omitted,
		Targets:        resultTargets,
	}
}
