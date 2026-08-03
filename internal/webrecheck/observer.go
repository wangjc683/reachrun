package webrecheck

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

const (
	defaultTimeout    = 25 * time.Second
	maximumTimeout    = 30 * time.Second
	perAttemptTimeout = 5 * time.Second
)

type dependencies struct {
	now      func() time.Time
	platform probe.Platform
	web      webobservation.Observer
}

type observer struct {
	timeout  time.Duration
	now      func() time.Time
	platform probe.Platform
	web      webobservation.Observer
}

type reportBuilder struct {
	input                      Input
	localCandidatesOmitted     int
	referenceCandidatesOmitted int
	attempts                   []Attempt
	webSource                  probe.Source
	hasWebSource               bool
}

type terminal struct {
	status Status
	reason StopReason
	detail string
}

// New creates the production candidate recheck. Every call into the direct
// Web adapter creates its own non-reusable transport and connection.
func New(config Config) (Observer, error) {
	timeout, err := normalizeTimeout(config.Timeout)
	if err != nil {
		return nil, err
	}
	web, err := webobservation.New(webobservation.Config{
		Timeout: min(timeout, perAttemptTimeout),
	})
	if err != nil {
		return nil, fmt.Errorf("create Web observation adapter: %w", err)
	}
	return newObserver(config, dependencies{now: time.Now, web: web})
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
	if deps.web == nil {
		return nil, errors.New("Web observation dependency must not be nil")
	}
	return &observer{
		timeout: timeout, now: deps.now, platform: deps.platform, web: deps.web,
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

// Observe rechecks all bounded candidates even after a successful HTTP
// response. Stopping at the first success would make that response stand in
// for the rest of its candidate source.
func (o *observer) Observe(ctx context.Context, request Request) Result {
	startedAt := o.now()
	input, err := normalizeRequest(request)
	builder := reportBuilder{
		input:    input,
		attempts: make([]Attempt, 0, candidateLimitPerSource*2),
	}
	if err != nil {
		return o.finish(startedAt, builder, terminal{
			status: StatusStopped, reason: StopInvalidInput, detail: err.Error(),
		})
	}
	builder.localCandidatesOmitted = omittedCandidates(input.LocalCandidates)
	builder.referenceCandidatesOmitted = omittedCandidates(input.ReferenceCandidates)
	if state, ok := terminalContext(ctx, ctx); ok {
		return o.finish(startedAt, builder, state)
	}

	recheckCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	for _, candidate := range schedule(input) {
		if state, ok := terminalContext(ctx, recheckCtx); ok {
			return o.finish(startedAt, builder, state)
		}
		attemptCtx, attemptCancel := context.WithTimeout(recheckCtx, perAttemptTimeout)
		observation := o.web.Observe(attemptCtx, webobservation.Request{
			Scheme:   input.Scheme,
			Hostname: input.Hostname,
			DialIP:   candidate.ip,
		})
		attemptCancel()
		if err := o.validateObservation(observation, candidate, &builder); err != nil {
			return o.finish(startedAt, builder, terminal{
				status: StatusStopped, reason: StopInvalidProbeEvidence, detail: err.Error(),
			})
		}
		if state, ok := terminalContext(ctx, recheckCtx); ok {
			if observation.Outcome != probe.OutcomeSucceeded {
				builder.attempts = append(builder.attempts, Attempt{
					CandidateSource: candidate.source,
					Observation:     observation,
				})
			}
			return o.finish(startedAt, builder, state)
		}
		builder.attempts = append(builder.attempts, Attempt{
			CandidateSource: candidate.source,
			Observation:     observation,
		})
		if observation.Outcome == probe.OutcomeCancelled {
			return o.finish(startedAt, builder, terminal{
				status: StatusCancelled, reason: StopCancelled,
			})
		}
	}
	if state, ok := terminalContext(ctx, recheckCtx); ok {
		return o.finish(startedAt, builder, state)
	}

	return o.finish(startedAt, builder, terminal{status: StatusCompleted})
}

func (o *observer) validateObservation(
	result webobservation.Result,
	candidate scheduledCandidate,
	builder *reportBuilder,
) error {
	if err := webobservation.Validate(result); err != nil {
		return fmt.Errorf("invalid Web Observation: %w", err)
	}
	expected := webobservation.Input{
		Scheme:   builder.input.Scheme,
		Hostname: builder.input.Hostname,
		DialIP:   candidate.ip,
		Family:   builder.input.Family,
		Port:     builder.input.Port,
		Method:   builder.input.Method,
		Path:     builder.input.Path,
	}
	if result.Platform != o.platform || result.Input != expected {
		return errors.New("Web Observation changes the fixed platform or first-hop request")
	}
	if !builder.hasWebSource {
		builder.webSource = result.Source
		builder.hasWebSource = true
	} else if result.Source != builder.webSource {
		return errors.New("Web Observation changes the configured adapter")
	}
	return nil
}

func terminalContext(parent, recheck context.Context) (terminal, bool) {
	if errors.Is(parent.Err(), context.Canceled) {
		return terminal{
			status: StatusCancelled, reason: StopCancelled, detail: parent.Err().Error(),
		}, true
	}
	if parent.Err() != nil || errors.Is(recheck.Err(), context.DeadlineExceeded) {
		err := parent.Err()
		if err == nil {
			err = recheck.Err()
		}
		return terminal{
			status: StatusStopped, reason: StopRecheckTimeout, detail: err.Error(),
		}, true
	}
	if errors.Is(recheck.Err(), context.Canceled) {
		return terminal{
			status: StatusCancelled, reason: StopCancelled, detail: recheck.Err().Error(),
		}, true
	}
	return terminal{}, false
}

func (o *observer) finish(
	startedAt time.Time,
	builder reportBuilder,
	state terminal,
) Result {
	finishedAt := o.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return Result{
		SchemaVersion:              SchemaVersion,
		Operation:                  Operation,
		ObservedAt:                 finishedAt.UTC(),
		DurationMS:                 duration,
		Platform:                   o.platform,
		Input:                      builder.input,
		Status:                     state.status,
		StopReason:                 state.reason,
		Detail:                     state.detail,
		LocalCandidatesOmitted:     builder.localCandidatesOmitted,
		ReferenceCandidatesOmitted: builder.referenceCandidatesOmitted,
		Attempts: append(
			make([]Attempt, 0, len(builder.attempts)),
			builder.attempts...,
		),
	}
}
