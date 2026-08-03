package dnshttpspath

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	defaultTimeout = 30 * time.Second
	maximumTimeout = 45 * time.Second
)

type dependencies struct {
	now      func() time.Time
	platform probe.Platform
	dns      dnsobservation.Observer
}

type observer struct {
	timeout  time.Duration
	now      func() time.Time
	platform probe.Platform
	dns      dnsobservation.Observer
}

type reportBuilder struct {
	input                 Input
	aliasesFollowed       int
	httpsObservations     []dnsobservation.Result
	serviceBindings       []BindingDecision
	addressTargets        []AddressTarget
	serviceTargetsOmitted int
	resolverEndpoint      string
	dnsSource             probe.Source
	hasDNSIdentity        bool
}

type terminal struct {
	status     Status
	completion CompletionKind
	reason     StopReason
	detail     string
}

// New creates the production HTTPS discovery path with one immutable DNS
// Observer shared by every exchange in the sequence.
func New(config Config) (Observer, error) {
	if _, err := normalizeTimeout(config.Timeout); err != nil {
		return nil, err
	}
	dns, err := dnsobservation.New(config.DNS)
	if err != nil {
		return nil, fmt.Errorf("create DNS observation adapter: %w", err)
	}
	return newObserver(config, dependencies{now: time.Now, dns: dns})
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
	if deps.dns == nil {
		return nil, errors.New("DNS observation dependency must not be nil")
	}
	return &observer{
		timeout:  timeout,
		now:      deps.now,
		platform: deps.platform,
		dns:      deps.dns,
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

func normalizeRequest(request Request) (Input, error) {
	hostname, err := dnsobservation.NormalizeHostname(request.Hostname)
	input := Input{
		Hostname:           hostname,
		Resolver:           dnsobservation.ResolverID(strings.TrimSpace(string(request.Resolver))),
		Transport:          request.Transport,
		QueryType:          dnsobservation.QueryTypeHTTPS,
		AliasLimit:         aliasLimit,
		ServiceTargetLimit: serviceTargetLimit,
		AddressQueryTypes:  []dnsobservation.QueryType{dnsobservation.QueryTypeA, dnsobservation.QueryTypeAAAA},
	}
	if err != nil {
		return input, err
	}
	if input.Resolver == "" {
		return input, errors.New("resolver id must not be empty")
	}
	switch input.Transport {
	case dnsobservation.TransportUDP, dnsobservation.TransportTCP, dnsobservation.TransportDoH:
	default:
		return input, fmt.Errorf("unsupported DNS transport %q", input.Transport)
	}
	return input, nil
}

// Observe follows at most three HTTPS AliasMode records, always using the same
// resolver and transport, then records A and AAAA evidence for usable final
// targets or the RFC 9460 fallback name.
func (o *observer) Observe(ctx context.Context, request Request) Result {
	startedAt := o.now()
	input, err := normalizeRequest(request)
	builder := reportBuilder{
		input:             input,
		httpsObservations: make([]dnsobservation.Result, 0, aliasLimit+1),
		serviceBindings:   make([]BindingDecision, 0),
		addressTargets:    make([]AddressTarget, 0),
	}
	if err != nil {
		return o.finish(startedAt, builder, terminal{
			status: StatusStopped, reason: StopInvalidInput, detail: err.Error(),
		})
	}
	if state, ok := terminalContext(ctx, ctx); ok {
		return o.finish(startedAt, builder, state)
	}

	pathCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()
	current := input.Hostname
	seen := map[string]struct{}{current: {}}

	for {
		if state, ok := terminalContext(ctx, pathCtx); ok {
			return o.finish(startedAt, builder, state)
		}
		observation := o.dns.Observe(pathCtx, dnsobservation.Request{
			Hostname:  current,
			QueryType: dnsobservation.QueryTypeHTTPS,
			Resolver:  input.Resolver,
			Transport: input.Transport,
		})
		if err := o.validateObservation(
			observation,
			current,
			dnsobservation.QueryTypeHTTPS,
			input.Resolver,
			input.Transport,
			&builder,
		); err != nil {
			return o.finish(startedAt, builder, terminal{
				status: StatusStopped, reason: StopInvalidProbeEvidence, detail: err.Error(),
			})
		}
		if state, ok := terminalContext(ctx, pathCtx); ok {
			if observation.Outcome != probe.OutcomeSucceeded {
				builder.httpsObservations = append(builder.httpsObservations, observation)
			}
			return o.finish(startedAt, builder, state)
		}
		builder.httpsObservations = append(builder.httpsObservations, observation)
		if observation.Outcome == probe.OutcomeCancelled {
			return o.finish(startedAt, builder, terminal{status: StatusCancelled, reason: StopCancelled})
		}
		if observation.Outcome != probe.OutcomeSucceeded {
			return o.finish(startedAt, builder, terminal{
				status: StatusStopped, reason: StopDNSObservationFailed,
				detail: failureDetail(observation),
			})
		}
		if observation.Evidence.AnswerKind == dnsobservation.AnswerKindIncomplete {
			return o.finish(startedAt, builder, terminal{
				status: StatusStopped, reason: StopDNSObservationIncomplete,
				detail: "HTTPS DNS observation is incomplete",
			})
		}

		seen[observation.Evidence.EffectiveName] = struct{}{}
		aliases, services := relevantBindings(*observation.Evidence)
		if len(aliases) > 0 {
			// RFC 9460 permits multiple AliasMode records but recommends one. This
			// diagnostic path follows the first wire-ordered record so its evidence
			// remains deterministic and reproducible.
			target := aliases[0].record.Service.Target
			if target == "." {
				return o.finish(startedAt, builder, terminal{
					status: StatusCompleted, completion: CompletionServiceUnavailable,
				})
			}
			if _, loop := seen[target]; loop {
				return o.finish(startedAt, builder, terminal{
					status: StatusStopped, reason: StopAliasLoop,
					detail: fmt.Sprintf("HTTPS AliasMode target %q repeats the observed chain", target),
				})
			}
			if builder.aliasesFollowed >= aliasLimit {
				return o.finish(startedAt, builder, terminal{
					status: StatusStopped, reason: StopAliasLimit,
					detail: fmt.Sprintf("HTTPS AliasMode limit %d reached", aliasLimit),
				})
			}
			builder.aliasesFollowed++
			seen[target] = struct{}{}
			current = target
			continue
		}

		if len(services) > 0 {
			builder.serviceBindings = evaluateBindings(services)
			builder.addressTargets = serviceAddressTargets(builder.serviceBindings)
			if len(builder.addressTargets) > builder.input.ServiceTargetLimit {
				builder.serviceTargetsOmitted = len(builder.addressTargets) - builder.input.ServiceTargetLimit
				builder.addressTargets = builder.addressTargets[:builder.input.ServiceTargetLimit]
			}
			if len(builder.addressTargets) == 0 {
				return o.finish(startedAt, builder, terminal{
					status: StatusCompleted, completion: CompletionUnsupportedServiceMode,
				})
			}
			state := o.observeAddressTargets(ctx, pathCtx, &builder)
			if state.status == "" {
				state = terminal{status: StatusCompleted, completion: CompletionServiceMode}
			}
			return o.finish(startedAt, builder, state)
		}

		fallback := observation.Evidence.EffectiveName
		if fallback == "." {
			return o.finish(startedAt, builder, terminal{
				status: StatusCompleted, completion: CompletionServiceUnavailable,
			})
		}
		completion := CompletionOriginFallback
		source := TargetOriginFallback
		if builder.aliasesFollowed > 0 {
			completion = CompletionAliasFallback
			source = TargetAliasFallback
		}
		builder.addressTargets = []AddressTarget{{
			Hostname:     fallback,
			Source:       source,
			Observations: make([]dnsobservation.Result, 0, 2),
		}}
		state := o.observeAddressTargets(ctx, pathCtx, &builder)
		if state.status == "" {
			state = terminal{status: StatusCompleted, completion: completion}
		}
		return o.finish(startedAt, builder, state)
	}
}

func (o *observer) observeAddressTargets(
	parent context.Context,
	pathCtx context.Context,
	builder *reportBuilder,
) terminal {
	hadFailure := false
	hadIncomplete := false
	for targetIndex := range builder.addressTargets {
		target := &builder.addressTargets[targetIndex]
		for _, queryType := range builder.input.AddressQueryTypes {
			if state, ok := terminalContext(parent, pathCtx); ok {
				return state
			}
			observation := o.dns.Observe(pathCtx, dnsobservation.Request{
				Hostname:  target.Hostname,
				QueryType: queryType,
				Resolver:  builder.input.Resolver,
				Transport: builder.input.Transport,
			})
			if err := o.validateObservation(
				observation,
				target.Hostname,
				queryType,
				builder.input.Resolver,
				builder.input.Transport,
				builder,
			); err != nil {
				return terminal{
					status: StatusStopped, reason: StopInvalidProbeEvidence, detail: err.Error(),
				}
			}
			if state, ok := terminalContext(parent, pathCtx); ok {
				if observation.Outcome != probe.OutcomeSucceeded {
					target.Observations = append(target.Observations, observation)
				}
				return state
			}
			target.Observations = append(target.Observations, observation)
			if observation.Outcome == probe.OutcomeCancelled {
				return terminal{status: StatusCancelled, reason: StopCancelled}
			}
			if observation.Outcome != probe.OutcomeSucceeded {
				hadFailure = true
				continue
			}
			if observation.Evidence.AnswerKind == dnsobservation.AnswerKindIncomplete {
				hadIncomplete = true
			}
		}
	}
	if hadFailure {
		return terminal{
			status: StatusStopped, reason: StopDNSObservationFailed,
			detail: "one or more final address observations failed",
		}
	}
	if hadIncomplete {
		return terminal{
			status: StatusStopped, reason: StopDNSObservationIncomplete,
			detail: "one or more final address observations are incomplete",
		}
	}
	return terminal{}
}

func (o *observer) validateObservation(
	result dnsobservation.Result,
	hostname string,
	queryType dnsobservation.QueryType,
	resolver dnsobservation.ResolverID,
	transport dnsobservation.Transport,
	builder *reportBuilder,
) error {
	if err := dnsobservation.Validate(result); err != nil {
		return fmt.Errorf("invalid DNS Observation: %w", err)
	}
	if result.Platform != o.platform ||
		result.Input.Hostname != hostname ||
		result.Input.QueryType != queryType ||
		result.Input.Resolver.ID != resolver ||
		result.Input.Transport != transport {
		return errors.New("DNS Observation does not match the requested platform, hostname, or query")
	}
	if !builder.hasDNSIdentity {
		builder.resolverEndpoint = result.Input.Resolver.Endpoint
		builder.dnsSource = result.Source
		builder.hasDNSIdentity = true
	} else if result.Input.Resolver.Endpoint != builder.resolverEndpoint || result.Source != builder.dnsSource {
		return errors.New("DNS Observation changes the configured resolver adapter")
	}
	return nil
}

func failureDetail(result dnsobservation.Result) string {
	if result.Failure == nil || result.Failure.Detail == "" {
		return "DNS observation failed"
	}
	return result.Failure.Detail
}

func terminalContext(parent, path context.Context) (terminal, bool) {
	if errors.Is(parent.Err(), context.Canceled) {
		return terminal{status: StatusCancelled, reason: StopCancelled, detail: parent.Err().Error()}, true
	}
	if parent.Err() != nil || errors.Is(path.Err(), context.DeadlineExceeded) {
		err := parent.Err()
		if err == nil {
			err = path.Err()
		}
		return terminal{status: StatusStopped, reason: StopPathTimeout, detail: err.Error()}, true
	}
	if errors.Is(path.Err(), context.Canceled) {
		return terminal{status: StatusCancelled, reason: StopCancelled, detail: path.Err().Error()}, true
	}
	return terminal{}, false
}

func (o *observer) finish(startedAt time.Time, builder reportBuilder, state terminal) Result {
	finishedAt := o.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return Result{
		SchemaVersion:         SchemaVersion,
		Operation:             Operation,
		ObservedAt:            finishedAt.UTC(),
		DurationMS:            duration,
		Platform:              o.platform,
		Input:                 builder.input,
		Status:                state.status,
		Completion:            state.completion,
		StopReason:            state.reason,
		Detail:                state.detail,
		AliasesFollowed:       builder.aliasesFollowed,
		ServiceTargetsOmitted: builder.serviceTargetsOmitted,
		HTTPSObservations: append(
			make([]dnsobservation.Result, 0, len(builder.httpsObservations)),
			builder.httpsObservations...,
		),
		ServiceBindings: append(
			make([]BindingDecision, 0, len(builder.serviceBindings)),
			builder.serviceBindings...,
		),
		AddressTargets: append(
			make([]AddressTarget, 0, len(builder.addressTargets)),
			builder.addressTargets...,
		),
	}
}
