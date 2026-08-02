package webpath

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"runtime"
	"time"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

const (
	defaultTimeout  = 15 * time.Second
	maximumTimeout  = 45 * time.Second
	perProbeTimeout = 5 * time.Second
)

type dependencies struct {
	now      func() time.Time
	platform probe.Platform
	resolver systemresolver.Resolver
	web      webobservation.Observer
}

type observer struct {
	timeout  time.Duration
	now      func() time.Time
	platform probe.Platform
	resolver systemresolver.Resolver
	web      webobservation.Observer
}

type reportBuilder struct {
	input             Input
	hops              []Hop
	redirectsFollowed int
	fallbackUsed      bool
}

type chainResult struct {
	status      Status
	reason      StopReason
	detail      string
	hadResponse bool
}

type hopResult struct {
	hop      *Hop
	response *webobservation.Result
	status   Status
	reason   StopReason
	detail   string
}

// New creates the production Web-path observer with the operating system
// resolver and the direct first-hop Web adapter hidden inside the module.
func New(config Config) (Observer, error) {
	timeout, err := normalizeTimeout(config.Timeout)
	if err != nil {
		return nil, err
	}
	attemptTimeout := min(timeout, perProbeTimeout)
	web, err := webobservation.New(webobservation.Config{Timeout: attemptTimeout})
	if err != nil {
		return nil, fmt.Errorf("create Web observation adapter: %w", err)
	}
	return newObserver(config, dependencies{
		now:      time.Now,
		resolver: systemresolver.New(),
		web:      web,
	})
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
	if deps.resolver == nil {
		return nil, errors.New("system resolver dependency must not be nil")
	}
	if deps.web == nil {
		return nil, errors.New("Web observation dependency must not be nil")
	}
	return &observer{
		timeout:  timeout,
		now:      deps.now,
		platform: deps.platform,
		resolver: deps.resolver,
		web:      deps.web,
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

func (o *observer) Observe(ctx context.Context, request Request) Result {
	startedAt := o.now()
	input, initialURL, err := normalizeInput(request)
	builder := reportBuilder{input: input, hops: make([]Hop, 0, redirectLimit+2)}
	if err != nil {
		return o.finish(startedAt, builder, StatusStopped, StopInvalidInput, err)
	}
	if status, reason, contextErr := terminalContext(ctx, ctx); contextErr != nil {
		return o.finish(startedAt, builder, status, reason, contextErr)
	}

	pathCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	chain := o.observeChain(ctx, pathCtx, initialURL, &builder)
	if chain.status == StatusStopped &&
		chain.reason == StopAllCandidatesFailed &&
		!chain.hadResponse &&
		pathCtx.Err() == nil {
		builder.fallbackUsed = true
		fallbackURL := cloneURL(initialURL)
		fallbackURL.Scheme = string(webobservation.SchemeHTTP)
		chain = o.observeChain(ctx, pathCtx, fallbackURL, &builder)
	}
	if status, reason, contextErr := terminalContext(ctx, pathCtx); contextErr != nil {
		chain.status = status
		chain.reason = reason
		chain.detail = contextErr.Error()
	}

	var finishErr error
	if chain.detail != "" {
		finishErr = errors.New(chain.detail)
	}
	return o.finish(startedAt, builder, chain.status, chain.reason, finishErr)
}

func normalizeInput(request Request) (Input, *url.URL, error) {
	hostname, err := nettarget.NormalizeWebHostname(request.Hostname)
	input := Input{
		Hostname:                hostname,
		InitialURL:              "https://" + hostname + "/",
		Method:                  "GET",
		RedirectLimit:           redirectLimit,
		CandidateLimitPerFamily: candidateLimitPerFamily,
	}
	if err != nil {
		return input, nil, err
	}
	initial := &url.URL{
		Scheme: string(webobservation.SchemeHTTPS),
		Host:   hostname,
		Path:   "/",
	}
	return input, initial, nil
}

func (o *observer) observeChain(
	parent context.Context,
	pathCtx context.Context,
	initial *url.URL,
	builder *reportBuilder,
) chainResult {
	current := cloneURL(initial)
	seen := map[string]struct{}{current.String(): {}}
	hadResponse := false
	pendingRedirect := false

	for {
		observed := o.observeHop(parent, pathCtx, current)
		if observed.hop != nil {
			if pendingRedirect {
				builder.redirectsFollowed++
				pendingRedirect = false
			}
			builder.hops = append(builder.hops, *observed.hop)
		}
		if observed.response == nil {
			return chainResult{
				status: observed.status, reason: observed.reason,
				detail: observed.detail, hadResponse: hadResponse,
			}
		}
		hadResponse = true

		response := observed.response.Evidence.HTTP
		if !isRedirectStatus(response.StatusCode) {
			return chainResult{
				status: StatusCompleted, reason: StopFinalResponse,
				hadResponse: true,
			}
		}
		if builder.redirectsFollowed >= redirectLimit {
			return chainResult{
				status: StatusStopped, reason: StopRedirectLimit,
				detail:      fmt.Sprintf("redirect limit %d reached", redirectLimit),
				hadResponse: true,
			}
		}

		next, reason, err := redirectTarget(current, response)
		if err != nil {
			return chainResult{
				status: StatusStopped, reason: reason,
				detail: err.Error(), hadResponse: true,
			}
		}
		canonical := next.String()
		if _, exists := seen[canonical]; exists {
			return chainResult{
				status: StatusStopped, reason: StopRedirectLoop,
				detail:      fmt.Sprintf("redirect loop returns to %s", canonical),
				hadResponse: true,
			}
		}
		seen[canonical] = struct{}{}
		pendingRedirect = true
		current = next
	}
}

func (o *observer) observeHop(
	parent context.Context,
	pathCtx context.Context,
	targetURL *url.URL,
) hopResult {
	if status, reason, err := terminalContext(parent, pathCtx); err != nil {
		return hopResult{status: status, reason: reason, detail: err.Error()}
	}

	resolveCtx, cancel := context.WithTimeout(pathCtx, perProbeTimeout)
	resolution := o.resolver.Resolve(resolveCtx, targetURL.Hostname())
	cancel()
	if err := systemresolver.Validate(resolution); err != nil {
		return hopResult{
			status: StatusStopped, reason: StopInvalidProbeEvidence,
			detail: fmt.Sprintf("invalid System Resolution: %v", err),
		}
	}
	if resolution.Platform != o.platform || resolution.Input.Hostname != targetURL.Hostname() {
		return hopResult{
			status: StatusStopped, reason: StopInvalidProbeEvidence,
			detail: "System Resolution does not match the requested platform and hostname",
		}
	}
	hop := &Hop{
		URL:        targetURL.String(),
		Resolution: resolution,
		Attempts:   make([]webobservation.Result, 0, candidateLimitPerFamily*2),
	}
	if status, reason, err := terminalContext(parent, pathCtx); err != nil {
		return hopResult{hop: hop, status: status, reason: reason, detail: err.Error()}
	}
	if resolution.Outcome == probe.OutcomeCancelled {
		return hopResult{hop: hop, status: StatusCancelled, reason: StopCancelled}
	}
	if resolution.Outcome != probe.OutcomeSucceeded {
		return hopResult{
			hop: hop, status: StatusStopped, reason: StopResolutionFailed,
			detail: resolution.Failure.Detail,
		}
	}

	candidates := selectPublicCandidates(resolution.Evidence.Addresses)
	if len(candidates) == 0 {
		return hopResult{
			hop: hop, status: StatusStopped, reason: StopNoPublicCandidates,
			detail: "system resolution returned no allowed public Web address",
		}
	}

	for _, candidate := range candidates {
		attemptCtx, cancel := context.WithTimeout(pathCtx, perProbeTimeout)
		observation := o.web.Observe(attemptCtx, webobservation.Request{
			Scheme:   webobservation.Scheme(targetURL.Scheme),
			Hostname: targetURL.Hostname(),
			DialIP:   candidate,
			Path:     targetURL.EscapedPath(),
			RawQuery: targetURL.RawQuery,
		})
		cancel()
		if err := webobservation.Validate(observation); err != nil {
			return hopResult{
				hop: hop, status: StatusStopped, reason: StopInvalidProbeEvidence,
				detail: fmt.Sprintf("invalid Web Observation: %v", err),
			}
		}
		if observation.Platform != o.platform ||
			observation.Input.Scheme != webobservation.Scheme(targetURL.Scheme) ||
			observation.Input.Hostname != targetURL.Hostname() ||
			observation.Input.DialIP != candidate ||
			observation.Input.Path != targetURL.EscapedPath() ||
			observation.Input.RawQuery != targetURL.RawQuery {
			return hopResult{
				hop: hop, status: StatusStopped, reason: StopInvalidProbeEvidence,
				detail: "Web Observation does not match the requested platform and target",
			}
		}
		hop.Attempts = append(hop.Attempts, observation)
		if status, reason, err := terminalContext(parent, pathCtx); err != nil {
			return hopResult{hop: hop, status: status, reason: reason, detail: err.Error()}
		}
		if observation.Outcome == probe.OutcomeCancelled {
			return hopResult{hop: hop, status: StatusCancelled, reason: StopCancelled}
		}
		if observation.Outcome == probe.OutcomeSucceeded {
			selected := observation
			return hopResult{hop: hop, response: &selected}
		}
	}

	return hopResult{
		hop: hop, status: StatusStopped, reason: StopAllCandidatesFailed,
		detail: "all bounded public candidates failed before valid HTTP response headers",
	}
}

func selectPublicCandidates(addresses []systemresolver.Address) []string {
	selected := make([]string, 0, candidateLimitPerFamily*2)
	counts := map[systemresolver.Family]int{
		systemresolver.FamilyIPv4: 0,
		systemresolver.FamilyIPv6: 0,
	}
	for _, address := range addresses {
		if counts[address.Family] >= candidateLimitPerFamily {
			continue
		}
		text, parsed, err := nettarget.NormalizePublicIP(address.IP)
		if err != nil || text != address.IP {
			continue
		}
		family := systemresolver.FamilyIPv6
		if parsed.Is4() {
			family = systemresolver.FamilyIPv4
		}
		if family != address.Family {
			continue
		}
		selected = append(selected, text)
		counts[family]++
	}
	return selected
}

func terminalContext(parent, attempt context.Context) (Status, StopReason, error) {
	if errors.Is(parent.Err(), context.Canceled) {
		return StatusCancelled, StopCancelled, parent.Err()
	}
	if parent.Err() != nil || errors.Is(attempt.Err(), context.DeadlineExceeded) {
		err := parent.Err()
		if err == nil {
			err = attempt.Err()
		}
		return StatusStopped, StopPathTimeout, err
	}
	if errors.Is(attempt.Err(), context.Canceled) {
		return StatusCancelled, StopCancelled, attempt.Err()
	}
	return "", "", nil
}

func (o *observer) finish(
	startedAt time.Time,
	builder reportBuilder,
	status Status,
	reason StopReason,
	err error,
) Result {
	finishedAt := o.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	result := Result{
		SchemaVersion:     SchemaVersion,
		Operation:         Operation,
		ObservedAt:        finishedAt.UTC(),
		DurationMS:        duration,
		Platform:          o.platform,
		Input:             builder.input,
		Status:            status,
		StopReason:        reason,
		RedirectsFollowed: builder.redirectsFollowed,
		HTTPFallbackUsed:  builder.fallbackUsed,
		Hops:              append(make([]Hop, 0, len(builder.hops)), builder.hops...),
	}
	if err != nil {
		result.Detail = err.Error()
	}
	return result
}

func cloneURL(value *url.URL) *url.URL {
	copy := *value
	return &copy
}
