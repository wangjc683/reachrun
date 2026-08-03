package familycondition

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	defaultTimeout = 2 * time.Second
	maximumTimeout = 10 * time.Second
)

type routeSpec struct {
	family   Family
	network  string
	endpoint string
}

var routeSpecs = [...]routeSpec{
	{family: FamilyIPv4, network: "udp4", endpoint: IPv4RouteTarget},
	{family: FamilyIPv6, network: "udp6", endpoint: IPv6RouteTarget},
}

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type dependencies struct {
	now                 func() time.Time
	dialContext         dialContextFunc
	beforeSuccessCommit func()
}

type observer struct {
	timeout             time.Duration
	now                 func() time.Time
	dialContext         dialContextFunc
	beforeSuccessCommit func()
	source              probe.Source
}

// New validates Config and creates the production observer. UDP connect asks
// the kernel to select a route and source address; this package never calls
// Write, so the observation sends no UDP payload.
func New(config Config) (Observer, error) {
	dialer := &net.Dialer{}
	return newObserver(config, dependencies{
		now:         time.Now,
		dialContext: dialer.DialContext,
	})
}

func newObserver(config Config, deps dependencies) (*observer, error) {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 0 || timeout > maximumTimeout {
		return nil, fmt.Errorf("timeout must be between zero and %s", maximumTimeout)
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.dialContext == nil {
		dialer := &net.Dialer{}
		deps.dialContext = dialer.DialContext
	}
	return &observer{
		timeout:             timeout,
		now:                 deps.now,
		dialContext:         deps.dialContext,
		beforeSuccessCommit: deps.beforeSuccessCommit,
		source: probe.Source{
			Backend:    "go-stdlib-udp-route-selection-no-write",
			Capability: probe.CapabilityNative,
		},
	}, nil
}

func (o *observer) Observe(ctx context.Context) Result {
	startedAt := o.now()
	if ctx.Err() != nil {
		return o.contextFailure(startedAt, ctx, ctx, ctx.Err())
	}

	attemptCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	evidence := Evidence{Conditions: make([]Condition, 0, len(routeSpecs))}
	for _, spec := range routeSpecs {
		condition, err := o.observeRoute(attemptCtx, spec)
		if err != nil {
			if reason, ok := classifyUnavailable(err); ok && ctx.Err() == nil && attemptCtx.Err() == nil {
				evidence.Conditions = append(evidence.Conditions, unavailableCondition(spec, reason))
				continue
			}
			return o.contextFailure(startedAt, ctx, attemptCtx, err)
		}
		evidence.Conditions = append(evidence.Conditions, condition)
	}

	if o.beforeSuccessCommit != nil {
		o.beforeSuccessCommit()
	}
	if ctx.Err() != nil || attemptCtx.Err() != nil {
		return o.contextFailure(startedAt, ctx, attemptCtx, errors.Join(ctx.Err(), attemptCtx.Err()))
	}

	result := o.baseResult(startedAt)
	result.Outcome = probe.OutcomeSucceeded
	result.Evidence = &evidence
	return result
}

func (o *observer) observeRoute(ctx context.Context, spec routeSpec) (Condition, error) {
	conn, err := o.dialContext(ctx, spec.network, spec.endpoint)
	if err != nil {
		return Condition{}, err
	}
	defer conn.Close()

	remote, err := canonicalEndpoint(conn.RemoteAddr())
	if err != nil {
		return Condition{}, fmt.Errorf("inspect %s remote endpoint: %w", spec.family, err)
	}
	if remote != spec.endpoint {
		return Condition{}, fmt.Errorf(
			"%s route selected remote endpoint %q, want %q",
			spec.family,
			remote,
			spec.endpoint,
		)
	}

	localAddress, localZone, err := canonicalLocalAddress(conn.LocalAddr(), spec.family)
	if err != nil {
		return Condition{}, fmt.Errorf("inspect %s local source: %w", spec.family, err)
	}
	return Condition{
		Family:           spec.family,
		Network:          spec.network,
		RouteTarget:      spec.endpoint,
		Status:           StatusRouteSelected,
		Reason:           ReasonKernelRouteSelected,
		LocalAddress:     localAddress,
		LocalZone:        localZone,
		PayloadBytesSent: 0,
	}, nil
}

func canonicalEndpoint(address net.Addr) (string, error) {
	if address == nil {
		return "", errors.New("dialer returned no remote endpoint")
	}
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return "", fmt.Errorf("parse endpoint %q: %w", address.String(), err)
	}
	if endpoint.Addr().Zone() != "" {
		return "", errors.New("remote endpoint unexpectedly includes an IPv6 zone")
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()).String(), nil
}

func canonicalLocalAddress(address net.Addr, family Family) (string, string, error) {
	if address == nil {
		return "", "", errors.New("dialer returned no local source")
	}
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return "", "", fmt.Errorf("parse local source %q: %w", address.String(), err)
	}
	local := endpoint.Addr()
	zone := local.Zone()
	local = local.WithZone("").Unmap()
	if local.IsUnspecified() || local.IsMulticast() {
		return "", "", fmt.Errorf("local source %q is not a selected unicast address", local)
	}
	if (family == FamilyIPv4) != local.Is4() {
		return "", "", fmt.Errorf("local source %q does not match %s", local, family)
	}
	if local.Is4() && zone != "" {
		return "", "", errors.New("IPv4 local source unexpectedly includes a zone")
	}
	return local.String(), zone, nil
}

func unavailableCondition(spec routeSpec, reason Reason) Condition {
	return Condition{
		Family:           spec.family,
		Network:          spec.network,
		RouteTarget:      spec.endpoint,
		Status:           StatusUnavailable,
		Reason:           reason,
		PayloadBytesSent: 0,
	}
}

func (o *observer) contextFailure(
	startedAt time.Time,
	parent context.Context,
	attempt context.Context,
	err error,
) Result {
	outcome := probe.OutcomeFailed
	code := FailureRouteCheck
	switch {
	case errors.Is(parent.Err(), context.Canceled):
		outcome = probe.OutcomeCancelled
		code = probe.FailureCancelled
	case errors.Is(parent.Err(), context.DeadlineExceeded),
		errors.Is(attempt.Err(), context.DeadlineExceeded),
		errors.Is(err, context.DeadlineExceeded),
		isTimeout(err):
		code = probe.FailureTimeout
	case errors.Is(attempt.Err(), context.Canceled), errors.Is(err, context.Canceled):
		outcome = probe.OutcomeCancelled
		code = probe.FailureCancelled
	}
	result := o.baseResult(startedAt)
	result.Outcome = outcome
	result.Failure = &probe.Failure{Code: code}
	if err != nil {
		result.Failure.Detail = err.Error()
	}
	return result
}

func (o *observer) baseResult(startedAt time.Time) Result {
	finishedAt := o.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    finishedAt.UTC(),
		DurationMS:    duration,
		Platform: probe.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Source: o.source,
		Input:  Input{},
	}
}

func isTimeout(err error) bool {
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}
