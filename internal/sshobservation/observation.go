package sshobservation

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
	defaultTimeout = 6 * time.Second
	maximumTimeout = 30 * time.Second
)

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

// New validates Config and creates the production Observer. The direct TCP
// dialer and identification parser remain implementation details.
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
			Backend:    "go-stdlib-tcp-ssh-identification",
			Capability: probe.CapabilityNative,
		},
	}, nil
}

func (o *observer) Observe(ctx context.Context, request Request) Result {
	startedAt := o.now()
	input, target, err := normalizeRequest(request)
	if err != nil {
		return o.failureResult(startedAt, input, probe.OutcomeFailed, probe.FailureInvalidInput, err)
	}
	if ctx.Err() != nil {
		outcome, code := classifyTCPFailure(ctx, ctx, ctx.Err())
		return o.failureResult(startedAt, input, outcome, code, ctx.Err())
	}

	attemptCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	connectStarted := o.now()
	conn, err := o.dialContext(attemptCtx, target.network, target.endpoint)
	connectDone := o.now()
	if err != nil {
		outcome, code := classifyTCPFailure(ctx, attemptCtx, err)
		// No later protocol stage ran, so duration_ms is the bounded TCP
		// attempt duration for this failure.
		return o.failureResult(connectStarted, input, outcome, code, err)
	}
	defer conn.Close()

	remoteEndpoint, err := canonicalRemoteEndpoint(conn.RemoteAddr())
	if err != nil || remoteEndpoint != target.endpoint {
		if err == nil {
			err = fmt.Errorf("dialer connected to %q, want %q", remoteEndpoint, target.endpoint)
		}
		return o.failureResult(startedAt, input, probe.OutcomeFailed, FailureTCP, err)
	}

	deadline, ok := attemptCtx.Deadline()
	if !ok {
		return o.failureResult(
			startedAt,
			input,
			probe.OutcomeFailed,
			FailureTCP,
			errors.New("SSH observation attempt has no deadline"),
		)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return o.commitEvidence(ctx, attemptCtx, startedAt, input, Evidence{
			RemoteEndpoint: remoteEndpoint,
			TCPConnectMS:   durationMS(connectDone.Sub(connectStarted)),
			Identification: Identification{
				Status:            IdentificationUnconfirmed,
				UnconfirmedReason: UnconfirmedExchangeFailure,
			},
		})
	}
	stopInterrupt := context.AfterFunc(attemptCtx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopInterrupt()

	exchangeStarted := o.now()
	parsed, exchangeErr := exchangeIdentification(conn)
	exchangeDone := o.now()
	identification := Identification{
		PreambleLines:            parsed.preambleLines,
		ClientIdentificationSent: parsed.clientLineSent,
		ExchangeMS:               durationMS(exchangeDone.Sub(exchangeStarted)),
	}
	if exchangeErr == nil {
		identification.Status = IdentificationReceived
		identification.ServerIdentification = parsed.raw
		identification.ProtocolVersion = parsed.protocolVersion
		identification.SoftwareVersion = parsed.softwareVersion
		identification.Comments = parsed.comments
	} else {
		identification.Status = IdentificationUnconfirmed
		identification.UnconfirmedReason = classifyUnconfirmedReason(exchangeErr)
	}

	return o.commitEvidence(ctx, attemptCtx, startedAt, input, Evidence{
		RemoteEndpoint: remoteEndpoint,
		TCPConnectMS:   durationMS(connectDone.Sub(connectStarted)),
		Identification: identification,
	})
}

func canonicalRemoteEndpoint(address net.Addr) (string, error) {
	if address == nil {
		return "", errors.New("dialer returned no remote endpoint")
	}
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return "", fmt.Errorf("parse remote endpoint %q: %w", address.String(), err)
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()).String(), nil
}

func (o *observer) successResult(startedAt time.Time, input Input, evidence Evidence) Result {
	result := o.baseResult(startedAt, input)
	result.Outcome = probe.OutcomeSucceeded
	result.Evidence = &evidence
	return result
}

func (o *observer) commitEvidence(
	ctx context.Context,
	attemptCtx context.Context,
	startedAt time.Time,
	input Input,
	evidence Evidence,
) Result {
	if o.beforeSuccessCommit != nil {
		o.beforeSuccessCommit()
	}
	if errors.Is(ctx.Err(), context.Canceled) {
		return o.failureResult(startedAt, input, probe.OutcomeCancelled, probe.FailureCancelled, ctx.Err())
	}
	if ctx.Err() != nil || attemptCtx.Err() != nil {
		evidence.Identification.Status = IdentificationUnconfirmed
		evidence.Identification.UnconfirmedReason = UnconfirmedTimeout
		evidence.Identification.ServerIdentification = ""
		evidence.Identification.ProtocolVersion = ""
		evidence.Identification.SoftwareVersion = ""
		evidence.Identification.Comments = ""
	}
	return o.successResult(startedAt, input, evidence)
}

func (o *observer) failureResult(
	startedAt time.Time,
	input Input,
	outcome probe.Outcome,
	code probe.FailureCode,
	err error,
) Result {
	result := o.baseResult(startedAt, input)
	result.Outcome = outcome
	result.Failure = &probe.Failure{Code: code}
	if err != nil {
		result.Failure.Detail = err.Error()
	}
	return result
}

func (o *observer) baseResult(startedAt time.Time, input Input) Result {
	finishedAt := o.now()
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    finishedAt.UTC(),
		DurationMS:    durationMS(finishedAt.Sub(startedAt)),
		Platform: probe.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Source: o.source,
		Input:  input,
	}
}

func durationMS(duration time.Duration) int64 {
	if duration < 0 {
		return 0
	}
	return duration.Milliseconds()
}
