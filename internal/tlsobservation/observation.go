package tlsobservation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
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
// dialer and deliberately hostname-free TLS configuration remain
// implementation details.
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
			Backend:    "go-stdlib-tls-direct-no-sni",
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

	evidence := Evidence{
		RemoteEndpoint: remoteEndpoint,
		TCPConnectMS:   durationMS(connectDone.Sub(connectStarted)),
	}
	deadline, ok := attemptCtx.Deadline()
	if !ok {
		evidence.TLS = unconfirmedTLS(0, UnconfirmedExchangeFailure)
		return o.commitEvidence(ctx, attemptCtx, startedAt, input, evidence)
	}
	if err := conn.SetDeadline(deadline); err != nil {
		evidence.TLS = unconfirmedTLS(0, UnconfirmedExchangeFailure)
		return o.commitEvidence(ctx, attemptCtx, startedAt, input, evidence)
	}
	stopInterrupt := context.AfterFunc(attemptCtx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopInterrupt()

	// Identity verification is intentionally disabled because this module has
	// no hostname to verify and sends no SNI. The resulting certificate is
	// evidence only; Input makes this limitation explicit in every result.
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	handshakeStarted := o.now()
	handshakeErr := tlsConn.HandshakeContext(attemptCtx)
	handshakeDone := o.now()
	handshakeMS := durationMS(handshakeDone.Sub(handshakeStarted))
	if handshakeErr != nil {
		evidence.TLS = unconfirmedTLS(handshakeMS, classifyUnconfirmedReason(handshakeErr))
		return o.commitEvidence(ctx, attemptCtx, startedAt, input, evidence)
	}

	tlsEvidence, err := completedTLS(tlsConn.ConnectionState(), handshakeMS)
	if err != nil {
		evidence.TLS = unconfirmedTLS(handshakeMS, UnconfirmedExchangeFailure)
	} else {
		evidence.TLS = tlsEvidence
	}
	return o.commitEvidence(ctx, attemptCtx, startedAt, input, evidence)
}

func completedTLS(state tls.ConnectionState, handshakeMS int64) (TLS, error) {
	if !state.HandshakeComplete {
		return TLS{}, errors.New("TLS state is not complete")
	}
	if state.ServerName != "" {
		return TLS{}, fmt.Errorf("TLS state unexpectedly reports server name %q", state.ServerName)
	}
	if len(state.VerifiedChains) != 0 {
		return TLS{}, errors.New("hostname-free TLS state unexpectedly includes verified chains")
	}
	if len(state.PeerCertificates) == 0 {
		return TLS{}, errors.New("TLS state has no peer certificate")
	}
	leaf := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(leaf.Raw)
	return TLS{
		Status:           TLSCompleted,
		HandshakeMS:      handshakeMS,
		Version:          tlsVersionName(state.Version),
		CipherSuite:      tls.CipherSuiteName(state.CipherSuite),
		ALPN:             state.NegotiatedProtocol,
		PeerCertificates: len(state.PeerCertificates),
		Leaf: &LeafCertificate{
			SHA256:    hex.EncodeToString(fingerprint[:]),
			NotBefore: leaf.NotBefore.UTC(),
			NotAfter:  leaf.NotAfter.UTC(),
		},
	}, nil
}

func unconfirmedTLS(handshakeMS int64, reason UnconfirmedReason) TLS {
	return TLS{
		Status:            TLSUnconfirmed,
		UnconfirmedReason: reason,
		HandshakeMS:       handshakeMS,
	}
}

func canonicalRemoteEndpoint(address net.Addr) (string, error) {
	if address == nil {
		return "", errors.New("dialer returned no remote endpoint")
	}
	endpoint, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return "", fmt.Errorf("parse remote endpoint %q: %w", address.String(), err)
	}
	if endpoint.Addr().Zone() != "" {
		return "", errors.New("remote endpoint unexpectedly includes an IPv6 zone")
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port()).String(), nil
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
		evidence.TLS = unconfirmedTLS(evidence.TLS.HandshakeMS, UnconfirmedHandshakeTimeout)
	}
	result := o.baseResult(startedAt, input)
	result.Outcome = probe.OutcomeSucceeded
	result.Evidence = &evidence
	return result
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

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}
