package webobservation

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	defaultTimeout         = 6 * time.Second
	maximumTimeout         = 30 * time.Second
	maxResponseHeaderBytes = 32 << 10
	maxLocationBytes       = 4 << 10
	maxRetryAfterBytes     = 1024
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type dependencies struct {
	now                 func() time.Time
	dialContext         dialContextFunc
	rootCAs             *x509.CertPool
	beforeSuccessCommit func()
}

type observer struct {
	timeout             time.Duration
	now                 func() time.Time
	dialContext         dialContextFunc
	rootCAs             *x509.CertPool
	beforeSuccessCommit func()
	source              probe.Source
}

// New validates Config and creates the production Observer. System trust roots
// and a direct net.Dialer remain implementation details.
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
	if deps.rootCAs != nil {
		deps.rootCAs = deps.rootCAs.Clone()
	}

	return &observer{
		timeout:             timeout,
		now:                 deps.now,
		dialContext:         deps.dialContext,
		rootCAs:             deps.rootCAs,
		beforeSuccessCommit: deps.beforeSuccessCommit,
		source: probe.Source{
			Backend:    "go-stdlib-http1-direct",
			Capability: probe.CapabilityNative,
		},
	}, nil
}

func (o *observer) Observe(ctx context.Context, request Request) Result {
	startedAt := o.now()
	input, target, err := normalizeRequest(request)
	if err != nil {
		return o.failureResult(
			startedAt,
			input,
			probe.OutcomeFailed,
			probe.FailureInvalidInput,
			err,
		)
	}
	if outcome, code, contextErr := classifyContext(ctx, attemptStageTCP); contextErr != nil {
		return o.failureResult(startedAt, input, outcome, code, contextErr)
	}

	attemptCtx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	requestURL := &url.URL{
		Scheme:   string(input.Scheme),
		Host:     input.Hostname,
		Path:     target.path,
		RawPath:  target.rawPath,
		RawQuery: target.rawQuery,
	}
	httpRequest, err := http.NewRequestWithContext(
		attemptCtx,
		input.Method,
		requestURL.String(),
		nil,
	)
	if err != nil {
		return o.failureResult(
			startedAt,
			input,
			probe.OutcomeFailed,
			probe.FailureInvalidInput,
			err,
		)
	}
	httpRequest.Host = input.Hostname
	httpRequest.Close = true
	httpRequest.Header.Set("User-Agent", "ReachRun/phase0")

	trace := &attemptTrace{now: o.now}
	httpRequest = httpRequest.WithContext(httptrace.WithClientTrace(
		httpRequest.Context(),
		trace.clientTrace(),
	))

	var dialed atomic.Bool
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            o.literalDialer(target, &dialed, trace),
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		TLSHandshakeTimeout:    o.timeout,
		ResponseHeaderTimeout:  o.timeout,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		TLSClientConfig: &tls.Config{
			ServerName: target.hostname,
			RootCAs:    o.rootCAs,
			NextProtos: []string{"http/1.1"},
		},
		// A non-nil empty map disables implicit alternate-protocol adapters. The
		// Phase 0 backend performs exactly one auditable HTTP/1.1 exchange.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	defer transport.CloseIdleConnections()

	response, err := transport.RoundTrip(httpRequest)
	if err != nil {
		stage := trace.failureStage(input.Scheme)
		if outcome, code, contextErr := classifyAttemptContext(ctx, attemptCtx, stage); contextErr != nil {
			return o.failureResult(startedAt, input, outcome, code, contextErr)
		}
		return o.failureResult(
			startedAt,
			input,
			probe.OutcomeFailed,
			classifyExchangeFailure(err, stage),
			err,
		)
	}
	if response.Body != nil {
		// Response headers are sufficient for this probe. Do not consume any
		// response-body bytes and do not make a connection reusable.
		_ = response.Body.Close()
	}

	stageDurations, err := trace.successDurations(input.Scheme)
	if err != nil {
		return o.failureResult(
			startedAt,
			input,
			probe.OutcomeFailed,
			FailureHTTPProtocol,
			err,
		)
	}
	evidence, code, err := evidenceFromResponse(input, target, response, trace.remote(), stageDurations)
	if err != nil {
		return o.failureResult(startedAt, input, probe.OutcomeFailed, code, err)
	}

	if o.beforeSuccessCommit != nil {
		o.beforeSuccessCommit()
	}
	if outcome, code, contextErr := classifyAttemptContext(
		ctx,
		attemptCtx,
		attemptStageHTTP,
	); contextErr != nil {
		return o.failureResult(startedAt, input, outcome, code, contextErr)
	}

	result := o.baseResult(startedAt, input)
	result.Outcome = probe.OutcomeSucceeded
	result.Evidence = &evidence
	return result
}

func (o *observer) literalDialer(
	target configuredTarget,
	dialed *atomic.Bool,
	trace *attemptTrace,
) dialContextFunc {
	return func(ctx context.Context, _ string, address string) (net.Conn, error) {
		if !strings.EqualFold(address, logicalEndpoint(target)) {
			return nil, fmt.Errorf(
				"transport requested unexpected endpoint %q instead of %q",
				address,
				logicalEndpoint(target),
			)
		}
		if dialed.Swap(true) {
			return nil, errors.New("transport attempted more than one connection")
		}

		conn, err := o.dialContext(ctx, target.network, target.endpoint)
		if err != nil {
			return nil, err
		}
		remote, err := canonicalRemoteEndpoint(conn.RemoteAddr())
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if remote != target.endpoint {
			_ = conn.Close()
			return nil, fmt.Errorf(
				"connected remote endpoint %q does not match literal target %q",
				remote,
				target.endpoint,
			)
		}
		trace.setRemote(remote)
		return conn, nil
	}
}

func canonicalRemoteEndpoint(address net.Addr) (string, error) {
	if address == nil {
		return "", errors.New("connected socket has no remote endpoint")
	}
	parsed, err := netip.ParseAddrPort(address.String())
	if err != nil {
		return "", fmt.Errorf("parse connected remote endpoint %q: %w", address.String(), err)
	}
	if parsed.Addr().Zone() != "" {
		return "", errors.New("connected remote endpoint unexpectedly includes an IPv6 zone")
	}
	parsed = netip.AddrPortFrom(parsed.Addr().Unmap(), parsed.Port())
	return parsed.String(), nil
}

func evidenceFromResponse(
	input Input,
	target configuredTarget,
	response *http.Response,
	remote string,
	timings stageDurations,
) (Evidence, probe.FailureCode, error) {
	if response == nil {
		return Evidence{}, FailureHTTPProtocol, errors.New("HTTP transport returned no response")
	}
	if response.StatusCode < 100 || response.StatusCode > 599 {
		return Evidence{}, FailureHTTPProtocol, fmt.Errorf(
			"HTTP status %d is outside the supported range",
			response.StatusCode,
		)
	}
	if remote == "" {
		return Evidence{}, FailureHTTPProtocol, errors.New("HTTP response has no connected remote endpoint")
	}
	if remote != target.endpoint {
		return Evidence{}, FailureHTTPProtocol, fmt.Errorf(
			"HTTP remote endpoint %q does not match target %q",
			remote,
			target.endpoint,
		)
	}

	location, locationOmitted := boundedHeaderValue(
		response.Header.Get("Location"),
		maxLocationBytes,
	)
	retryAfter, retryAfterOmitted := boundedHeaderValue(
		response.Header.Get("Retry-After"),
		maxRetryAfterBytes,
	)

	evidence := Evidence{
		RemoteEndpoint: remote,
		TCPConnectMS:   timings.tcp.Milliseconds(),
		HTTP: HTTPObservation{
			Protocol:          response.Proto,
			StatusCode:        response.StatusCode,
			TTFBMS:            timings.ttfb.Milliseconds(),
			Location:          location,
			LocationOmitted:   locationOmitted,
			RetryAfter:        retryAfter,
			RetryAfterOmitted: retryAfterOmitted,
		},
	}
	if input.Scheme == SchemeHTTPS {
		tlsEvidence, err := tlsEvidenceFromState(input, response.TLS, timings.tls)
		if err != nil {
			return Evidence{}, FailureHTTPProtocol, err
		}
		evidence.TLS = &tlsEvidence
	} else if response.TLS != nil {
		return Evidence{}, FailureHTTPProtocol, errors.New("HTTP response unexpectedly includes TLS state")
	}
	return evidence, "", nil
}

func boundedHeaderValue(value string, maximum int) (string, bool) {
	if len(value) <= maximum && utf8.ValidString(value) {
		return value, false
	}
	// A partial URL or Retry-After value is unsafe for later orchestration.
	// Preserve the valid HTTP status and record that optional metadata was
	// intentionally omitted instead of turning first-hop success into failure.
	return "", true
}

func tlsEvidenceFromState(
	input Input,
	state *tls.ConnectionState,
	duration time.Duration,
) (TLSObservation, error) {
	if state == nil || !state.HandshakeComplete {
		return TLSObservation{}, errors.New("HTTPS response lacks a completed TLS state")
	}
	if state.ServerName != input.Hostname {
		return TLSObservation{}, fmt.Errorf(
			"TLS server name %q does not match hostname %q",
			state.ServerName,
			input.Hostname,
		)
	}
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
		return TLSObservation{}, errors.New("HTTPS response lacks a verified certificate chain")
	}
	leaf := state.PeerCertificates[0]
	fingerprint := sha256.Sum256(leaf.Raw)
	return TLSObservation{
		ServerName:     state.ServerName,
		Version:        tlsVersionName(state.Version),
		CipherSuite:    tls.CipherSuiteName(state.CipherSuite),
		ALPN:           state.NegotiatedProtocol,
		HandshakeMS:    duration.Milliseconds(),
		VerifiedChains: len(state.VerifiedChains),
		Leaf: LeafCertificate{
			SHA256:    hex.EncodeToString(fingerprint[:]),
			NotBefore: leaf.NotBefore.UTC(),
			NotAfter:  leaf.NotAfter.UTC(),
		},
	}, nil
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
		Input:  input,
	}
}

type stageDurations struct {
	tcp  time.Duration
	tls  time.Duration
	ttfb time.Duration
}

type attemptTrace struct {
	mu sync.Mutex

	now func() time.Time

	connectStarted time.Time
	connectDone    time.Time
	connectErr     error
	tlsStarted     time.Time
	tlsDone        time.Time
	tlsErr         error
	requestWritten time.Time
	firstByte      time.Time
	remoteEndpoint string
}

func (t *attemptTrace) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			t.mu.Lock()
			defer t.mu.Unlock()
			if t.connectStarted.IsZero() {
				t.connectStarted = t.now()
			}
		},
		ConnectDone: func(_, _ string, err error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.connectDone = t.now()
			t.connectErr = err
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.tlsStarted = t.now()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.tlsDone = t.now()
			t.tlsErr = err
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				return
			}
			t.mu.Lock()
			defer t.mu.Unlock()
			t.requestWritten = t.now()
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			defer t.mu.Unlock()
			t.firstByte = t.now()
		},
	}
}

func (t *attemptTrace) setRemote(endpoint string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remoteEndpoint = endpoint
}

func (t *attemptTrace) remote() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remoteEndpoint
}

func (t *attemptTrace) failureStage(scheme Scheme) attemptStage {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connectDone.IsZero() || t.connectErr != nil {
		return attemptStageTCP
	}
	if scheme == SchemeHTTPS && (t.tlsDone.IsZero() || t.tlsErr != nil) {
		return attemptStageTLS
	}
	return attemptStageHTTP
}

func (t *attemptTrace) successDurations(scheme Scheme) (stageDurations, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connectStarted.IsZero() || t.connectDone.IsZero() || t.connectErr != nil {
		return stageDurations{}, errors.New("successful HTTP response lacks completed TCP timing")
	}
	if t.requestWritten.IsZero() || t.firstByte.IsZero() {
		return stageDurations{}, errors.New("successful HTTP response lacks TTFB timing")
	}
	result := stageDurations{
		tcp:  nonNegativeDuration(t.connectDone.Sub(t.connectStarted)),
		ttfb: nonNegativeDuration(t.firstByte.Sub(t.requestWritten)),
	}
	if scheme == SchemeHTTPS {
		if t.tlsStarted.IsZero() || t.tlsDone.IsZero() || t.tlsErr != nil {
			return stageDurations{}, errors.New("successful HTTPS response lacks completed TLS timing")
		}
		result.tls = nonNegativeDuration(t.tlsDone.Sub(t.tlsStarted))
	}
	return result, nil
}

func nonNegativeDuration(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	return value
}
