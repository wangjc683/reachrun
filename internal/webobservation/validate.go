package webobservation

import (
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/wangjc683/reachrun/internal/probe"
)

// Validate checks the shared envelope and the complete Web-observation
// evidence contract. Downstream scripted adapters should validate fixtures
// through the same interface used for production evidence.
func Validate(result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe envelope: %w", err)
	}
	if result.Probe != ProbeKind {
		return fmt.Errorf("probe must be %q", ProbeKind)
	}
	if result.Failure != nil && !validFailureCode(result.Failure.Code) {
		return fmt.Errorf("unsupported Web observation failure code %q", result.Failure.Code)
	}
	if err := validateInputContract(result.Input, result.Failure); err != nil {
		return fmt.Errorf("invalid Web observation input: %w", err)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		if err := validateFailureForInput(result.Input, result.Failure); err != nil {
			return fmt.Errorf("invalid Web observation failure: %w", err)
		}
		return nil
	}
	if err := validateEvidence(
		result.Input,
		result.ObservedAt,
		result.DurationMS,
		*result.Evidence,
	); err != nil {
		return fmt.Errorf("invalid Web observation evidence: %w", err)
	}
	return nil
}

func validateFailureForInput(input Input, failure *probe.Failure) error {
	if failure == nil || failure.Code == probe.FailureInvalidInput {
		return nil
	}
	if input.Scheme != SchemeHTTP {
		return nil
	}
	switch failure.Code {
	case FailureTLSTimeout,
		FailureTLSConnectionReset,
		FailureTLSCertificate,
		FailureTLSHandshake:
		return fmt.Errorf("plain HTTP input must not produce TLS failure %q", failure.Code)
	default:
		return nil
	}
}

func validateInputContract(input Input, failure *probe.Failure) error {
	normalized, _, inputErr := normalizeRequest(Request{
		Scheme:   input.Scheme,
		Hostname: input.Hostname,
		DialIP:   input.DialIP,
	})
	if normalized != input {
		return fmt.Errorf("input must use its normalized and derived representation")
	}

	isInvalidFailure := failure != nil && failure.Code == probe.FailureInvalidInput
	if inputErr != nil {
		if !isInvalidFailure {
			return fmt.Errorf("invalid request requires invalid_input: %w", inputErr)
		}
		return nil
	}
	if isInvalidFailure {
		return fmt.Errorf("valid request must not produce invalid_input")
	}
	return nil
}

func validateEvidence(
	input Input,
	observedAt time.Time,
	durationMS int64,
	evidence Evidence,
) error {
	const maximumRepresentableDurationMS = math.MaxInt64/int64(time.Millisecond) - 1
	if durationMS > maximumRepresentableDurationMS {
		return fmt.Errorf("duration_ms exceeds the representable observation interval")
	}
	remote, err := netip.ParseAddrPort(evidence.RemoteEndpoint)
	if err != nil {
		return fmt.Errorf("remote_endpoint %q is not an address and port: %w", evidence.RemoteEndpoint, err)
	}
	if remote.Addr().Zone() != "" {
		return fmt.Errorf("remote_endpoint must not include an IPv6 zone")
	}
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	if remote.String() != evidence.RemoteEndpoint {
		return fmt.Errorf("remote_endpoint must be canonical")
	}
	if remote.Addr().String() != input.DialIP || remote.Port() != input.Port {
		return fmt.Errorf(
			"remote_endpoint %q does not match dial target %s:%d",
			evidence.RemoteEndpoint,
			input.DialIP,
			input.Port,
		)
	}
	if evidence.TCPConnectMS < 0 {
		return fmt.Errorf("tcp_connect_ms must not be negative")
	}
	if err := validateHTTP(evidence.HTTP); err != nil {
		return err
	}
	stageMS := evidence.TCPConnectMS
	for _, value := range []int64{evidence.HTTP.TTFBMS, tlsDurationMS(evidence.TLS)} {
		if value < 0 {
			return fmt.Errorf("stage timings must not be negative")
		}
		if value > durationMS-stageMS {
			return fmt.Errorf("stage timings exceed envelope duration_ms")
		}
		stageMS += value
	}

	switch input.Scheme {
	case SchemeHTTP:
		if evidence.TLS != nil {
			return fmt.Errorf("HTTP evidence must not include TLS")
		}
	case SchemeHTTPS:
		if evidence.TLS == nil {
			return fmt.Errorf("HTTPS evidence must include TLS")
		}
		if err := validateTLS(
			input,
			observedAt,
			durationMS,
			evidence.TCPConnectMS,
			evidence.HTTP.TTFBMS,
			*evidence.TLS,
		); err != nil {
			return err
		}
	}

	return nil
}

func tlsDurationMS(observation *TLSObservation) int64 {
	if observation == nil {
		return 0
	}
	return observation.HandshakeMS
}

func validateHTTP(observation HTTPObservation) error {
	if observation.Protocol != "HTTP/1.0" && observation.Protocol != "HTTP/1.1" {
		return fmt.Errorf("unsupported HTTP protocol %q", observation.Protocol)
	}
	if observation.StatusCode < 100 || observation.StatusCode > 599 {
		return fmt.Errorf("status_code must be between 100 and 599")
	}
	if observation.TTFBMS < 0 {
		return fmt.Errorf("ttfb_ms must not be negative")
	}
	if observation.LocationOmitted && observation.Location != "" {
		return fmt.Errorf("omitted location must not include a value")
	}
	if len(observation.Location) > maxLocationBytes || !utf8.ValidString(observation.Location) {
		return fmt.Errorf("location must be valid UTF-8 within %d bytes", maxLocationBytes)
	}
	if observation.RetryAfterOmitted && observation.RetryAfter != "" {
		return fmt.Errorf("omitted retry_after must not include a value")
	}
	if len(observation.RetryAfter) > maxRetryAfterBytes || !utf8.ValidString(observation.RetryAfter) {
		return fmt.Errorf("retry_after must be valid UTF-8 within %d bytes", maxRetryAfterBytes)
	}
	return nil
}

func validateTLS(
	input Input,
	observedAt time.Time,
	durationMS int64,
	tcpConnectMS int64,
	ttfbMS int64,
	observation TLSObservation,
) error {
	if observation.ServerName != input.Hostname {
		return fmt.Errorf(
			"TLS server_name %q does not match hostname %q",
			observation.ServerName,
			input.Hostname,
		)
	}
	if observation.Version == "" || observation.CipherSuite == "" {
		return fmt.Errorf("TLS version and cipher_suite must not be empty")
	}
	if observation.HandshakeMS < 0 {
		return fmt.Errorf("TLS handshake_ms must not be negative")
	}
	if observation.VerifiedChains <= 0 {
		return fmt.Errorf("TLS verified_chains must be positive")
	}
	if observation.ALPN != "" && observation.ALPN != "http/1.1" {
		return fmt.Errorf("HTTP/1.1 backend cannot report TLS ALPN %q", observation.ALPN)
	}

	fingerprint, err := hex.DecodeString(observation.Leaf.SHA256)
	if err != nil || len(fingerprint) != 32 || strings.ToLower(observation.Leaf.SHA256) != observation.Leaf.SHA256 {
		return fmt.Errorf("TLS leaf sha256 must be 64 lowercase hexadecimal characters")
	}
	if observation.Leaf.NotBefore.IsZero() || observation.Leaf.NotAfter.IsZero() {
		return fmt.Errorf("TLS leaf validity times must not be zero")
	}
	if _, offset := observation.Leaf.NotBefore.Zone(); offset != 0 {
		return fmt.Errorf("TLS leaf not_before must use UTC")
	}
	if _, offset := observation.Leaf.NotAfter.Zone(); offset != 0 {
		return fmt.Errorf("TLS leaf not_after must use UTC")
	}
	if !observation.Leaf.NotBefore.Before(observation.Leaf.NotAfter) {
		return fmt.Errorf("TLS leaf not_before must precede not_after")
	}
	attemptStarted := observedAt.Add(-time.Duration(durationMS+1) * time.Millisecond)
	earliestTLSStart := attemptStarted.Add(time.Duration(tcpConnectMS) * time.Millisecond)
	latestTLSCompletion := observedAt.Add(-time.Duration(ttfbMS) * time.Millisecond)
	if observation.Leaf.NotAfter.Before(earliestTLSStart) ||
		observation.Leaf.NotBefore.After(latestTLSCompletion) {
		return fmt.Errorf("TLS leaf validity does not overlap the possible TLS verification window")
	}
	return nil
}

func validFailureCode(code probe.FailureCode) bool {
	switch code {
	case probe.FailureInvalidInput,
		probe.FailureCancelled,
		FailureTCPConnectionRefused,
		FailureTCPNoRoute,
		FailureTCPTimeout,
		FailureTCPConnectionReset,
		FailureTCP,
		FailureTLSTimeout,
		FailureTLSConnectionReset,
		FailureTLSCertificate,
		FailureTLSHandshake,
		FailureHTTPTimeout,
		FailureHTTPConnectionReset,
		FailureHTTPProtocol:
		return true
	default:
		return false
	}
}
