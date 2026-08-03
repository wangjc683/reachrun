// Package tlsobservation records one bounded TLS handshake against a
// caller-selected public IP when no website hostname is available. It produces
// probe evidence; it does not send SNI, verify identity, send HTTP, retry,
// select targets, or assess an asset.
package tlsobservation

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// ProbeKind identifies a hostname-free TLS observation in the shared Phase
	// 0 evidence envelope.
	ProbeKind = probe.KindTLSObservation

	// Port is fixed because this module observes the HTTPS service endpoint
	// defined for a server asset; it does not expose arbitrary port scanning.
	Port uint16 = 443

	// FailureTCPConnectionRefused means the literal target actively refused the
	// TCP connection.
	FailureTCPConnectionRefused probe.FailureCode = "tcp_connection_refused"
	// FailureTCPNoRoute means the local network stack reported no route to the
	// literal target.
	FailureTCPNoRoute probe.FailureCode = "tcp_no_route"
	// FailureTCPTimeout means the attempt deadline expired during TCP connect.
	FailureTCPTimeout probe.FailureCode = "tcp_timeout"
	// FailureTCPConnectionReset means the connection was reset before TCP setup
	// completed.
	FailureTCPConnectionReset probe.FailureCode = "tcp_connection_reset"
	// FailureTCP means TCP connect failed without a more stable classification.
	FailureTCP probe.FailureCode = "tcp_failure"
)

// Family identifies the address family of the one literal dial target.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// SNIMode makes the missing hostname condition explicit in every terminal
// envelope instead of leaving an empty string open to interpretation.
type SNIMode string

const SNIOmittedNoHostname SNIMode = "omitted_no_hostname"

// IdentityVerificationMode records the deliberately limited identity claim of
// this observation. A completed handshake is not a verified website identity.
type IdentityVerificationMode string

const IdentityNotPerformedNoHostname IdentityVerificationMode = "not_performed_no_hostname"

// TLSStatus distinguishes a completed TLS handshake from a reachable TCP
// endpoint whose TLS behavior could not be confirmed without hostname context.
type TLSStatus string

const (
	TLSCompleted   TLSStatus = "completed"
	TLSUnconfirmed TLSStatus = "unconfirmed"
)

// UnconfirmedReason describes the terminal fact observed after TCP connected.
// It never asserts that missing SNI caused the result.
type UnconfirmedReason string

const (
	UnconfirmedHandshakeTimeout UnconfirmedReason = "handshake_timeout"
	UnconfirmedConnectionClosed UnconfirmedReason = "connection_closed"
	UnconfirmedConnectionReset  UnconfirmedReason = "connection_reset"
	UnconfirmedHandshakeFailure UnconfirmedReason = "handshake_failure"
	UnconfirmedExchangeFailure  UnconfirmedReason = "exchange_failure"
)

// Config controls the overall duration of one TCP/TLS observation. Port, SNI,
// identity, retry, and protocol limits are fixed by the module contract.
type Config struct {
	Timeout time.Duration
}

// Request asks for one hostname-free TLS handshake against one public IP.
// DialIP remains text so malformed CLI input can still produce terminal
// invalid_input evidence.
type Request struct {
	DialIP string
}

// Input is the normalized and fully derived request captured in every
// envelope. The SNI and identity modes are fixed, not caller-controlled.
type Input struct {
	DialIP               string                   `json:"dial_ip"`
	Family               Family                   `json:"family"`
	Port                 uint16                   `json:"port"`
	SNIMode              SNIMode                  `json:"sni_mode"`
	IdentityVerification IdentityVerificationMode `json:"identity_verification"`
}

// LeafCertificate records bounded, unverified leaf-certificate facts. Subject
// and SAN strings are deliberately omitted. Presence does not imply trust,
// validity-time, or hostname verification.
type LeafCertificate struct {
	SHA256    string    `json:"sha256"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// TLS records either a completed hostname-free handshake or why the reachable
// endpoint remained unconfirmed. Completed-only fields are omitted otherwise.
type TLS struct {
	Status            TLSStatus         `json:"status"`
	UnconfirmedReason UnconfirmedReason `json:"unconfirmed_reason,omitempty"`
	HandshakeMS       int64             `json:"handshake_ms"`
	Version           string            `json:"version,omitempty"`
	CipherSuite       string            `json:"cipher_suite,omitempty"`
	ALPN              string            `json:"alpn,omitempty"`
	PeerCertificates  int               `json:"peer_certificates,omitempty"`
	Leaf              *LeafCertificate  `json:"leaf,omitempty"`
}

// Evidence exists once TCP connected, even when the bounded TLS handshake
// could not be confirmed. TCP failures remain failed envelopes.
type Evidence struct {
	RemoteEndpoint string `json:"remote_endpoint"`
	TCPConnectMS   int64  `json:"tcp_connect_ms"`
	TLS            TLS    `json:"tls"`
}

// Result is the TLS-observation specialization of the Phase 0 envelope.
type Result = probe.Envelope[Input, Evidence]

// Observer returns one terminal evidence envelope for each explicit
// hostname-free TLS attempt. Expected network failures live inside Result.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}
