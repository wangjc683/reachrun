// Package webobservation records one controlled first-hop Web exchange against
// a caller-selected public IP while preserving the logical HTTP and TLS
// hostname. It produces probe evidence; it does not select candidates, retry,
// follow redirects, aggregate address families, or assess an asset.
package webobservation

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// ProbeKind identifies a direct first-hop Web observation in the shared
	// Phase 0 evidence envelope.
	ProbeKind = probe.KindWebObservation

	// FailureTCPConnectionRefused means the literal target actively refused the
	// TCP connection.
	FailureTCPConnectionRefused probe.FailureCode = "tcp_connection_refused"
	// FailureTCPNoRoute means the local network stack reported no route to the
	// literal target.
	FailureTCPNoRoute probe.FailureCode = "tcp_no_route"
	// FailureTCPTimeout means the attempt deadline expired during TCP connect.
	FailureTCPTimeout probe.FailureCode = "tcp_timeout"
	// FailureTCPConnectionReset means the connection was reset during the TCP
	// stage before TLS or HTTP could begin.
	FailureTCPConnectionReset probe.FailureCode = "tcp_connection_reset"
	// FailureTCP means TCP connect failed without a more stable classification.
	FailureTCP probe.FailureCode = "tcp_failure"

	// FailureTLSTimeout means the attempt deadline expired during TLS setup.
	FailureTLSTimeout probe.FailureCode = "tls_timeout"
	// FailureTLSConnectionReset means the peer reset the connection during TLS.
	FailureTLSConnectionReset probe.FailureCode = "tls_connection_reset"
	// FailureTLSCertificate means public-chain, validity-time, or hostname
	// verification failed.
	FailureTLSCertificate probe.FailureCode = "tls_certificate_failure"
	// FailureTLSHandshake means the TLS handshake failed for another reason.
	FailureTLSHandshake probe.FailureCode = "tls_handshake_failure"

	// FailureHTTPTimeout means the attempt deadline expired while writing the
	// request or waiting for response headers.
	FailureHTTPTimeout probe.FailureCode = "http_timeout"
	// FailureHTTPConnectionReset means the peer reset an established HTTP
	// exchange.
	FailureHTTPConnectionReset probe.FailureCode = "http_connection_reset"
	// FailureHTTPProtocol means no syntactically valid bounded HTTP response was
	// obtained after the transport stages succeeded.
	FailureHTTPProtocol probe.FailureCode = "http_protocol_failure"
)

// Scheme selects the one protocol attempted by a Request.
type Scheme string

const (
	SchemeHTTP  Scheme = "http"
	SchemeHTTPS Scheme = "https"
)

// Family identifies the address family of the one literal dial target.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Config controls the overall duration of one observation. All other Web
// request and resource limits are fixed by the module contract.
type Config struct {
	Timeout time.Duration
}

// Request asks for one first-hop GET / against one public IP. DialIP is kept as
// text so malformed CLI input can still produce a terminal invalid_input
// envelope instead of escaping the probe contract as a parsing error.
type Request struct {
	Scheme   Scheme
	Hostname string
	DialIP   string
}

// Input is the normalized, fully derived request captured in every envelope.
// Port, Method, and Path are not caller-controlled.
type Input struct {
	Scheme   Scheme `json:"scheme"`
	Hostname string `json:"hostname"`
	DialIP   string `json:"dial_ip"`
	Family   Family `json:"family"`
	Port     uint16 `json:"port"`
	Method   string `json:"method"`
	Path     string `json:"path"`
}

// LeafCertificate records bounded identity facts about the verified leaf
// certificate. Subject and SAN strings are deliberately omitted.
type LeafCertificate struct {
	SHA256    string    `json:"sha256"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
}

// TLSObservation records a successfully verified TLS connection. Its presence
// itself means the public trust chain, validity time, and Hostname succeeded.
type TLSObservation struct {
	ServerName     string          `json:"server_name"`
	Version        string          `json:"version"`
	CipherSuite    string          `json:"cipher_suite"`
	ALPN           string          `json:"alpn,omitempty"`
	HandshakeMS    int64           `json:"handshake_ms"`
	VerifiedChains int             `json:"verified_chains"`
	Leaf           LeafCertificate `json:"leaf"`
}

// HTTPObservation records one bounded first-hop HTTP response. Redirect
// metadata is evidence only; the Observer never follows it.
type HTTPObservation struct {
	Protocol          string `json:"protocol"`
	StatusCode        int    `json:"status_code"`
	TTFBMS            int64  `json:"ttfb_ms"`
	Location          string `json:"location,omitempty"`
	LocationOmitted   bool   `json:"location_omitted,omitempty"`
	RetryAfter        string `json:"retry_after,omitempty"`
	RetryAfterOmitted bool   `json:"retry_after_omitted,omitempty"`
}

// Evidence is present only after valid response headers arrive. Failed
// envelope outcomes intentionally carry no partial evidence under envelope v1.
type Evidence struct {
	RemoteEndpoint string          `json:"remote_endpoint"`
	TCPConnectMS   int64           `json:"tcp_connect_ms"`
	TLS            *TLSObservation `json:"tls,omitempty"`
	HTTP           HTTPObservation `json:"http"`
}

// Result is the Web-observation specialization of the Phase 0 envelope.
type Result = probe.Envelope[Input, Evidence]

// Observer returns one terminal evidence envelope for each explicit first-hop
// exchange. Expected network, TLS, and HTTP failures live inside Result.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}
