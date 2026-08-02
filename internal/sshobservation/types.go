// Package sshobservation records one bounded SSH identification exchange
// against a caller-selected public IP and port. It produces probe evidence; it
// does not select targets, retry, exchange keys, authenticate, or assess an
// asset.
package sshobservation

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// ProbeKind identifies an SSH identification observation in the shared
	// Phase 0 evidence envelope.
	ProbeKind = probe.KindSSHObservation

	// DefaultPort is used when Request.Port is zero.
	DefaultPort uint16 = 22
	// ClientIdentification is the fixed line sent by the probe, without its
	// terminating CRLF. It carries no user or machine identity.
	ClientIdentification = "SSH-2.0-ReachRun_Phase0"

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

// IdentificationStatus distinguishes a confirmed SSH identification from a
// reachable TCP endpoint whose application protocol could not be confirmed.
type IdentificationStatus string

const (
	IdentificationReceived    IdentificationStatus = "received"
	IdentificationUnconfirmed IdentificationStatus = "unconfirmed"
)

// UnconfirmedReason explains why TCP reachability did not become confirmed
// SSH evidence. These values are facts about this bounded exchange, not asset
// or censorship conclusions.
type UnconfirmedReason string

const (
	UnconfirmedInvalidIdentification UnconfirmedReason = "invalid_identification"
	UnconfirmedTimeout               UnconfirmedReason = "identification_timeout"
	UnconfirmedConnectionClosed      UnconfirmedReason = "connection_closed"
	UnconfirmedConnectionReset       UnconfirmedReason = "connection_reset"
	UnconfirmedPreambleLimit         UnconfirmedReason = "preamble_limit_exceeded"
	UnconfirmedExchangeFailure       UnconfirmedReason = "exchange_failure"
)

// Config controls the overall duration of one observation. Identification,
// preamble, and read limits are fixed by the module contract.
type Config struct {
	Timeout time.Duration
}

// Request asks for one bounded identification exchange against one public IP.
// Port zero selects DefaultPort. DialIP remains text so malformed CLI input can
// still produce a terminal invalid_input envelope.
type Request struct {
	DialIP string
	Port   uint16
}

// Input is the normalized request captured in every envelope. The client
// identification is fixed and not caller-controlled.
type Input struct {
	DialIP               string `json:"dial_ip"`
	Family               Family `json:"family"`
	Port                 uint16 `json:"port"`
	ClientIdentification string `json:"client_identification"`
}

// Identification records either a valid server identification or a bounded
// reason why the reachable endpoint was not confirmed as SSH.
type Identification struct {
	Status                   IdentificationStatus `json:"status"`
	UnconfirmedReason        UnconfirmedReason    `json:"unconfirmed_reason,omitempty"`
	ServerIdentification     string               `json:"server_identification,omitempty"`
	ProtocolVersion          string               `json:"protocol_version,omitempty"`
	SoftwareVersion          string               `json:"software_version,omitempty"`
	Comments                 string               `json:"comments,omitempty"`
	PreambleLines            int                  `json:"preamble_lines"`
	ClientIdentificationSent bool                 `json:"client_identification_sent"`
	ExchangeMS               int64                `json:"exchange_ms"`
}

// Evidence exists once TCP connected, even when the bounded identification
// exchange could not confirm SSH. TCP failures remain failed envelopes.
type Evidence struct {
	RemoteEndpoint string         `json:"remote_endpoint"`
	TCPConnectMS   int64          `json:"tcp_connect_ms"`
	Identification Identification `json:"identification"`
}

// Result is the SSH-observation specialization of the Phase 0 envelope.
type Result = probe.Envelope[Input, Evidence]

// Observer returns one terminal evidence envelope for each explicit SSH
// identification attempt. Expected network failures live inside Result.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}
