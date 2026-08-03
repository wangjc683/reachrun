// Package dnshttpspath follows the HTTPS RR discovery path for one logical
// hostname while preserving each controlled DNS exchange as an independent
// DNS Observation. It owns AliasMode restart, ServiceMode compatibility, and
// final A/AAAA observation; it does not make Web requests or asset assessments.
package dnshttpspath

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// SchemaVersion versions this Phase 0 aggregate independently from the
	// probe envelope embedded in it.
	SchemaVersion = 1
	// Operation identifies this aggregate on the temporary diagnostic CLI.
	Operation = "dns_https_path"

	aliasLimit         = 3
	serviceTargetLimit = 8
)

// Status records whether the bounded discovery sequence completed, stopped
// with partial evidence, or was cancelled.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusStopped   Status = "stopped"
	StatusCancelled Status = "cancelled"
)

// CompletionKind is a protocol fact about the completed HTTPS discovery
// sequence. It is not an asset-health or reachability result.
type CompletionKind string

const (
	CompletionServiceMode            CompletionKind = "service_mode"
	CompletionAliasFallback          CompletionKind = "alias_fallback"
	CompletionOriginFallback         CompletionKind = "origin_fallback"
	CompletionServiceUnavailable     CompletionKind = "service_unavailable"
	CompletionUnsupportedServiceMode CompletionKind = "unsupported_service_mode"
)

// StopReason is a stable orchestration boundary, not a causal diagnosis.
type StopReason string

const (
	StopInvalidInput             StopReason = "invalid_input"
	StopDNSObservationFailed     StopReason = "dns_observation_failed"
	StopDNSObservationIncomplete StopReason = "dns_observation_incomplete"
	StopAliasLoop                StopReason = "alias_loop"
	StopAliasLimit               StopReason = "alias_limit"
	StopPathTimeout              StopReason = "path_timeout"
	StopCancelled                StopReason = "cancelled"
	StopInvalidProbeEvidence     StopReason = "invalid_probe_evidence"
)

// BindingDecision records whether the current Phase 0 HTTPS client can use a
// final ServiceMode record. The original record and all parameter bytes remain
// in HTTPSObservations; this structure only records the bounded decision.
type BindingDecision struct {
	RecordIndex              int           `json:"record_index"`
	Priority                 uint16        `json:"priority"`
	AddressHostname          string        `json:"address_hostname"`
	Usable                   bool          `json:"usable"`
	Reason                   BindingReason `json:"reason"`
	UnsupportedParameterKeys []uint16      `json:"unsupported_parameter_keys,omitempty"`
}

// BindingReason is a stable compatibility category for one ServiceMode RR.
type BindingReason string

const (
	BindingUsable                BindingReason = "usable"
	BindingMalformedParameters   BindingReason = "malformed_parameters"
	BindingUnsupportedParameters BindingReason = "unsupported_parameters"
)

// TargetSource explains why a hostname receives final A and AAAA queries.
type TargetSource string

const (
	TargetServiceMode    TargetSource = "service_mode"
	TargetAliasFallback  TargetSource = "alias_fallback"
	TargetOriginFallback TargetSource = "origin_fallback"
)

// AddressTarget groups the A and AAAA observations for one ServiceMode or
// RFC 9460 fallback hostname. Hints never replace these observations.
type AddressTarget struct {
	Hostname     string                  `json:"hostname"`
	Source       TargetSource            `json:"source"`
	Priority     uint16                  `json:"priority,omitempty"`
	Observations []dnsobservation.Result `json:"observations"`
}

// Config fixes the resolver endpoints used by the nested DNS Observer and the
// total discovery deadline. Alias count, query types, and compatibility rules
// are module policy rather than caller choices.
type Config struct {
	DNS     dnsobservation.Config
	Timeout time.Duration
}

// Request chooses one preconfigured resolver and one explicit transport for
// the complete HTTPS -> HTTPS -> A/AAAA sequence.
type Request struct {
	Hostname  string
	Resolver  dnsobservation.ResolverID
	Transport dnsobservation.Transport
}

// Input records the normalized hostname identity and fixed path policy.
type Input struct {
	Hostname           string                     `json:"hostname"`
	Resolver           dnsobservation.ResolverID  `json:"resolver"`
	Transport          dnsobservation.Transport   `json:"transport"`
	QueryType          dnsobservation.QueryType   `json:"query_type"`
	AliasLimit         int                        `json:"alias_limit"`
	ServiceTargetLimit int                        `json:"service_target_limit"`
	AddressQueryTypes  []dnsobservation.QueryType `json:"address_query_types"`
}

// Result retains valid partial evidence when the bounded path cannot finish.
// Hostname remains the HTTP Host/TLS identity; AddressTargets only change the
// names used to obtain candidate addresses.
type Result struct {
	SchemaVersion         int                     `json:"schema_version"`
	Operation             string                  `json:"operation"`
	ObservedAt            time.Time               `json:"observed_at"`
	DurationMS            int64                   `json:"duration_ms"`
	Platform              probe.Platform          `json:"platform"`
	Input                 Input                   `json:"input"`
	Status                Status                  `json:"status"`
	Completion            CompletionKind          `json:"completion,omitempty"`
	StopReason            StopReason              `json:"stop_reason,omitempty"`
	Detail                string                  `json:"detail,omitempty"`
	AliasesFollowed       int                     `json:"aliases_followed"`
	ServiceTargetsOmitted int                     `json:"service_targets_omitted"`
	HTTPSObservations     []dnsobservation.Result `json:"https_observations"`
	ServiceBindings       []BindingDecision       `json:"service_bindings"`
	AddressTargets        []AddressTarget         `json:"address_targets"`
}

// Observer hides AliasMode traversal, ServiceMode compatibility, and final
// address observation behind one request.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}
