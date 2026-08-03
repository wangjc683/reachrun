// Package webrecheck performs one bounded, controlled recheck of local and
// reference Web candidates for the same logical hostname. It keeps every
// first-hop Web Observation as evidence and deliberately does not diagnose
// DNS, CDN, GeoDNS, or asset health.
package webrecheck

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

const (
	// SchemaVersion versions this aggregate independently from the probe
	// envelopes embedded in it.
	SchemaVersion = 1
	// Operation identifies this Phase 0 aggregate report.
	Operation = "web_candidate_recheck"

	candidateLimitPerSource = 2
	httpsPort               = 443
	httpMethod              = "GET"
	httpPath                = "/"
	retryLimit              = 0
	redirectLimit           = 0
)

// Status records whether all bounded candidates were observed, the aggregate
// stopped with partial evidence, or the caller cancelled it.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusStopped   Status = "stopped"
	StatusCancelled Status = "cancelled"
)

// StopReason is a stable orchestration fact, not a Web or DNS assessment.
type StopReason string

const (
	StopInvalidInput         StopReason = "invalid_input"
	StopRecheckTimeout       StopReason = "recheck_timeout"
	StopCancelled            StopReason = "cancelled"
	StopInvalidProbeEvidence StopReason = "invalid_probe_evidence"
)

// CandidateSource identifies which caller-supplied candidate set produced an
// attempt. It does not itself prove DNS provenance.
type CandidateSource string

const (
	CandidateLocal     CandidateSource = "local"
	CandidateReference CandidateSource = "reference"
)

// Config controls only the aggregate deadline. Candidate count, scheme,
// method, path, retries, redirects, and per-attempt limits are fixed policy.
type Config struct {
	Timeout time.Duration
}

// Request supplies two candidate sets for one logical hostname. Callers must
// invoke separate rechecks for IPv4 and IPv6.
type Request struct {
	Hostname            string
	LocalCandidates     []string
	ReferenceCandidates []string
}

// Input records the normalized candidates and the fixed comparison policy.
// The embedded Web Observation inputs may differ only in DialIP.
type Input struct {
	Hostname                string                `json:"hostname"`
	URL                     string                `json:"url"`
	Scheme                  webobservation.Scheme `json:"scheme"`
	Family                  webobservation.Family `json:"family"`
	Port                    uint16                `json:"port"`
	Method                  string                `json:"method"`
	Path                    string                `json:"path"`
	CandidateLimitPerSource int                   `json:"candidate_limit_per_source"`
	RetryLimit              int                   `json:"retry_limit"`
	RedirectLimit           int                   `json:"redirect_limit"`
	LocalCandidates         []string              `json:"local_candidates"`
	ReferenceCandidates     []string              `json:"reference_candidates"`
}

// Attempt labels one complete first-hop probe envelope with its candidate
// source. Attempts remain in actual execution order.
type Attempt struct {
	CandidateSource CandidateSource       `json:"candidate_source"`
	Observation     webobservation.Result `json:"observation"`
}

// Result retains valid partial attempts if the aggregate cannot finish. A
// completed result means the bounded comparison evidence is complete, not
// that either candidate set succeeded or that DNS caused a difference.
type Result struct {
	SchemaVersion              int            `json:"schema_version"`
	Operation                  string         `json:"operation"`
	ObservedAt                 time.Time      `json:"observed_at"`
	DurationMS                 int64          `json:"duration_ms"`
	Platform                   probe.Platform `json:"platform"`
	Input                      Input          `json:"input"`
	Status                     Status         `json:"status"`
	StopReason                 StopReason     `json:"stop_reason,omitempty"`
	Detail                     string         `json:"detail,omitempty"`
	LocalCandidatesOmitted     int            `json:"local_candidates_omitted"`
	ReferenceCandidatesOmitted int            `json:"reference_candidates_omitted"`
	Attempts                   []Attempt      `json:"attempts"`
}

// Observer hides candidate normalization, same-family enforcement, bounded
// scheduling, fresh Web attempts, cancellation, and evidence validation.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}
