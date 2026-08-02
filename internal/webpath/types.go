// Package webpath observes the public website path for one logical hostname.
// It owns system resolution, bounded public-candidate selection, HTTPS-first
// fallback, and safe redirect orchestration while preserving every underlying
// System Resolution and Web Observation as distinct probe evidence.
package webpath

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

const (
	// SchemaVersion versions the Phase 0 Web-path aggregate report. It is kept
	// separate from the individual probe envelope contract embedded below.
	SchemaVersion = 1
	// Operation identifies this aggregate report on the temporary CLI.
	Operation = "web_path"

	redirectLimit           = 3
	candidateLimitPerFamily = 2
)

// Status describes whether the controlled path reached a terminal HTTP
// response, stopped with bounded evidence, or was cancelled by the caller.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusStopped   Status = "stopped"
	StatusCancelled Status = "cancelled"
)

// StopReason is a stable fact about why orchestration ended. It is not an
// asset-health or causal assessment.
type StopReason string

const (
	StopFinalResponse               StopReason = "final_response"
	StopInvalidInput                StopReason = "invalid_input"
	StopResolutionFailed            StopReason = "resolution_failed"
	StopNoPublicCandidates          StopReason = "no_public_candidates"
	StopAllCandidatesFailed         StopReason = "all_candidates_failed"
	StopRedirectLocationUnavailable StopReason = "redirect_location_unavailable"
	StopRedirectTargetInvalid       StopReason = "redirect_target_invalid"
	StopRedirectTargetUnsafe        StopReason = "redirect_target_unsafe"
	StopRedirectLoop                StopReason = "redirect_loop"
	StopRedirectLimit               StopReason = "redirect_limit"
	StopPathTimeout                 StopReason = "path_timeout"
	StopCancelled                   StopReason = "cancelled"
	StopInvalidProbeEvidence        StopReason = "invalid_probe_evidence"
)

// Config controls the total duration of one public-path observation. Redirect
// count, candidate count, methods, ports, and per-attempt limits are fixed by
// the module contract rather than exposed as caller choices.
type Config struct {
	Timeout time.Duration
}

// Request asks for the public website path of one normalized DNS hostname.
type Request struct {
	Hostname string
}

// Input records the normalized request and fixed orchestration policy.
type Input struct {
	Hostname                string `json:"hostname"`
	InitialURL              string `json:"initial_url"`
	Method                  string `json:"method"`
	RedirectLimit           int    `json:"redirect_limit"`
	CandidateLimitPerFamily int    `json:"candidate_limit_per_family"`
}

// Hop keeps resolution and direct Web attempts distinct while grouping the
// evidence belonging to one concrete URL in the observed redirect path.
type Hop struct {
	URL        string                  `json:"url"`
	Resolution systemresolver.Result   `json:"resolution"`
	Attempts   []webobservation.Result `json:"attempts"`
}

// Result is one terminal aggregate report. Unlike an individual probe
// envelope, stopped paths intentionally retain all valid partial evidence.
type Result struct {
	SchemaVersion     int            `json:"schema_version"`
	Operation         string         `json:"operation"`
	ObservedAt        time.Time      `json:"observed_at"`
	DurationMS        int64          `json:"duration_ms"`
	Platform          probe.Platform `json:"platform"`
	Input             Input          `json:"input"`
	Status            Status         `json:"status"`
	StopReason        StopReason     `json:"stop_reason"`
	Detail            string         `json:"detail,omitempty"`
	RedirectsFollowed int            `json:"redirects_followed"`
	HTTPFallbackUsed  bool           `json:"http_fallback_used"`
	Hops              []Hop          `json:"hops"`
}

// Observer hides resolution, candidate scheduling, redirects, fallback, and
// resource limits behind one hostname-only interface.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}
