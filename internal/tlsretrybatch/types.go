// Package tlsretrybatch performs a bounded Phase 0 batch of hostname-free TLS
// observations. It preserves every underlying probe envelope while owning
// target limits, concurrency, transient-failure retries, jitter, the batch
// deadline, and cancellation. It does not assess assets or persist results.
package tlsretrybatch

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

const (
	// SchemaVersion versions this aggregate independently from its embedded
	// TLS Observation envelopes.
	SchemaVersion = 1
	// Operation identifies this temporary Phase 0 orchestration report.
	Operation = "tls_retry_batch"

	targetLimit        = 4
	requestTargetLimit = 16
	concurrencyLimit   = 2
	attemptLimit       = 3
	retryLimit         = attemptLimit - 1
)

// Status records whether the bounded schedule completed, stopped with partial
// evidence, or was cancelled by the caller.
type Status string

const (
	StatusCompleted Status = "completed"
	StatusStopped   Status = "stopped"
	StatusCancelled Status = "cancelled"
)

// StopReason is a stable orchestration fact, not a TLS or asset assessment.
type StopReason string

const (
	StopInvalidInput         StopReason = "invalid_input"
	StopBatchTimeout         StopReason = "batch_timeout"
	StopCancelled            StopReason = "cancelled"
	StopInvalidProbeEvidence StopReason = "invalid_probe_evidence"
	StopSchedulerFailure     StopReason = "scheduler_failure"
)

// TargetStatus distinguishes a settled retry sequence from one interrupted by
// the batch terminal state or never started before that state.
type TargetStatus string

const (
	TargetCompleted   TargetStatus = "completed"
	TargetInterrupted TargetStatus = "interrupted"
	TargetNotStarted  TargetStatus = "not_started"
)

// Config controls only the aggregate deadline. Target count, concurrency,
// attempts, retry categories, per-attempt timeout, and jitter are fixed policy.
type Config struct {
	Timeout time.Duration
}

// Request supplies explicit public IPs. Targets are normalized and
// deduplicated; only the first bounded set is scheduled.
type Request struct {
	Targets []string
}

// Input records every normalized target and the complete fixed retry policy.
// Targets beyond TargetLimit remain visible but are not contacted.
type Input struct {
	Targets              []string                                `json:"targets"`
	TargetLimit          int                                     `json:"target_limit"`
	ConcurrencyLimit     int                                     `json:"concurrency_limit"`
	AttemptLimit         int                                     `json:"attempt_limit"`
	RetryLimit           int                                     `json:"retry_limit"`
	Port                 uint16                                  `json:"port"`
	SNIMode              tlsobservation.SNIMode                  `json:"sni_mode"`
	IdentityVerification tlsobservation.IdentityVerificationMode `json:"identity_verification"`
	PerAttemptTimeoutMS  int64                                   `json:"per_attempt_timeout_ms"`
	BackoffMinMS         int64                                   `json:"backoff_min_ms"`
	BackoffMaxMS         int64                                   `json:"backoff_max_ms"`
}

// Attempt retains one complete TLS Observation and the jitter delay that
// elapsed immediately before it. The first attempt always has zero delay.
type Attempt struct {
	Number       int                   `json:"number"`
	RetryDelayMS int64                 `json:"retry_delay_ms"`
	Observation  tlsobservation.Result `json:"observation"`
}

// TargetResult preserves one target's retry sequence in execution order.
// Completed means the bounded policy settled, not that TLS succeeded.
type TargetResult struct {
	DialIP   string                `json:"dial_ip"`
	Family   tlsobservation.Family `json:"family"`
	Status   TargetStatus          `json:"status"`
	Attempts []Attempt             `json:"attempts"`
}

// Result retains valid partial evidence on timeout, cancellation, or internal
// contract failure. Only StatusCompleted means every scheduled target settled.
type Result struct {
	SchemaVersion  int            `json:"schema_version"`
	Operation      string         `json:"operation"`
	ObservedAt     time.Time      `json:"observed_at"`
	DurationMS     int64          `json:"duration_ms"`
	Platform       probe.Platform `json:"platform"`
	Input          Input          `json:"input"`
	Status         Status         `json:"status"`
	StopReason     StopReason     `json:"stop_reason,omitempty"`
	Detail         string         `json:"detail,omitempty"`
	TargetsOmitted int            `json:"targets_omitted"`
	Targets        []TargetResult `json:"targets"`
}

// Observer hides normalization, bounded concurrent scheduling, retry policy,
// jitter, deadlines, cancellation, and nested evidence validation.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}
