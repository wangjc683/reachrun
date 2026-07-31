// Package probe defines the small, versioned evidence envelope shared by
// Phase 0 network capability probes.
package probe

import (
	"fmt"
	"time"
)

// SchemaVersion is the JSON contract version for the Phase 0 evidence envelope.
const SchemaVersion = 1

// Kind identifies which probe produced an envelope.
type Kind string

const (
	// KindSystemResolution observes the addresses returned by the operating
	// system's normal hostname resolution path.
	KindSystemResolution Kind = "system_resolution"
)

// Capability describes how faithfully a probe source provides the intended
// platform evidence.
type Capability string

const (
	CapabilityNative   Capability = "native"
	CapabilityDegraded Capability = "degraded"
)

// Outcome is the terminal state of one probe attempt.
type Outcome string

const (
	OutcomeSucceeded Outcome = "succeeded"
	OutcomeFailed    Outcome = "failed"
	OutcomeCancelled Outcome = "cancelled"
)

// FailureCode is a stable, machine-readable failure category. Human-readable
// operating-system messages belong in Failure.Detail and must not drive product
// decisions.
type FailureCode string

const (
	FailureInvalidInput      FailureCode = "invalid_input"
	FailureNameUnresolved    FailureCode = "name_unresolved"
	FailureTimeout           FailureCode = "timeout"
	FailureResolutionFailure FailureCode = "resolution_failure"
	FailureCancelled         FailureCode = "cancelled"
)

// Platform identifies the executable's operating-system environment.
type Platform struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

// Source records the backend that supplied the evidence and whether it meets
// the native platform contract.
type Source struct {
	Backend    string     `json:"backend"`
	Capability Capability `json:"capability"`
	Reason     string     `json:"reason,omitempty"`
}

// Failure contains a stable category and an optional diagnostic detail.
type Failure struct {
	Code   FailureCode `json:"code"`
	Detail string      `json:"detail,omitempty"`
}

// Envelope is the versioned JSON boundary shared by Phase 0 probes. Input and
// evidence remain probe-specific while lifecycle and failure semantics stay
// consistent across platforms.
type Envelope[I any, E any] struct {
	SchemaVersion int       `json:"schema_version"`
	Probe         Kind      `json:"probe"`
	ObservedAt    time.Time `json:"observed_at"`
	DurationMS    int64     `json:"duration_ms"`
	Platform      Platform  `json:"platform"`
	Source        Source    `json:"source"`
	Input         I         `json:"input"`
	Outcome       Outcome   `json:"outcome"`
	Evidence      *E        `json:"evidence,omitempty"`
	Failure       *Failure  `json:"failure,omitempty"`
}

// Validate checks the invariants common to every Phase 0 probe envelope.
func (e Envelope[I, E]) Validate() error {
	if e.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if e.Probe == "" {
		return fmt.Errorf("probe must not be empty")
	}
	if e.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at must not be zero")
	}
	if _, offset := e.ObservedAt.Zone(); offset != 0 {
		return fmt.Errorf("observed_at must use UTC")
	}
	if e.DurationMS < 0 {
		return fmt.Errorf("duration_ms must not be negative")
	}
	if e.Platform.OS == "" || e.Platform.Arch == "" {
		return fmt.Errorf("platform os and arch must not be empty")
	}
	if e.Source.Backend == "" {
		return fmt.Errorf("source backend must not be empty")
	}
	if !e.Source.Capability.valid() {
		return fmt.Errorf("unsupported source capability %q", e.Source.Capability)
	}
	if e.Source.Capability == CapabilityNative && e.Source.Reason != "" {
		return fmt.Errorf("native source must not include a degradation reason")
	}
	if e.Source.Capability == CapabilityDegraded && e.Source.Reason == "" {
		return fmt.Errorf("degraded source must include a reason")
	}

	switch e.Outcome {
	case OutcomeSucceeded:
		if e.Evidence == nil {
			return fmt.Errorf("succeeded outcome must include evidence")
		}
		if e.Failure != nil {
			return fmt.Errorf("succeeded outcome must not include failure")
		}
	case OutcomeFailed:
		if e.Evidence != nil {
			return fmt.Errorf("failed outcome must not include evidence")
		}
		if e.Failure == nil {
			return fmt.Errorf("failed outcome must include failure")
		}
		if !e.Failure.Code.valid() || e.Failure.Code == FailureCancelled {
			return fmt.Errorf("failed outcome has unsupported failure code %q", e.Failure.Code)
		}
	case OutcomeCancelled:
		if e.Evidence != nil {
			return fmt.Errorf("cancelled outcome must not include evidence")
		}
		if e.Failure == nil || e.Failure.Code != FailureCancelled {
			return fmt.Errorf("cancelled outcome must include cancelled failure")
		}
	default:
		return fmt.Errorf("unsupported outcome %q", e.Outcome)
	}

	return nil
}

func (c Capability) valid() bool {
	return c == CapabilityNative || c == CapabilityDegraded
}

func (c FailureCode) valid() bool {
	switch c {
	case FailureInvalidInput,
		FailureNameUnresolved,
		FailureTimeout,
		FailureResolutionFailure,
		FailureCancelled:
		return true
	default:
		return false
	}
}
