// Package resolverinventory observes the operating system's configured DNS
// resolver candidates. It does not identify which resolver answered any
// particular system-resolution attempt.
package resolverinventory

import (
	"context"
	"errors"
	"runtime"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// FailureUnavailable means the platform adapter could not obtain a usable
	// resolver configuration snapshot.
	FailureUnavailable probe.FailureCode = "resolver_inventory_unavailable"
	// FailureInvalid means configuration was obtained but could not form valid
	// typed resolver-inventory evidence.
	FailureInvalid probe.FailureCode = "resolver_inventory_invalid"
)

// Scope identifies whether a resolver group came from the general resolver
// configuration or a platform configuration explicitly scoped to an
// interface. It does not describe actual query routing.
type Scope string

const (
	ScopeGlobal Scope = "global"
	ScopeScoped Scope = "scoped"
)

// Input is empty because resolver inventory observes the current environment,
// not a user-supplied hostname or address.
type Input struct{}

// Server is one configured resolver endpoint. Address is a canonical IP
// literal without an IPv6 zone, Zone preserves that scope separately, and
// Port defaults to 53 when the platform source omits it.
type Server struct {
	Address string `json:"address"`
	Port    uint16 `json:"port"`
	Zone    string `json:"zone,omitempty"`
}

// Group preserves the association between resolver endpoints, interface
// scope, search domains, and match domains reported by one configuration
// block. Slice order is source observation order, not proven query priority.
type Group struct {
	Scope          Scope    `json:"scope"`
	Servers        []Server `json:"servers"`
	Interface      string   `json:"interface,omitempty"`
	InterfaceIndex uint32   `json:"interface_index,omitempty"`
	SearchDomains  []string `json:"search_domains,omitempty"`
	MatchDomains   []string `json:"match_domains,omitempty"`
}

// Evidence is a best-effort snapshot of configured resolver groups.
type Evidence struct {
	Groups []Group `json:"groups"`
}

// Result is the resolver-inventory specialization of the Phase 0 envelope.
type Result = probe.Envelope[Input, Evidence]

// Observer returns one terminal resolver-inventory envelope per observation.
// Expected platform and configuration failures are represented inside Result.
type Observer interface {
	Observe(ctx context.Context) Result
}

type collected struct {
	evidence Evidence
	source   probe.Source
}

type collectError struct {
	code   probe.FailureCode
	source probe.Source
	err    error
}

func (e *collectError) Error() string {
	return e.err.Error()
}

func (e *collectError) Unwrap() error {
	return e.err
}

type collectFunc func(context.Context) (collected, error)

type nativeObserver struct {
	collect             collectFunc
	now                 func() time.Time
	beforeSuccessCommit func()
}

// New creates the production adapter for the current operating system.
func New() Observer {
	return newObserver(collectPlatform, time.Now)
}

func newObserver(collect collectFunc, now func() time.Time) Observer {
	return &nativeObserver{collect: collect, now: now}
}

func unavailablePlatformSource() probe.Source {
	return probe.Source{
		Backend:    "resolver-inventory-unavailable",
		Capability: probe.CapabilityDegraded,
		Reason:     "platform_source_unavailable",
	}
}

func (o *nativeObserver) Observe(ctx context.Context) Result {
	startedAt := o.now()
	observation, err := o.collect(ctx)
	if err == nil {
		if contextErr := ctx.Err(); contextErr != nil {
			err = contextErr
		} else {
			normalized, normalizeErr := normalizeEvidence(observation.evidence)
			if normalizeErr != nil {
				err = &collectError{
					code:   FailureInvalid,
					source: observation.source,
					err:    normalizeErr,
				}
			} else {
				if o.beforeSuccessCommit != nil {
					o.beforeSuccessCommit()
				}
				if contextErr := ctx.Err(); contextErr != nil {
					err = contextErr
				} else {
					return o.result(startedAt, observation.source, probe.OutcomeSucceeded, &normalized, nil)
				}
			}
		}
	}

	source := observation.source
	code := FailureUnavailable
	var platformError *collectError
	if errors.As(err, &platformError) {
		code = platformError.code
		source = platformError.source
	}
	if source.Backend == "" {
		source = unavailablePlatformSource()
	}

	outcome := probe.OutcomeFailed
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		outcome = probe.OutcomeCancelled
		code = probe.FailureCancelled
	} else if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		code = probe.FailureTimeout
	}

	failure := &probe.Failure{Code: code}
	if err != nil {
		failure.Detail = err.Error()
	}
	return o.result(startedAt, source, outcome, nil, failure)
}

func (o *nativeObserver) result(
	startedAt time.Time,
	source probe.Source,
	outcome probe.Outcome,
	evidence *Evidence,
	failure *probe.Failure,
) Result {
	finishedAt := o.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}

	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindResolverInventory,
		ObservedAt:    finishedAt.UTC(),
		DurationMS:    duration,
		Platform: probe.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Source:   source,
		Input:    Input{},
		Outcome:  outcome,
		Evidence: evidence,
		Failure:  failure,
	}
}
