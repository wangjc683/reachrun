// Package systemresolver observes hostname resolution through the operating
// system's normal resolver path.
package systemresolver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"
	"unicode"

	"github.com/wangjc683/reachrun/internal/probe"
)

// Family identifies an observed IP address family.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Input is the normalized request captured in a system-resolution envelope.
type Input struct {
	Hostname string `json:"hostname"`
}

// Address is one address returned by the system resolver. The original system
// order is preserved because it may affect the path applications try first.
type Address struct {
	IP     string `json:"ip"`
	Family Family `json:"family"`
}

// Evidence contains only facts exposed by system address resolution. DNS TTL,
// response codes, and responding servers require separate DNS observations.
type Evidence struct {
	Addresses []Address `json:"addresses"`
}

// Result is the system-resolution specialization of the Phase 0 envelope.
type Result = probe.Envelope[Input, Evidence]

// Resolver returns a terminal evidence envelope for every attempt. Expected
// lookup failures are represented inside Result rather than as Go errors.
type Resolver interface {
	Resolve(ctx context.Context, hostname string) Result
}

type lookupFunc func(context.Context, string, string) ([]netip.Addr, error)

type nativeResolver struct {
	lookup lookupFunc
	now    func() time.Time
	source probe.Source
}

// New creates the production adapter backed by net.DefaultResolver. The source
// capability is locked when New is called so one run cannot silently change
// evidence semantics halfway through.
func New() Resolver {
	return newNativeResolver(net.DefaultResolver.LookupNetIP, time.Now, currentSource())
}

func newNativeResolver(lookup lookupFunc, now func() time.Time, source probe.Source) Resolver {
	return &nativeResolver{
		lookup: lookup,
		now:    now,
		source: source,
	}
}

func (r *nativeResolver) Resolve(ctx context.Context, hostname string) Result {
	startedAt := r.now()
	hostname, err := normalizeHostname(hostname)
	if err != nil {
		return r.failureResult(startedAt, hostname, probe.FailureInvalidInput, err)
	}

	addresses, err := r.lookup(ctx, "ip", hostname)
	if err != nil {
		outcome, code := classifyFailure(ctx, err)
		return r.result(startedAt, hostname, outcome, nil, &probe.Failure{
			Code:   code,
			Detail: err.Error(),
		})
	}
	if err := ctx.Err(); err != nil {
		outcome, code := classifyFailure(ctx, err)
		return r.result(startedAt, hostname, outcome, nil, &probe.Failure{
			Code:   code,
			Detail: err.Error(),
		})
	}

	evidence, err := normalizeAddresses(addresses)
	if err != nil {
		return r.failureResult(startedAt, hostname, probe.FailureResolutionFailure, err)
	}
	if len(evidence.Addresses) == 0 {
		return r.failureResult(
			startedAt,
			hostname,
			probe.FailureResolutionFailure,
			errors.New("system resolver returned no addresses"),
		)
	}

	return r.result(startedAt, hostname, probe.OutcomeSucceeded, &evidence, nil)
}

func normalizeHostname(value string) (string, error) {
	hostname := strings.TrimSpace(value)
	if hostname == "" {
		return hostname, errors.New("hostname must not be empty")
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return hostname, errors.New("IP literals are not system-resolution hostnames")
	}
	if strings.ContainsAny(hostname, "/\\:@?#[]*") ||
		strings.IndexFunc(hostname, unicode.IsSpace) >= 0 {
		return hostname, errors.New("hostname must not include a scheme, port, path, or whitespace")
	}
	return hostname, nil
}

func (r *nativeResolver) failureResult(
	startedAt time.Time,
	hostname string,
	code probe.FailureCode,
	err error,
) Result {
	outcome := probe.OutcomeFailed
	if code == probe.FailureCancelled {
		outcome = probe.OutcomeCancelled
	}

	failure := &probe.Failure{Code: code}
	if err != nil {
		failure.Detail = err.Error()
	}

	return r.result(startedAt, hostname, outcome, nil, failure)
}

func (r *nativeResolver) result(
	startedAt time.Time,
	hostname string,
	outcome probe.Outcome,
	evidence *Evidence,
	failure *probe.Failure,
) Result {
	finishedAt := r.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}

	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindSystemResolution,
		ObservedAt:    finishedAt.UTC(),
		DurationMS:    duration,
		Platform: probe.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Source:   r.source,
		Input:    Input{Hostname: hostname},
		Outcome:  outcome,
		Evidence: evidence,
		Failure:  failure,
	}
}

func normalizeAddresses(addresses []netip.Addr) (Evidence, error) {
	result := Evidence{Addresses: make([]Address, 0, len(addresses))}
	seen := make(map[netip.Addr]struct{}, len(addresses))

	for _, address := range addresses {
		if !address.IsValid() {
			return Evidence{}, fmt.Errorf("system resolver returned an invalid address")
		}

		address = address.Unmap()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}

		family := FamilyIPv6
		if address.Is4() {
			family = FamilyIPv4
		} else if !address.Is6() {
			return Evidence{}, fmt.Errorf("system resolver returned an unsupported address family")
		}

		result.Addresses = append(result.Addresses, Address{
			IP:     address.String(),
			Family: family,
		})
	}

	return result, nil
}

func classifyFailure(ctx context.Context, err error) (probe.Outcome, probe.FailureCode) {
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return probe.OutcomeCancelled, probe.FailureCancelled
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return probe.OutcomeFailed, probe.FailureTimeout
	}

	var dnsError *net.DNSError
	if errors.As(err, &dnsError) {
		switch {
		case dnsError.IsNotFound:
			return probe.OutcomeFailed, probe.FailureNameUnresolved
		case dnsError.IsTimeout:
			return probe.OutcomeFailed, probe.FailureTimeout
		}
	}

	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return probe.OutcomeFailed, probe.FailureTimeout
	}

	return probe.OutcomeFailed, probe.FailureResolutionFailure
}
