package systemresolver

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

var testSource = probe.Source{
	Backend:    "test-system-resolver",
	Capability: probe.CapabilityNative,
}

func TestResolveReturnsOrderedCanonicalAddresses(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.August, 1, 8, 0, 0, 0, time.FixedZone("test", 8*60*60))
	finishedAt := startedAt.Add(15 * time.Millisecond)
	lookup := func(_ context.Context, network, hostname string) ([]netip.Addr, error) {
		if network != "ip" {
			t.Fatalf("network = %q, want ip", network)
		}
		if hostname != "example.com" {
			t.Fatalf("hostname = %q, want example.com", hostname)
		}
		return []netip.Addr{
			netip.MustParseAddr("::ffff:192.0.2.10"),
			netip.MustParseAddr("192.0.2.10"),
			netip.MustParseAddr("2001:db8::10"),
		}, nil
	}

	resolver := newNativeResolver(lookup, sequenceClock(startedAt, finishedAt), testSource)
	result := resolver.Resolve(context.Background(), "  example.com  ")

	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.ObservedAt != finishedAt.UTC() {
		t.Fatalf("observed_at = %v, want %v", result.ObservedAt, finishedAt.UTC())
	}
	if result.DurationMS != 15 {
		t.Fatalf("duration_ms = %d, want 15", result.DurationMS)
	}
	if result.Platform.OS != runtime.GOOS || result.Platform.Arch != runtime.GOARCH {
		t.Fatalf("platform = %#v, want %s/%s", result.Platform, runtime.GOOS, runtime.GOARCH)
	}
	if result.Source != testSource {
		t.Fatalf("source = %#v, want %#v", result.Source, testSource)
	}

	want := []Address{
		{IP: "192.0.2.10", Family: FamilyIPv4},
		{IP: "2001:db8::10", Family: FamilyIPv6},
	}
	if !reflect.DeepEqual(result.Evidence.Addresses, want) {
		t.Fatalf("addresses = %#v, want %#v", result.Evidence.Addresses, want)
	}
}

func TestResolveNormalizesFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ctx         func() context.Context
		lookupError error
		outcome     probe.Outcome
		code        probe.FailureCode
	}{
		"not found": {
			ctx:         context.Background,
			lookupError: &net.DNSError{Err: "no such host", Name: "missing.example", IsNotFound: true},
			outcome:     probe.OutcomeFailed,
			code:        probe.FailureNameUnresolved,
		},
		"dns timeout": {
			ctx:         context.Background,
			lookupError: &net.DNSError{Err: "timeout", Name: "example.com", IsTimeout: true},
			outcome:     probe.OutcomeFailed,
			code:        probe.FailureTimeout,
		},
		"temporary": {
			ctx:         context.Background,
			lookupError: &net.DNSError{Err: "temporary", Name: "example.com", IsTemporary: true},
			outcome:     probe.OutcomeFailed,
			code:        probe.FailureResolutionFailure,
		},
		"deadline": {
			ctx:         context.Background,
			lookupError: context.DeadlineExceeded,
			outcome:     probe.OutcomeFailed,
			code:        probe.FailureTimeout,
		},
		"cancelled": {
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			lookupError: errors.New("lookup stopped"),
			outcome:     probe.OutcomeCancelled,
			code:        probe.FailureCancelled,
		},
		"unavailable": {
			ctx:         context.Background,
			lookupError: errors.New("resolver unavailable"),
			outcome:     probe.OutcomeFailed,
			code:        probe.FailureResolutionFailure,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lookup := func(context.Context, string, string) ([]netip.Addr, error) {
				return nil, test.lookupError
			}
			resolver := newNativeResolver(lookup, sequenceClock(time.Now(), time.Now()), testSource)
			result := resolver.Resolve(test.ctx(), "example.com")

			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Outcome != test.outcome {
				t.Fatalf("outcome = %q, want %q", result.Outcome, test.outcome)
			}
			if result.Failure.Code != test.code {
				t.Fatalf("failure code = %q, want %q", result.Failure.Code, test.code)
			}
			if result.Failure.Detail == "" {
				t.Fatal("failure detail is empty, want raw diagnostic detail")
			}
		})
	}
}

func TestResolveRejectsInvalidInputWithoutLookup(t *testing.T) {
	t.Parallel()

	for _, input := range []string{" \t ", "192.0.2.1", "https://example.com", "example.com:443"} {
		input := input
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			called := false
			lookup := func(context.Context, string, string) ([]netip.Addr, error) {
				called = true
				return nil, nil
			}
			resolver := newNativeResolver(lookup, sequenceClock(time.Now(), time.Now()), testSource)
			result := resolver.Resolve(context.Background(), input)

			if called {
				t.Fatalf("lookup called for invalid input %q", input)
			}
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Failure.Code != probe.FailureInvalidInput {
				t.Fatalf("failure code = %q, want %q", result.Failure.Code, probe.FailureInvalidInput)
			}
			if result.Failure.Detail == "" {
				t.Fatal("invalid input has no diagnostic detail")
			}
		})
	}
}

func TestResolveDiscardsLateSuccessAfterCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		cancel()
		return []netip.Addr{netip.MustParseAddr("192.0.2.10")}, nil
	}
	resolver := newNativeResolver(lookup, sequenceClock(time.Now(), time.Now()), testSource)
	result := resolver.Resolve(ctx, "example.com")

	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Outcome != probe.OutcomeCancelled {
		t.Fatalf("outcome = %q, want %q", result.Outcome, probe.OutcomeCancelled)
	}
	if result.Failure.Code != probe.FailureCancelled {
		t.Fatalf("failure code = %q, want %q", result.Failure.Code, probe.FailureCancelled)
	}
	if result.Evidence != nil {
		t.Fatalf("evidence = %#v, want nil after cancellation", result.Evidence)
	}
}

func TestResolveHandlesNoDataAndInvalidNativeAddress(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		addresses []netip.Addr
		code      probe.FailureCode
	}{
		"no data": {
			addresses: nil,
			code:      probe.FailureResolutionFailure,
		},
		"invalid native address": {
			addresses: []netip.Addr{{}},
			code:      probe.FailureResolutionFailure,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lookup := func(context.Context, string, string) ([]netip.Addr, error) {
				return test.addresses, nil
			}
			resolver := newNativeResolver(lookup, sequenceClock(time.Now(), time.Now()), testSource)
			result := resolver.Resolve(context.Background(), "example.com")

			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Failure.Code != test.code {
				t.Fatalf("failure code = %q, want %q", result.Failure.Code, test.code)
			}
		})
	}
}

func TestValidateRejectsInvalidSystemResolutionEvidence(t *testing.T) {
	t.Parallel()

	tests := map[string][]Address{
		"invalid ip": {
			{IP: "not-an-ip", Family: FamilyIPv4},
		},
		"mapped ipv4 is not canonical": {
			{IP: "::ffff:192.0.2.1", Family: FamilyIPv4},
		},
		"wrong family": {
			{IP: "192.0.2.1", Family: FamilyIPv6},
		},
		"duplicate": {
			{IP: "192.0.2.1", Family: FamilyIPv4},
			{IP: "192.0.2.1", Family: FamilyIPv4},
		},
		"ip literal input": {
			{IP: "192.0.2.1", Family: FamilyIPv4},
		},
	}

	for name, addresses := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validSystemResolutionResult(addresses)
			if name == "ip literal input" {
				result.Input.Hostname = "192.0.2.1"
			}
			if err := Validate(result); err == nil {
				t.Fatal("Validate() error = nil, want invalid evidence error")
			}
		})
	}
}

func TestValidateRejectsInputOutcomeMismatch(t *testing.T) {
	t.Parallel()

	tests := map[string]Result{
		"valid hostname marked invalid": func() Result {
			result := validSystemResolutionResult([]Address{{IP: "192.0.2.1", Family: FamilyIPv4}})
			result.Outcome = probe.OutcomeFailed
			result.Evidence = nil
			result.Failure = &probe.Failure{Code: probe.FailureInvalidInput}
			return result
		}(),
		"unnormalized hostname": func() Result {
			result := validSystemResolutionResult([]Address{{IP: "192.0.2.1", Family: FamilyIPv4}})
			result.Input.Hostname = " example.com "
			return result
		}(),
	}

	for name, result := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(result); err == nil {
				t.Fatal("Validate() error = nil, want input invariant error")
			}
		})
	}
}

func TestValidateRejectsFailureCodeOutsideSystemResolverContract(t *testing.T) {
	t.Parallel()

	result := validSystemResolutionResult([]Address{{IP: "192.0.2.1", Family: FamilyIPv4}})
	result.Outcome = probe.OutcomeFailed
	result.Evidence = nil
	result.Failure = &probe.Failure{Code: probe.FailureCode("other_probe_failure")}

	if err := Validate(result); err == nil {
		t.Fatal("Validate() error = nil, want unsupported failure code error")
	}
}

func validSystemResolutionResult(addresses []Address) Result {
	evidence := Evidence{Addresses: addresses}
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindSystemResolution,
		ObservedAt:    time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC),
		Platform:      probe.Platform{OS: "testos", Arch: "testarch"},
		Source:        testSource,
		Input:         Input{Hostname: "example.com"},
		Outcome:       probe.OutcomeSucceeded,
		Evidence:      &evidence,
	}
}

func sequenceClock(times ...time.Time) func() time.Time {
	index := 0
	return func() time.Time {
		if index >= len(times) {
			panic("test clock exhausted")
		}
		value := times[index]
		index++
		return value
	}
}
