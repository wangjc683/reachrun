package familycondition

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestNewNormalizesConfig(t *testing.T) {
	t.Parallel()

	observer, err := newObserver(Config{}, dependencies{})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	if observer.timeout != defaultTimeout {
		t.Fatalf("timeout = %s, want %s", observer.timeout, defaultTimeout)
	}
	for _, timeout := range []time.Duration{-time.Nanosecond, maximumTimeout + time.Nanosecond} {
		if _, err := newObserver(Config{Timeout: timeout}, dependencies{}); err == nil {
			t.Fatalf("newObserver(%s) error = nil, want validation error", timeout)
		}
	}
}

func TestObserveReturnsOrderedRouteSelectionWithoutWriting(t *testing.T) {
	t.Parallel()

	startedAt := time.Date(2026, time.August, 3, 10, 0, 0, 0, time.FixedZone("test", -4*60*60))
	finishedAt := startedAt.Add(7 * time.Millisecond)
	connections := []*fakeConn{routeTestConn(FamilyIPv4), routeTestConn(FamilyIPv6)}
	type call struct{ network, endpoint string }
	var calls []call
	dial := func(_ context.Context, network, endpoint string) (net.Conn, error) {
		calls = append(calls, call{network: network, endpoint: endpoint})
		return connections[len(calls)-1], nil
	}
	observer, err := newObserver(Config{}, dependencies{
		now:         familySequenceClock(startedAt, finishedAt),
		dialContext: dial,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}

	result := observer.Observe(context.Background())
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Platform.OS != runtime.GOOS || result.Platform.Arch != runtime.GOARCH {
		t.Fatalf("platform = %#v, want %s/%s", result.Platform, runtime.GOOS, runtime.GOARCH)
	}
	if result.ObservedAt != finishedAt.UTC() || result.DurationMS != 7 {
		t.Fatalf("timing = %v/%d, want %v/7", result.ObservedAt, result.DurationMS, finishedAt.UTC())
	}
	wantCalls := []call{{"udp4", IPv4RouteTarget}, {"udp6", IPv6RouteTarget}}
	if fmt.Sprint(calls) != fmt.Sprint(wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	conditions := result.Evidence.Conditions
	if conditions[0].LocalAddress != "192.0.2.10" || conditions[0].LocalZone != "" {
		t.Fatalf("IPv4 source = %#v, want 192.0.2.10 without zone", conditions[0])
	}
	if conditions[1].LocalAddress != "2001:db8::10" || conditions[1].LocalZone != "test0" {
		t.Fatalf("IPv6 source = %#v, want canonical address and separate zone", conditions[1])
	}
	for index, connection := range connections {
		if connection.writeCalls != 0 || connection.closeCalls != 1 {
			t.Fatalf("connection %d writes/closes = %d/%d, want 0/1", index, connection.writeCalls, connection.closeCalls)
		}
	}
}

func TestObserveRecordsExplicitIPv6NoRouteAsEvidence(t *testing.T) {
	t.Parallel()

	v4 := routeTestConn(FamilyIPv4)
	dials := 0
	dial := func(context.Context, string, string) (net.Conn, error) {
		dials++
		if dials == 1 {
			return v4, nil
		}
		return nil, &net.OpError{Op: "dial", Net: "udp6", Err: syscall.ENETUNREACH}
	}
	now := time.Now()
	observer, err := newObserver(Config{}, dependencies{
		now:         familySequenceClock(now, now),
		dialContext: dial,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}

	result := observer.Observe(context.Background())
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Outcome != probe.OutcomeSucceeded || result.Failure != nil {
		t.Fatalf("terminal = %#v, want succeeded evidence", result)
	}
	v6 := result.Evidence.Conditions[1]
	if v6.Status != StatusUnavailable || v6.Reason != ReasonNoRoute || v6.LocalAddress != "" {
		t.Fatalf("IPv6 condition = %#v, want unavailable/no_route", v6)
	}
}

func TestObserveFailsOnUnclassifiedRouteError(t *testing.T) {
	t.Parallel()

	now := time.Now()
	observer, err := newObserver(Config{}, dependencies{
		now: familySequenceClock(now, now),
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("permission denied by test policy")
		},
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	result := observer.Observe(context.Background())
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Outcome != probe.OutcomeFailed || result.Failure.Code != FailureRouteCheck {
		t.Fatalf("terminal = %#v, want failed/%s", result, FailureRouteCheck)
	}
	if result.Failure.Detail != "permission denied by test policy" {
		t.Fatalf("failure detail = %q", result.Failure.Detail)
	}
}

func TestObserveClassifiesContextTerminalStates(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		ctx     func() context.Context
		dialErr error
		outcome probe.Outcome
		code    probe.FailureCode
	}{
		"pre-cancelled": {
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			outcome: probe.OutcomeCancelled,
			code:    probe.FailureCancelled,
		},
		"pre-expired": {
			ctx: func() context.Context {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				t.Cleanup(cancel)
				return ctx
			},
			outcome: probe.OutcomeFailed,
			code:    probe.FailureTimeout,
		},
		"network timeout": {
			ctx:     context.Background,
			dialErr: timeoutError{},
			outcome: probe.OutcomeFailed,
			code:    probe.FailureTimeout,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := time.Now()
			dialCalls := 0
			observer, err := newObserver(Config{}, dependencies{
				now: familySequenceClock(now, now),
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					dialCalls++
					return nil, test.dialErr
				},
			})
			if err != nil {
				t.Fatalf("newObserver() error = %v", err)
			}
			result := observer.Observe(test.ctx())
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Outcome != test.outcome || result.Failure.Code != test.code {
				t.Fatalf("terminal = %s/%s, want %s/%s", result.Outcome, result.Failure.Code, test.outcome, test.code)
			}
			if name != "network timeout" && dialCalls != 0 {
				t.Fatalf("dial calls = %d, want 0", dialCalls)
			}
		})
	}
}

func TestObserveCancellationWinsAtSuccessCommit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	connections := []*fakeConn{routeTestConn(FamilyIPv4), routeTestConn(FamilyIPv6)}
	dials := 0
	now := time.Now()
	observer, err := newObserver(Config{}, dependencies{
		now: familySequenceClock(now, now),
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			connection := connections[dials]
			dials++
			return connection, nil
		},
		beforeSuccessCommit: cancel,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	result := observer.Observe(ctx)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Outcome != probe.OutcomeCancelled || result.Evidence != nil {
		t.Fatalf("result = %#v, want cancelled without evidence", result)
	}
}

func TestObserveDeadlineWinsAtSuccessCommit(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	connections := []*fakeConn{routeTestConn(FamilyIPv4), routeTestConn(FamilyIPv6)}
	dials := 0
	now := time.Now()
	observer, err := newObserver(Config{}, dependencies{
		now: familySequenceClock(now, now),
		dialContext: func(context.Context, string, string) (net.Conn, error) {
			connection := connections[dials]
			dials++
			return connection, nil
		},
		beforeSuccessCommit: func() { <-ctx.Done() },
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	result := observer.Observe(ctx)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Outcome != probe.OutcomeFailed || result.Failure.Code != probe.FailureTimeout || result.Evidence != nil {
		t.Fatalf("result = %#v, want failed/timeout without evidence", result)
	}
}

func TestObserveRejectsDialerEndpointInvariantViolations(t *testing.T) {
	t.Parallel()

	tests := map[string]*fakeConn{
		"wrong remote": {
			local:  &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 49152},
			remote: &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53},
		},
		"unspecified local": {
			local:  &net.UDPAddr{IP: net.IPv4zero, Port: 49152},
			remote: &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53},
		},
		"wrong local family": {
			local:  &net.UDPAddr{IP: net.ParseIP("2001:db8::10"), Port: 49152},
			remote: &net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 53},
		},
	}

	for name, connection := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			now := time.Now()
			observer, err := newObserver(Config{}, dependencies{
				now: familySequenceClock(now, now),
				dialContext: func(context.Context, string, string) (net.Conn, error) {
					return connection, nil
				},
			})
			if err != nil {
				t.Fatalf("newObserver() error = %v", err)
			}
			result := observer.Observe(context.Background())
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Outcome != probe.OutcomeFailed || result.Failure.Code != FailureRouteCheck {
				t.Fatalf("terminal = %#v, want failed/%s", result, FailureRouteCheck)
			}
		})
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "test timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestUnavailableClassificationsAreStable(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err    error
		reason Reason
	}{
		"network unreachable": {syscall.ENETUNREACH, ReasonNoRoute},
		"host unreachable":    {syscall.EHOSTUNREACH, ReasonNoRoute},
		"family unsupported":  {syscall.EAFNOSUPPORT, ReasonAddressFamilyUnsupported},
		"address unavailable": {syscall.EADDRNOTAVAIL, ReasonSourceAddressUnavailable},
		"network down":        {syscall.ENETDOWN, ReasonNetworkDown},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			reason, ok := classifyUnavailable(&net.OpError{Op: "dial", Err: test.err})
			if !ok || reason != test.reason {
				t.Fatalf("classifyUnavailable() = %q/%t, want %q/true", reason, ok, test.reason)
			}
		})
	}
}
