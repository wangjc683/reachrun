package tlsretrybatch

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

var (
	testPlatform = probe.Platform{OS: "testos", Arch: "testarch"}
	testSource   = probe.Source{Backend: "scripted-tls", Capability: probe.CapabilityNative}
)

type tlsObserverFunc func(context.Context, tlsobservation.Request) tlsobservation.Result

func (f tlsObserverFunc) Observe(
	ctx context.Context,
	request tlsobservation.Request,
) tlsobservation.Result {
	return f(ctx, request)
}

type keyedTLSObserver struct {
	mu      sync.Mutex
	results map[string][]tlsobservation.Result
	calls   []tlsobservation.Request
}

func (o *keyedTLSObserver) Observe(
	_ context.Context,
	request tlsobservation.Request,
) tlsobservation.Result {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls = append(o.calls, request)
	queue := o.results[request.DialIP]
	if len(queue) == 0 {
		panic("unexpected TLS observation for " + request.DialIP)
	}
	result := queue[0]
	o.results[request.DialIP] = queue[1:]
	return result
}

func (o *keyedTLSObserver) callCount(target string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	count := 0
	for _, call := range o.calls {
		if call.DialIP == target {
			count++
		}
	}
	return count
}

func testTLSCompleted(target string) tlsobservation.Result {
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	evidence := tlsobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(target), tlsobservation.Port).String(),
		TCPConnectMS:   1,
		TLS: tlsobservation.TLS{
			Status:           tlsobservation.TLSCompleted,
			HandshakeMS:      1,
			Version:          "TLS1.3",
			CipherSuite:      "TLS_AES_128_GCM_SHA256",
			PeerCertificates: 1,
			Leaf: &tlsobservation.LeafCertificate{
				SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				NotBefore: notBefore,
				NotAfter:  notBefore.Add(24 * time.Hour),
			},
		},
	}
	return testTLSResult(target, probe.OutcomeSucceeded, &evidence, nil)
}

func testTLSUnconfirmed(
	target string,
	reason tlsobservation.UnconfirmedReason,
) tlsobservation.Result {
	evidence := tlsobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(target), tlsobservation.Port).String(),
		TCPConnectMS:   1,
		TLS: tlsobservation.TLS{
			Status:            tlsobservation.TLSUnconfirmed,
			UnconfirmedReason: reason,
			HandshakeMS:       1,
		},
	}
	return testTLSResult(target, probe.OutcomeSucceeded, &evidence, nil)
}

func testTLSFailure(
	target string,
	outcome probe.Outcome,
	code probe.FailureCode,
) tlsobservation.Result {
	return testTLSResult(
		target,
		outcome,
		nil,
		&probe.Failure{Code: code, Detail: "scripted failure"},
	)
}

func testTLSResult(
	target string,
	outcome probe.Outcome,
	evidence *tlsobservation.Evidence,
	failure *probe.Failure,
) tlsobservation.Result {
	return tlsobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         tlsobservation.ProbeKind,
		ObservedAt:    time.Date(2026, time.August, 3, 15, 0, 0, 0, time.UTC),
		DurationMS:    2,
		Platform:      testPlatform,
		Source:        testSource,
		Input:         expectedTLSInput(target),
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func testObserver(
	t *testing.T,
	tls tlsobservation.Observer,
	options ...func(*dependencies),
) *observer {
	t.Helper()
	startedAt := time.Date(2026, time.August, 3, 15, 0, 0, 0, time.UTC)
	deps := dependencies{
		now:        sequenceClock(startedAt, startedAt.Add(10*time.Millisecond)),
		platform:   testPlatform,
		tls:        tls,
		retryDelay: func() time.Duration { return 125 * time.Millisecond },
		wait:       func(context.Context, time.Duration) error { return nil },
	}
	for _, option := range options {
		option(&deps)
	}
	observer, err := newObserver(Config{}, deps)
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	return observer
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
