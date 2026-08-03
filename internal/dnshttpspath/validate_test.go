package dnshttpspath

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
)

func TestValidateRejectsInconsistentPathEvidence(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"wrong schema": func(result *Result) {
			result.SchemaVersion++
		},
		"completed with stop reason": func(result *Result) {
			result.StopReason = StopAliasLoop
		},
		"wrong alias count": func(result *Result) {
			result.AliasesFollowed = 1
		},
		"first query changed": func(result *Result) {
			result.HTTPSObservations[0].Input.Hostname = "other.example"
		},
		"address resolver changed": func(result *Result) {
			result.AddressTargets[0].Observations[0].Input.Resolver.ID = "other"
		},
		"address endpoint changed": func(result *Result) {
			result.AddressTargets[0].Observations[0].Input.Resolver.Endpoint = "192.0.2.54:53"
			result.AddressTargets[0].Observations[0].Evidence.RemoteEndpoint = "192.0.2.54:53"
		},
		"address target changed": func(result *Result) {
			result.AddressTargets[0].Hostname = "other.example"
		},
		"missing AAAA observation": func(result *Result) {
			result.AddressTargets[0].Observations = result.AddressTargets[0].Observations[:1]
		},
		"binding decision changed": func(result *Result) {
			result.ServiceBindings[0].Usable = false
		},
		"nil collection": func(result *Result) {
			result.ServiceBindings = nil
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := observedServicePath(t)
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatal("Validate() error = nil, want inconsistent path rejection")
			}
		})
	}
}

func TestNewValidatesPathAndDNSConfiguration(t *testing.T) {
	t.Parallel()

	validDNS := dnsobservation.Config{Resolvers: []dnsobservation.ResolverEndpoint{{
		ID: "resolver", WireIP: netip.MustParseAddr("192.0.2.53"),
	}}}
	if _, err := New(Config{DNS: validDNS, Timeout: time.Second}); err != nil {
		t.Fatalf("New() valid config error = %v", err)
	}
	if _, err := New(Config{DNS: validDNS, Timeout: maximumTimeout + time.Millisecond}); err == nil {
		t.Fatal("New() accepted timeout above maximum")
	}
	if _, err := New(Config{Timeout: time.Second}); err == nil {
		t.Fatal("New() accepted missing DNS resolver endpoints")
	}
	if _, err := newObserver(Config{Timeout: time.Second}, dependencies{platform: testPlatform}); err == nil {
		t.Fatal("newObserver() accepted nil DNS dependency")
	}
}

func observedServicePath(t *testing.T) Result {
	t.Helper()
	observer, _ := newScriptedObserver(t,
		httpsService("www.example.com", 1, "svc.example.net", nil),
		addressAnswer("svc.example.net", dnsobservation.QueryTypeA, "203.0.113.10"),
		dnsNoData("svc.example.net", dnsobservation.QueryTypeAAAA),
	)
	result := observer.Observe(context.Background(), testRequest("www.example.com"))
	if err := Validate(result); err != nil {
		t.Fatalf("fixture Validate() error = %v", err)
	}
	return result
}
