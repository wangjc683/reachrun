package webpath

import (
	"context"
	"testing"

	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver/systemresolvertest"
	"github.com/wangjc683/reachrun/internal/webobservation"
	"github.com/wangjc683/reachrun/internal/webobservation/webobservationtest"
)

func TestValidateAcceptsInvalidInputWithoutProbeEvidence(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New()
	web := webobservationtest.New()
	observer := mustObserver(t, resolver, web)
	result := observer.Observe(context.Background(), Request{Hostname: "bad/name"})
	assertValidResult(t, result)
	if result.Status != StatusStopped || result.StopReason != StopInvalidInput || len(result.Hops) != 0 {
		t.Fatalf("result = %#v, want invalid input with no probes", result)
	}
	if len(resolver.Calls()) != 0 || len(web.Calls()) != 0 {
		t.Fatal("invalid input reached probe dependencies")
	}
}

func TestValidateRejectsBrokenWebPathContract(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"schema":              func(result *Result) { result.SchemaVersion++ },
		"operation":           func(result *Result) { result.Operation = "other" },
		"input policy":        func(result *Result) { result.Input.RedirectLimit++ },
		"terminal pair":       func(result *Result) { result.Status = StatusStopped },
		"completed detail":    func(result *Result) { result.Detail = "unexpected" },
		"first URL":           func(result *Result) { result.Hops[0].URL = "https://other.example/" },
		"resolution hostname": func(result *Result) { result.Hops[0].Resolution.Input.Hostname = "other.example" },
		"resolution platform": func(result *Result) { result.Hops[0].Resolution.Platform.OS = "other" },
		"attempt platform":    func(result *Result) { result.Hops[0].Attempts[0].Platform.OS = "other" },
		"attempt path":        func(result *Result) { result.Hops[0].Attempts[0].Input.Path = "/other" },
		"attempt dial IP":     func(result *Result) { result.Hops[0].Attempts[0].Input.DialIP = testIPv4Two },
		"resolver order": func(result *Result) {
			result.Hops[0].Resolution.Evidence.Addresses = []systemresolver.Address{
				{IP: testIPv4Two, Family: systemresolver.FamilyIPv4},
				{IP: testIPv4One, Family: systemresolver.FamilyIPv4},
			}
		},
		"redirect count": func(result *Result) { result.RedirectsFollowed = 1 },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validCompletedResult(t)
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatalf("Validate() error = nil; result = %#v", result)
			}
		})
	}
}

func TestValidateRejectsHTTPFallbackBeforeCandidateExhaustion(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(
		resolutionSuccess(testHostname, testIPv4One),
		resolutionSuccess(testHostname, testIPv4One),
	)
	web := webobservationtest.New(
		webFailure(
			webobservation.SchemeHTTPS,
			testHostname,
			testIPv4One,
			"/",
			webobservation.FailureTCPTimeout,
		),
		webSuccess(webobservation.SchemeHTTP, testHostname, testIPv4One, "/", "", 204, ""),
	)
	result := mustObserver(t, resolver, web).Observe(
		context.Background(),
		Request{Hostname: testHostname},
	)
	assertValidResult(t, result)

	result.Hops[0].Resolution.Evidence.Addresses = append(
		result.Hops[0].Resolution.Evidence.Addresses,
		systemresolver.Address{IP: testIPv4Two, Family: systemresolver.FamilyIPv4},
	)
	if err := Validate(result); err == nil {
		t.Fatalf("Validate() accepted HTTP fallback before all selected HTTPS candidates failed")
	}
}

func validCompletedResult(t *testing.T) Result {
	t.Helper()
	resolver := systemresolvertest.New(resolutionSuccess(testHostname, testIPv4One))
	web := webobservationtest.New(
		webSuccess(webobservation.SchemeHTTPS, testHostname, testIPv4One, "/", "", 204, ""),
	)
	return mustObserver(t, resolver, web).Observe(
		context.Background(),
		Request{Hostname: testHostname},
	)
}
