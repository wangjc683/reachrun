package familycondition

import (
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestValidateAcceptsSelectedAndUnavailableConditions(t *testing.T) {
	t.Parallel()

	result := validFamilyConditionResult()
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsContractMutations(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate  func(*Result)
		message string
	}{
		"probe": {
			mutate:  func(result *Result) { result.Probe = probe.KindSystemResolution },
			message: "probe must be",
		},
		"condition count": {
			mutate:  func(result *Result) { result.Evidence.Conditions = result.Evidence.Conditions[:1] },
			message: "exactly 2 conditions",
		},
		"family order": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].Family = FamilyIPv6
			},
			message: "family must be",
		},
		"network": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].Network = "udp"
			},
			message: "network must be",
		},
		"target": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].RouteTarget = "8.8.8.8:53"
			},
			message: "route target must be",
		},
		"payload": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].PayloadBytesSent = 1
			},
			message: "zero payload bytes",
		},
		"selected reason": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].Reason = ReasonNoRoute
			},
			message: "selected route must use reason",
		},
		"missing selected source": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].LocalAddress = ""
			},
			message: "local address",
		},
		"wrong source family": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].LocalAddress = "2001:db8::10"
			},
			message: "does not match",
		},
		"IPv4 zone": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[0].LocalZone = "test0"
			},
			message: "IPv4 local address",
		},
		"unavailable source": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[1].LocalAddress = "2001:db8::10"
			},
			message: "must not include a local source",
		},
		"unavailable reason": {
			mutate: func(result *Result) {
				result.Evidence.Conditions[1].Reason = ReasonKernelRouteSelected
			},
			message: "unsupported unavailable reason",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validFamilyConditionResult()
			test.mutate(&result)
			err := Validate(result)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func TestValidateAcceptsOnlyDeclaredFailureCodes(t *testing.T) {
	t.Parallel()

	for _, code := range []probe.FailureCode{
		FailureRouteCheck,
		probe.FailureTimeout,
		probe.FailureCancelled,
	} {
		result := validFamilyConditionResult()
		result.Evidence = nil
		result.Failure = &probe.Failure{Code: code}
		result.Outcome = probe.OutcomeFailed
		if code == probe.FailureCancelled {
			result.Outcome = probe.OutcomeCancelled
		}
		if err := Validate(result); err != nil {
			t.Fatalf("Validate(%q) error = %v", code, err)
		}
	}

	result := validFamilyConditionResult()
	result.Evidence = nil
	result.Outcome = probe.OutcomeFailed
	result.Failure = &probe.Failure{Code: probe.FailureInvalidInput}
	if err := Validate(result); err == nil {
		t.Fatal("Validate() error = nil for undeclared failure code")
	}
}

func validFamilyConditionResult() Result {
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    time.Date(2026, time.August, 3, 14, 0, 0, 0, time.UTC),
		DurationMS:    1,
		Platform:      probe.Platform{OS: "test", Arch: "test"},
		Source:        probe.Source{Backend: "scripted", Capability: probe.CapabilityNative},
		Input:         Input{},
		Outcome:       probe.OutcomeSucceeded,
		Evidence: &Evidence{Conditions: []Condition{
			{
				Family:           FamilyIPv4,
				Network:          "udp4",
				RouteTarget:      IPv4RouteTarget,
				Status:           StatusRouteSelected,
				Reason:           ReasonKernelRouteSelected,
				LocalAddress:     "192.0.2.10",
				PayloadBytesSent: 0,
			},
			{
				Family:           FamilyIPv6,
				Network:          "udp6",
				RouteTarget:      IPv6RouteTarget,
				Status:           StatusUnavailable,
				Reason:           ReasonNoRoute,
				PayloadBytesSent: 0,
			},
		}},
	}
}
