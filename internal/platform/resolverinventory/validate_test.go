package resolverinventory

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestValidateAcceptsInventoryFailureAllowlist(t *testing.T) {
	t.Parallel()

	for _, code := range []probe.FailureCode{
		FailureUnavailable,
		FailureInvalid,
		probe.FailureTimeout,
	} {
		code := code
		t.Run(string(code), func(t *testing.T) {
			t.Parallel()
			result := validInventoryResult()
			result.Outcome = probe.OutcomeFailed
			result.Evidence = nil
			result.Failure = &probe.Failure{Code: code}
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestInventoryResultJSONRoundTripRemainsValid(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(validInventoryResult())
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var decoded Result
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if err := Validate(decoded); err != nil {
		t.Fatalf("Validate() after JSON round trip = %v", err)
	}
}

func TestValidateRejectsWrongKindFailureOrEvidence(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"wrong kind": func(result *Result) {
			result.Probe = probe.KindSystemResolution
		},
		"foreign failure": func(result *Result) {
			result.Outcome = probe.OutcomeFailed
			result.Evidence = nil
			result.Failure = &probe.Failure{Code: probe.FailureNameUnresolved}
		},
		"noncanonical address": func(result *Result) {
			result.Evidence.Groups[0].Servers[0].Address = "::ffff:192.0.2.53"
		},
		"duplicate server": func(result *Result) {
			result.Evidence.Groups[0].Servers = append(
				result.Evidence.Groups[0].Servers,
				result.Evidence.Groups[0].Servers[0],
			)
		},
		"empty evidence": func(result *Result) {
			result.Evidence = &Evidence{Groups: []Group{}}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validInventoryResult()
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatal("Validate() error = nil, want contract error")
			}
		})
	}
}

func validInventoryResult() Result {
	evidence, err := normalizeEvidence(Evidence{Groups: []Group{{
		Scope:   ScopeGlobal,
		Servers: []Server{{Address: "192.0.2.53", Port: 53}},
	}}})
	if err != nil {
		panic(err)
	}
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindResolverInventory,
		ObservedAt:    time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC),
		Platform:      probe.Platform{OS: "testos", Arch: "testarch"},
		Source:        testInventorySource,
		Input:         Input{},
		Outcome:       probe.OutcomeSucceeded,
		Evidence:      &evidence,
	}
}
