package webrecheck

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation/webobservationtest"
)

func TestValidateAcceptsCompletedFailuresAsCompleteEvidence(t *testing.T) {
	t.Parallel()

	result := validCompletedResult(t)
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	for _, attempt := range result.Attempts {
		if attempt.Observation.Outcome != probe.OutcomeFailed {
			t.Fatalf("test fixture unexpectedly succeeded: %#v", attempt)
		}
	}
}

func TestValidateRejectsMutatedAggregateOrNestedEvidence(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"schema":      func(result *Result) { result.SchemaVersion++ },
		"operation":   func(result *Result) { result.Operation = "other" },
		"observed at": func(result *Result) { result.ObservedAt = time.Time{} },
		"observed at zone": func(result *Result) {
			result.ObservedAt = result.ObservedAt.In(time.FixedZone("UTC+1", 3600))
		},
		"duration":          func(result *Result) { result.DurationMS = -1 },
		"platform":          func(result *Result) { result.Platform.OS = "" },
		"attempt array":     func(result *Result) { result.Attempts = nil },
		"fixed URL":         func(result *Result) { result.Input.URL = "https://other.example/" },
		"fixed scheme":      func(result *Result) { result.Input.Scheme = "http" },
		"fixed family":      func(result *Result) { result.Input.Family = "ipv6" },
		"candidate limit":   func(result *Result) { result.Input.CandidateLimitPerSource++ },
		"retry policy":      func(result *Result) { result.Input.RetryLimit++ },
		"redirect policy":   func(result *Result) { result.Input.RedirectLimit++ },
		"omitted local":     func(result *Result) { result.LocalCandidatesOmitted++ },
		"omitted reference": func(result *Result) { result.ReferenceCandidatesOmitted++ },
		"attempt source": func(result *Result) {
			result.Attempts[0].CandidateSource = CandidateReference
		},
		"attempt dial ip": func(result *Result) {
			result.Attempts[0].Observation.Input.DialIP = "9.9.9.9"
		},
		"attempt hostname": func(result *Result) {
			result.Attempts[0].Observation.Input.Hostname = "other.example"
		},
		"attempt platform": func(result *Result) {
			result.Attempts[0].Observation.Platform.OS = "other"
		},
		"attempt adapter": func(result *Result) {
			result.Attempts[1].Observation.Source.Backend = "other"
		},
		"nested evidence": func(result *Result) {
			result.Attempts[0].Observation.Failure.Code = "unknown"
		},
		"completed missing attempt": func(result *Result) {
			result.Attempts = result.Attempts[:1]
		},
		"completed stop reason": func(result *Result) {
			result.StopReason = StopRecheckTimeout
		},
		"valid input marked invalid": func(result *Result) {
			result.Status = StatusStopped
			result.StopReason = StopInvalidInput
			result.Detail = "rejected"
			result.Attempts = result.Attempts[:0]
		},
		"invalid evidence after full schedule": func(result *Result) {
			result.Status = StatusStopped
			result.StopReason = StopInvalidProbeEvidence
			result.Detail = "invalid"
		},
		"stopped without detail": func(result *Result) {
			result.Status = StatusStopped
			result.StopReason = StopRecheckTimeout
			result.Attempts = result.Attempts[:1]
		},
		"cancelled wrong reason": func(result *Result) {
			result.Status = StatusCancelled
			result.StopReason = StopRecheckTimeout
			result.Attempts = result.Attempts[:1]
		},
	}

	for name, mutate := range tests {
		mutate := mutate
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

func TestInvalidInputJSONKeepsExplicitArrays(t *testing.T) {
	t.Parallel()

	web := webobservationtest.New()
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(t.Context(), Request{Hostname: "bad host"})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	text := string(encoded)
	for _, want := range []string{
		`"local_candidates":[]`,
		`"reference_candidates":[]`,
		`"attempts":[]`,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("JSON %s does not contain %s", text, want)
		}
	}
}

func validCompletedResult(t *testing.T) Result {
	t.Helper()
	web := webobservationtest.New(
		failedObservation("8.8.8.8"),
		failedObservation("1.1.1.1"),
	)
	observer := newTestObserver(t, Config{}, web)
	return observer.Observe(t.Context(), Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{"8.8.8.8"},
		ReferenceCandidates: []string{"1.1.1.1"},
	})
}
