package tlsretrybatch

import (
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

func TestValidateAcceptsCompletedRetryReport(t *testing.T) {
	t.Parallel()

	result := validRetryBatchResult()
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
		"schema": {
			mutate:  func(result *Result) { result.SchemaVersion++ },
			message: "schema_version",
		},
		"operation": {
			mutate:  func(result *Result) { result.Operation = "other" },
			message: "operation must be",
		},
		"input policy": {
			mutate:  func(result *Result) { result.Input.RetryLimit++ },
			message: "fixed retry policy",
		},
		"nil input targets": {
			mutate:  func(result *Result) { result.Input.Targets = nil },
			message: "encode as arrays",
		},
		"nil target results": {
			mutate:  func(result *Result) { result.Targets = nil },
			message: "encode as arrays",
		},
		"omitted count": {
			mutate:  func(result *Result) { result.TargetsOmitted = 1 },
			message: "targets_omitted",
		},
		"target address": {
			mutate:  func(result *Result) { result.Targets[0].DialIP = "1.1.1.1" },
			message: "normalized address",
		},
		"target status": {
			mutate:  func(result *Result) { result.Targets[0].Status = TargetInterrupted },
			message: "interrupted status",
		},
		"attempt number": {
			mutate:  func(result *Result) { result.Targets[0].Attempts[0].Number = 2 },
			message: "non-sequential",
		},
		"first delay": {
			mutate:  func(result *Result) { result.Targets[0].Attempts[0].RetryDelayMS = 100 },
			message: "first attempt",
		},
		"nested platform": {
			mutate: func(result *Result) {
				result.Targets[0].Attempts[0].Observation.Platform.OS = "other"
			},
			message: "fixed platform or TLS request",
		},
		"completed reason": {
			mutate:  func(result *Result) { result.StopReason = StopBatchTimeout },
			message: "completed batch",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validRetryBatchResult()
			test.mutate(&result)
			err := Validate(result)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func TestValidateRejectsRetryAfterNonRetryableResult(t *testing.T) {
	t.Parallel()

	result := validRetryBatchResult()
	target := result.Targets[0].DialIP
	result.Targets[0].Attempts = append(result.Targets[0].Attempts, Attempt{
		Number:       2,
		RetryDelayMS: backoffMin.Milliseconds(),
		Observation:  testTLSCompleted(target),
	})
	err := Validate(result)
	if err == nil || !strings.Contains(err.Error(), "follows a non-retryable result") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRequiresRetryableCompletedTargetToExhaustPolicy(t *testing.T) {
	t.Parallel()

	result := validRetryBatchResult()
	target := result.Targets[0].DialIP
	result.Targets[0].Attempts[0].Observation = testTLSFailure(
		target,
		probe.OutcomeFailed,
		tlsobservation.FailureTCPTimeout,
	)
	err := Validate(result)
	if err == nil || !strings.Contains(err.Error(), "before exhausting") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateAcceptsInvalidInputAndCancelledShapes(t *testing.T) {
	t.Parallel()

	invalidInput, err := normalizeRequest(Request{Targets: []string{"192.168.1.1"}})
	if err == nil {
		t.Fatal("normalizeRequest() error = nil")
	}
	invalid := Result{
		SchemaVersion: SchemaVersion,
		Operation:     Operation,
		ObservedAt:    time.Now().UTC(),
		Platform:      testPlatform,
		Input:         invalidInput,
		Status:        StatusStopped,
		StopReason:    StopInvalidInput,
		Detail:        err.Error(),
		Targets:       []TargetResult{},
	}
	if err := Validate(invalid); err != nil {
		t.Fatalf("Validate(invalid) error = %v", err)
	}

	cancelled := validRetryBatchResult()
	cancelled.Status = StatusCancelled
	cancelled.StopReason = StopCancelled
	cancelled.Detail = "context canceled"
	cancelled.Targets[0].Status = TargetNotStarted
	cancelled.Targets[0].Attempts = []Attempt{}
	if err := Validate(cancelled); err != nil {
		t.Fatalf("Validate(cancelled) error = %v", err)
	}
}

func TestValidateRequiresOneTLSAdapterAcrossAttempts(t *testing.T) {
	t.Parallel()

	result := validRetryBatchResult()
	secondIP := "1.1.1.1"
	result.Input.Targets = append(result.Input.Targets, secondIP)
	second := TargetResult{
		DialIP: secondIP,
		Family: tlsobservation.FamilyIPv4,
		Status: TargetCompleted,
		Attempts: []Attempt{{
			Number:      1,
			Observation: testTLSCompleted(secondIP),
		}},
	}
	second.Attempts[0].Observation.Source.Backend = "other-adapter"
	result.Targets = append(result.Targets, second)
	err := Validate(result)
	if err == nil || !strings.Contains(err.Error(), "configured TLS adapter") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func validRetryBatchResult() Result {
	target := "8.8.8.8"
	input, err := normalizeRequest(Request{Targets: []string{target}})
	if err != nil {
		panic(err)
	}
	return Result{
		SchemaVersion: SchemaVersion,
		Operation:     Operation,
		ObservedAt:    time.Date(2026, time.August, 3, 15, 0, 0, 0, time.UTC),
		DurationMS:    3,
		Platform:      testPlatform,
		Input:         input,
		Status:        StatusCompleted,
		Targets: []TargetResult{{
			DialIP: target,
			Family: tlsobservation.FamilyIPv4,
			Status: TargetCompleted,
			Attempts: []Attempt{{
				Number:      1,
				Observation: testTLSCompleted(target),
			}},
		}},
	}
}
