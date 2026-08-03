package browserplaceholder

import (
	"strings"
	"testing"
	"time"
)

func TestValidateAcceptsOpenedAndFallbackCompletions(t *testing.T) {
	t.Parallel()

	opened := validPlaceholderResult()
	if err := Validate(opened); err != nil {
		t.Fatalf("Validate(opened) error = %v", err)
	}
	fallback := validPlaceholderResult()
	failed := failedAttempt(fallback.URL)
	fallback.OpenAttempt = &failed
	fallback.FallbackNotified = true
	if err := Validate(fallback); err != nil {
		t.Fatalf("Validate(fallback) error = %v", err)
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
			message: "operation",
		},
		"platform": {
			mutate:  func(result *Result) { result.Platform.OS = "" },
			message: "platform",
		},
		"input": {
			mutate:  func(result *Result) { result.Input.ListenAddress = "localhost:0" },
			message: "fixed placeholder policy",
		},
		"URL": {
			mutate:  func(result *Result) { result.URL = "http://localhost:40000/" },
			message: "canonical placeholder",
		},
		"open attempt": {
			mutate:  func(result *Result) { result.OpenAttempt.Backend = "" },
			message: "browser opener evidence",
		},
		"fallback": {
			mutate:  func(result *Result) { result.FallbackNotified = true },
			message: "opened browser attempt",
		},
		"request": {
			mutate:  func(result *Result) { result.PageRequest.Host = "localhost:40000" },
			message: "exact placeholder URL",
		},
		"terminal": {
			mutate:  func(result *Result) { result.Completion = "other" },
			message: "completed placeholder",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validPlaceholderResult()
			test.mutate(&result)
			err := Validate(result)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func TestValidateAcceptsStoppedAndCancelledPartialShapes(t *testing.T) {
	t.Parallel()

	timedOut := validPlaceholderResult()
	timedOut.Status = StatusStopped
	timedOut.Completion = ""
	timedOut.StopReason = StopPlaceholderTimeout
	timedOut.Detail = "context deadline exceeded"
	timedOut.PageRequest = nil
	if err := Validate(timedOut); err != nil {
		t.Fatalf("Validate(timeout) error = %v", err)
	}

	cancelled := timedOut
	cancelled.Status = StatusCancelled
	cancelled.StopReason = StopCancelled
	cancelled.Detail = "context canceled"
	if err := Validate(cancelled); err != nil {
		t.Fatalf("Validate(cancelled) error = %v", err)
	}
}

func TestValidateRejectsInvalidFallbackFailureAndUnsafeURL(t *testing.T) {
	t.Parallel()

	notifyFailed := validPlaceholderResult()
	notifyFailed.Status = StatusStopped
	notifyFailed.Completion = ""
	notifyFailed.StopReason = StopFallbackNotificationFailure
	notifyFailed.Detail = "terminal unavailable"
	notifyFailed.PageRequest = nil
	opened := openedAttempt(notifyFailed.URL)
	notifyFailed.OpenAttempt = &opened
	if err := Validate(notifyFailed); err == nil || !strings.Contains(err.Error(), "unnotified failed opener") {
		t.Fatalf("Validate(fallback failure after opened attempt) error = %v", err)
	}

	unsafe := validPlaceholderResult()
	unsafe.URL = "http://user@127.0.0.1:40000/"
	if err := Validate(unsafe); err == nil || !strings.Contains(err.Error(), "canonical placeholder") {
		t.Fatalf("Validate(userinfo URL) error = %v", err)
	}
}

func validPlaceholderResult() Result {
	rawURL := "http://127.0.0.1:40000/"
	attempt := openedAttempt(rawURL)
	return Result{
		SchemaVersion: SchemaVersion,
		Operation:     Operation,
		ObservedAt:    time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC),
		DurationMS:    20,
		Platform:      testPlatform,
		Input:         fixedInput(time.Second),
		URL:           rawURL,
		OpenAttempt:   &attempt,
		PageRequest: &PageRequest{
			Method: "GET",
			Host:   "127.0.0.1:40000",
			Path:   "/",
		},
		Status:     StatusCompleted,
		Completion: CompletionPageRequested,
	}
}
