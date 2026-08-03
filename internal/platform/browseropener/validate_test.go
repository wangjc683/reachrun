package browseropener

import (
	"strings"
	"testing"
)

func TestValidateLoopbackURLAllowsOnlyCanonicalReachRunOrigin(t *testing.T) {
	t.Parallel()

	valid := []string{
		testLoopbackURL,
		"http://127.0.0.1:43821/path?value=1#session-token",
	}
	for _, rawURL := range valid {
		if err := validateLoopbackURL(rawURL); err != nil {
			t.Fatalf("validateLoopbackURL(%q) error = %v", rawURL, err)
		}
	}

	invalid := []string{
		"https://127.0.0.1:43821/",
		"http://localhost:43821/",
		"http://127.0.0.1/",
		"http://127.0.0.1:043821/",
		"http://user@127.0.0.1:43821/",
		"http://127.0.0.1:43821",
		"http://127.0.0.1:43821/\nnext",
	}
	for _, rawURL := range invalid {
		if err := validateLoopbackURL(rawURL); err == nil {
			t.Fatalf("validateLoopbackURL(%q) error = nil", rawURL)
		}
	}
}

func TestValidateRejectsResultMutations(t *testing.T) {
	t.Parallel()

	valid := Result{Backend: "scripted", URL: testLoopbackURL, Status: StatusOpened}
	tests := map[string]struct {
		mutate  func(*Result)
		message string
	}{
		"backend": {
			mutate:  func(result *Result) { result.Backend = "" },
			message: "backend",
		},
		"URL": {
			mutate:  func(result *Result) { result.URL = "http://127.0.0.1:43822/" },
			message: "requested URL",
		},
		"opened failure": {
			mutate: func(result *Result) {
				result.Failure = &Failure{Code: FailureLaunchFailed, Detail: "failed"}
			},
			message: "must not include failure",
		},
		"status": {
			mutate:  func(result *Result) { result.Status = "other" },
			message: "unsupported status",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := valid
			test.mutate(&result)
			err := Validate(result, testLoopbackURL)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("Validate() error = %v, want containing %q", err, test.message)
			}
		})
	}
}

func TestValidateRequiresStableFailureShapes(t *testing.T) {
	t.Parallel()

	failed := Result{
		Backend: "scripted",
		URL:     testLoopbackURL,
		Status:  StatusFailed,
		Failure: &Failure{Code: FailureLaunchFailed, Detail: "scripted failure"},
	}
	if err := Validate(failed, testLoopbackURL); err != nil {
		t.Fatalf("Validate(failed) error = %v", err)
	}
	cancelled := failed
	cancelled.Status = StatusCancelled
	cancelled.Failure = &Failure{Code: FailureCancelled, Detail: "context canceled"}
	if err := Validate(cancelled, testLoopbackURL); err != nil {
		t.Fatalf("Validate(cancelled) error = %v", err)
	}
	invalidCancelled := cancelled
	invalidCancelled.URL = "https://example.com/"
	if err := Validate(invalidCancelled, invalidCancelled.URL); err == nil ||
		!strings.Contains(err.Error(), "cancelled result has invalid URL") {
		t.Fatalf("Validate(cancelled invalid URL) error = %v", err)
	}
}
