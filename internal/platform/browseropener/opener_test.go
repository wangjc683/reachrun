package browseropener

import (
	"context"
	"errors"
	"os/exec"
	"reflect"
	"testing"
	"time"
)

const testLoopbackURL = "http://127.0.0.1:43821/"

func TestOpenReturnsValidatedPlatformAttempt(t *testing.T) {
	t.Parallel()

	var calls []string
	opener, err := newOpener(dependencies{
		backend: "scripted-browser",
		launch: func(_ context.Context, rawURL string) error {
			calls = append(calls, rawURL)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("newOpener() error = %v", err)
	}
	result := opener.Open(context.Background(), testLoopbackURL)
	if err := Validate(result, testLoopbackURL); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusOpened || !reflect.DeepEqual(calls, []string{testLoopbackURL}) {
		t.Fatalf("result/calls = %#v/%#v, want opened and one exact URL", result, calls)
	}
}

func TestOpenRejectsUnsafeURLsBeforeLaunching(t *testing.T) {
	t.Parallel()

	called := false
	opener, err := newOpener(dependencies{
		backend: "scripted-browser",
		launch: func(context.Context, string) error {
			called = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("newOpener() error = %v", err)
	}
	unsafeURL := "https://example.com/"
	result := opener.Open(context.Background(), unsafeURL)
	if err := Validate(result, unsafeURL); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if called || result.Status != StatusFailed || result.Failure.Code != FailureInvalidURL {
		t.Fatalf("result/called = %#v/%t, want invalid URL without launch", result, called)
	}
}

func TestOpenClassifiesPlatformLaunchFailures(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		err  error
		code FailureCode
	}{
		"command unavailable":  {err: exec.ErrNotFound, code: FailureCommandUnavailable},
		"unsupported platform": {err: errUnsupportedPlatform, code: FailureUnsupportedPlatform},
		"launch failed":        {err: errors.New("scripted failure"), code: FailureLaunchFailed},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			opener, err := newOpener(dependencies{
				backend: "scripted-browser",
				launch:  func(context.Context, string) error { return test.err },
			})
			if err != nil {
				t.Fatalf("newOpener() error = %v", err)
			}
			result := opener.Open(context.Background(), testLoopbackURL)
			if err := Validate(result, testLoopbackURL); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Status != StatusFailed || result.Failure.Code != test.code {
				t.Fatalf("result = %#v, want failure %q", result, test.code)
			}
		})
	}
}

func TestOpenClassifiesLaunchDeadlineSeparatelyFromCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	opener, err := newOpener(dependencies{
		backend: "scripted-browser",
		launch: func(ctx context.Context, _ string) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})
	if err != nil {
		t.Fatalf("newOpener() error = %v", err)
	}
	result := opener.Open(ctx, testLoopbackURL)
	if err := Validate(result, testLoopbackURL); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusFailed || result.Failure.Code != FailureLaunchTimeout {
		t.Fatalf("result = %#v, want failed/launch_timeout", result)
	}
}

func TestOpenMakesCancellationDominant(t *testing.T) {
	t.Parallel()

	preCancelled, cancelPre := context.WithCancel(context.Background())
	cancelPre()
	called := false
	opener, err := newOpener(dependencies{
		backend: "scripted-browser",
		launch: func(context.Context, string) error {
			called = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("newOpener() error = %v", err)
	}
	result := opener.Open(preCancelled, testLoopbackURL)
	if called || result.Status != StatusCancelled {
		t.Fatalf("pre-cancel result/called = %#v/%t", result, called)
	}

	lateContext, cancelLate := context.WithCancel(context.Background())
	lateOpener, err := newOpener(dependencies{
		backend:             "scripted-browser",
		launch:              func(context.Context, string) error { return nil },
		beforeSuccessCommit: cancelLate,
	})
	if err != nil {
		t.Fatalf("newOpener(late) error = %v", err)
	}
	result = lateOpener.Open(lateContext, testLoopbackURL)
	if err := Validate(result, testLoopbackURL); err != nil {
		t.Fatalf("Validate(late) error = %v", err)
	}
	if result.Status != StatusCancelled {
		t.Fatalf("late cancellation result = %#v", result)
	}
}

func TestNewOpenerRejectsMissingDependencies(t *testing.T) {
	t.Parallel()

	if _, err := newOpener(dependencies{launch: func(context.Context, string) error { return nil }}); err == nil {
		t.Fatal("newOpener() error = nil without backend")
	}
	if _, err := newOpener(dependencies{backend: "scripted"}); err == nil {
		t.Fatal("newOpener() error = nil without launch function")
	}
	if _, err := New(); err != nil {
		t.Fatalf("New() error = %v", err)
	}
}
