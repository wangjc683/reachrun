package browserplaceholder

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/browseropener"
)

func TestRunCompletesOnlyAfterExactPlaceholderRequest(t *testing.T) {
	t.Parallel()

	opener := openerFunc(func(_ context.Context, rawURL string) browseropener.Result {
		request, err := http.NewRequest(http.MethodGet, rawURL, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		response := requestPage(t, request)
		body := closeResponse(t, response)
		if response.StatusCode != http.StatusOK || !strings.Contains(body, "ReachRun browser check") {
			t.Fatalf("placeholder response = %d/%q", response.StatusCode, body)
		}
		for _, header := range []string{
			"Cache-Control",
			"Content-Security-Policy",
			"Referrer-Policy",
			"X-Content-Type-Options",
		} {
			if response.Header.Get(header) == "" {
				t.Fatalf("placeholder response missing %s", header)
			}
		}
		return openedAttempt(rawURL)
	})
	result := testRunner(t, opener).Run(context.Background(), func(Fallback) error {
		t.Fatal("fallback notified after opened browser attempt")
		return nil
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCompleted || result.FallbackNotified || result.PageRequest == nil {
		t.Fatalf("result = %#v, want completed exact request without fallback", result)
	}
}

func TestRunKeepsPlaceholderAvailableAfterOpenFailure(t *testing.T) {
	t.Parallel()

	opener := openerFunc(func(_ context.Context, rawURL string) browseropener.Result {
		return failedAttempt(rawURL)
	})
	var notified Fallback
	result := testRunner(t, opener).Run(context.Background(), func(fallback Fallback) error {
		notified = fallback
		request, err := http.NewRequest(http.MethodGet, fallback.URL, nil)
		if err != nil {
			t.Fatalf("NewRequest() error = %v", err)
		}
		response := requestPage(t, request)
		closeResponse(t, response)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("fallback response status = %d, want 200", response.StatusCode)
		}
		return nil
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCompleted || !result.FallbackNotified ||
		notified.URL != result.URL || notified.Failure.Code != browseropener.FailureLaunchFailed {
		t.Fatalf("result/notified = %#v/%#v, want completed accessible fallback", result, notified)
	}
}

func TestRunRejectsWrongHostMethodAndPathBeforeCompleting(t *testing.T) {
	t.Parallel()

	opener := openerFunc(func(_ context.Context, rawURL string) browseropener.Result {
		wrongHost, _ := http.NewRequest(http.MethodGet, rawURL, nil)
		wrongHost.Host = "localhost:" + wrongHost.URL.Port()
		response := requestPage(t, wrongHost)
		closeResponse(t, response)
		if response.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("wrong Host status = %d, want 421", response.StatusCode)
		}

		wrongMethod, _ := http.NewRequest(http.MethodPost, rawURL, nil)
		response = requestPage(t, wrongMethod)
		closeResponse(t, response)
		if response.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("wrong method status = %d, want 405", response.StatusCode)
		}

		wrongPath, _ := http.NewRequest(http.MethodGet, rawURL+"other", nil)
		response = requestPage(t, wrongPath)
		closeResponse(t, response)
		if response.StatusCode != http.StatusNotFound {
			t.Fatalf("wrong path status = %d, want 404", response.StatusCode)
		}

		valid, _ := http.NewRequest(http.MethodGet, rawURL, nil)
		response = requestPage(t, valid)
		closeResponse(t, response)
		return openedAttempt(rawURL)
	})
	result := testRunner(t, opener).Run(context.Background(), func(Fallback) error { return nil })
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCompleted {
		t.Fatalf("status = %q, want completed", result.Status)
	}
}

func TestRunStopsOnTimeoutAndFallbackNotificationFailure(t *testing.T) {
	t.Parallel()

	t.Run("timeout", func(t *testing.T) {
		t.Parallel()
		runner, err := newRunner(Config{Timeout: 10 * time.Millisecond}, dependencies{
			now:      time.Now,
			platform: testPlatform,
			opener: openerFunc(func(_ context.Context, rawURL string) browseropener.Result {
				return openedAttempt(rawURL)
			}),
		})
		if err != nil {
			t.Fatalf("newRunner() error = %v", err)
		}
		result := runner.Run(context.Background(), func(Fallback) error { return nil })
		if err := Validate(result); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if result.Status != StatusStopped || result.StopReason != StopPlaceholderTimeout {
			t.Fatalf("terminal = %s/%s, want timeout", result.Status, result.StopReason)
		}
	})

	t.Run("timeout while opener is active", func(t *testing.T) {
		t.Parallel()
		runner, err := newRunner(Config{Timeout: 10 * time.Millisecond}, dependencies{
			now:      time.Now,
			platform: testPlatform,
			opener: openerFunc(func(ctx context.Context, rawURL string) browseropener.Result {
				<-ctx.Done()
				return browseropener.Result{
					Backend: "scripted-browser",
					URL:     rawURL,
					Status:  browseropener.StatusFailed,
					Failure: &browseropener.Failure{
						Code:   browseropener.FailureLaunchTimeout,
						Detail: ctx.Err().Error(),
					},
				}
			}),
		})
		if err != nil {
			t.Fatalf("newRunner() error = %v", err)
		}
		result := runner.Run(context.Background(), func(Fallback) error {
			t.Fatal("fallback notified after the placeholder deadline")
			return nil
		})
		if err := Validate(result); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if result.Status != StatusStopped || result.StopReason != StopPlaceholderTimeout ||
			result.OpenAttempt == nil || result.FallbackNotified {
			t.Fatalf("result = %#v, want timeout with unnotified opener deadline", result)
		}
	})

	t.Run("fallback notification", func(t *testing.T) {
		t.Parallel()
		opener := openerFunc(func(_ context.Context, rawURL string) browseropener.Result {
			return failedAttempt(rawURL)
		})
		result := testRunner(t, opener).Run(context.Background(), func(Fallback) error {
			return errors.New("terminal unavailable")
		})
		if err := Validate(result); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if result.Status != StatusStopped || result.StopReason != StopFallbackNotificationFailure {
			t.Fatalf("terminal = %s/%s, want fallback notification failure", result.Status, result.StopReason)
		}
	})
}

func TestRunMakesCancellationDominant(t *testing.T) {
	t.Parallel()

	t.Run("pre-cancelled", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		called := false
		opener := openerFunc(func(context.Context, string) browseropener.Result {
			called = true
			return browseropener.Result{}
		})
		result := testRunner(t, opener).Run(ctx, func(Fallback) error { return nil })
		if err := Validate(result); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if called || result.Status != StatusCancelled || result.URL != "" {
			t.Fatalf("result/called = %#v/%t, want pre-cancel without listener or opener", result, called)
		}
	})

	t.Run("success commit", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		opener := openerFunc(func(_ context.Context, rawURL string) browseropener.Result {
			request, _ := http.NewRequest(http.MethodGet, rawURL, nil)
			response := requestPage(t, request)
			closeResponse(t, response)
			return openedAttempt(rawURL)
		})
		runner := testRunner(t, opener, func(deps *dependencies) {
			deps.beforeSuccessCommit = cancel
		})
		result := runner.Run(ctx, func(Fallback) error { return nil })
		if err := Validate(result); err != nil {
			t.Fatalf("Validate() error = %v", err)
		}
		if result.Status != StatusCancelled || result.PageRequest != nil {
			t.Fatalf("result = %#v, want late cancellation without completed request", result)
		}
	})
}

func TestRunRejectsInvalidDependenciesAndEvidence(t *testing.T) {
	t.Parallel()

	if _, err := newRunner(Config{}, dependencies{}); err == nil {
		t.Fatal("newRunner() error = nil without opener")
	}
	if _, err := newRunner(Config{Timeout: maximumTimeout + time.Millisecond}, dependencies{
		opener: openerFunc(func(context.Context, string) browseropener.Result {
			return browseropener.Result{}
		}),
	}); err == nil {
		t.Fatal("newRunner() error = nil for excessive timeout")
	}

	invalid := openerFunc(func(context.Context, string) browseropener.Result {
		return browseropener.Result{}
	})
	result := testRunner(t, invalid).Run(context.Background(), func(Fallback) error { return nil })
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusStopped || result.StopReason != StopInvalidOpenerEvidence ||
		result.OpenAttempt != nil {
		t.Fatalf("result = %#v, want discarded invalid opener evidence", result)
	}

	nilNotifierResult := testRunner(t, invalid).Run(context.Background(), nil)
	if err := Validate(nilNotifierResult); err != nil {
		t.Fatalf("Validate(nil notifier) error = %v", err)
	}
	if nilNotifierResult.StopReason != StopInvalidFallbackNotifier {
		t.Fatalf("stop reason = %q, want invalid fallback notifier", nilNotifierResult.StopReason)
	}
}

func TestRunRejectsNonLoopbackListenerEvidence(t *testing.T) {
	t.Parallel()

	opener := openerFunc(func(context.Context, string) browseropener.Result {
		t.Fatal("opener called for non-loopback listener")
		return browseropener.Result{}
	})
	runner := testRunner(t, opener, func(deps *dependencies) {
		deps.listen = func(network, _ string) (net.Listener, error) {
			return net.Listen(network, "0.0.0.0:0")
		}
	})
	result := runner.Run(context.Background(), func(Fallback) error { return nil })
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.StopReason != StopListenerFailure {
		t.Fatalf("stop reason = %q, want listener failure", result.StopReason)
	}
}
