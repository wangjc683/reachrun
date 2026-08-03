package browserplaceholder

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/browseropener"
	"github.com/wangjc683/reachrun/internal/probe"
)

var testPlatform = probe.Platform{OS: "testos", Arch: "testarch"}

type openerFunc func(context.Context, string) browseropener.Result

func (f openerFunc) Open(ctx context.Context, rawURL string) browseropener.Result {
	return f(ctx, rawURL)
}

func testRunner(
	t *testing.T,
	opener browseropener.Opener,
	options ...func(*dependencies),
) *runner {
	t.Helper()
	startedAt := time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	deps := dependencies{
		now:      sequenceClock(startedAt, startedAt.Add(20*time.Millisecond)),
		platform: testPlatform,
		opener:   opener,
	}
	for _, option := range options {
		option(&deps)
	}
	runner, err := newRunner(Config{Timeout: time.Second}, deps)
	if err != nil {
		t.Fatalf("newRunner() error = %v", err)
	}
	return runner
}

func sequenceClock(times ...time.Time) func() time.Time {
	index := 0
	return func() time.Time {
		if index >= len(times) {
			panic("test clock exhausted")
		}
		value := times[index]
		index++
		return value
	}
}

func openedAttempt(rawURL string) browseropener.Result {
	return browseropener.Result{
		Backend: "scripted-browser",
		URL:     rawURL,
		Status:  browseropener.StatusOpened,
	}
}

func failedAttempt(rawURL string) browseropener.Result {
	return browseropener.Result{
		Backend: "scripted-browser",
		URL:     rawURL,
		Status:  browseropener.StatusFailed,
		Failure: &browseropener.Failure{
			Code:   browseropener.FailureLaunchFailed,
			Detail: "scripted browser launch failure",
		},
	}
}

func requestPage(t *testing.T, request *http.Request) *http.Response {
	t.Helper()
	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("request placeholder: %v", err)
	}
	return response
}

func closeResponse(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read placeholder response: %v", err)
	}
	return string(body)
}
