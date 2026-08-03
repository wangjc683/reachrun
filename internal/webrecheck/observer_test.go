package webrecheck

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
	"github.com/wangjc683/reachrun/internal/webobservation/webobservationtest"
)

func TestObserveCompletesAllBoundedCandidatesInAlternatingOrder(t *testing.T) {
	t.Parallel()

	web := webobservationtest.New(
		successfulObservation("8.8.8.8"),
		failedObservation("1.1.1.1"),
		failedObservation("1.0.0.1"),
		successfulObservation("8.8.4.4"),
	)
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(context.Background(), Request{
		Hostname:            "EXAMPLE.COM.",
		LocalCandidates:     []string{"8.8.8.8", "1.0.0.1", "9.9.9.9"},
		ReferenceCandidates: []string{"1.1.1.1", "8.8.4.4", "149.112.112.112"},
	})

	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Status != StatusCompleted || result.StopReason != "" || result.Detail != "" {
		t.Fatalf("terminal state = %q/%q %q", result.Status, result.StopReason, result.Detail)
	}
	if result.LocalCandidatesOmitted != 1 || result.ReferenceCandidatesOmitted != 1 {
		t.Fatalf("omitted counts = %d/%d", result.LocalCandidatesOmitted, result.ReferenceCandidatesOmitted)
	}
	if len(result.Attempts) != 4 {
		t.Fatalf("attempt count = %d, want 4", len(result.Attempts))
	}
	wantSources := []CandidateSource{
		CandidateLocal, CandidateReference, CandidateLocal, CandidateReference,
	}
	wantIPs := []string{"8.8.8.8", "1.1.1.1", "1.0.0.1", "8.8.4.4"}
	for index, attempt := range result.Attempts {
		if attempt.CandidateSource != wantSources[index] || attempt.Observation.Input.DialIP != wantIPs[index] {
			t.Fatalf("attempt %d = %#v", index, attempt)
		}
	}

	calls := web.Calls()
	if len(calls) != len(wantIPs) {
		t.Fatalf("Web calls = %d, want %d", len(calls), len(wantIPs))
	}
	for index, call := range calls {
		want := webobservation.Request{
			Scheme: webobservation.SchemeHTTPS, Hostname: "example.com", DialIP: wantIPs[index],
		}
		if call.Request != want {
			t.Fatalf("call %d = %#v, want %#v", index, call.Request, want)
		}
	}
}

func TestObserveRejectsInvalidInputWithoutCallingWeb(t *testing.T) {
	t.Parallel()

	web := webobservationtest.New()
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(context.Background(), Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{"10.0.0.1"},
		ReferenceCandidates: []string{"1.1.1.1"},
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusStopped || result.StopReason != StopInvalidInput || result.Detail == "" {
		t.Fatalf("terminal state = %#v", result)
	}
	if len(web.Calls()) != 0 || len(result.Attempts) != 0 {
		t.Fatal("invalid input must not call the Web adapter or retain attempts")
	}
}

func TestObserveKeepsIPv6CandidatesInOneComparableFamily(t *testing.T) {
	t.Parallel()

	local := "2606:4700:4700::1111"
	reference := "2001:4860:4860::8888"
	web := webobservationtest.New(failedObservation(local), failedObservation(reference))
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(context.Background(), Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{local},
		ReferenceCandidates: []string{reference},
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCompleted || result.Input.Family != webobservation.FamilyIPv6 {
		t.Fatalf("IPv6 result = %#v", result)
	}
	for _, attempt := range result.Attempts {
		if attempt.Observation.Input.Family != webobservation.FamilyIPv6 {
			t.Fatalf("attempt family = %q", attempt.Observation.Input.Family)
		}
	}
}

func TestObserveStopsOnInvalidProbeEvidenceAndKeepsPriorAttempt(t *testing.T) {
	t.Parallel()

	invalid := successfulObservation("1.1.1.1")
	invalid.Input.Hostname = "other.example"
	web := webobservationtest.New(successfulObservation("8.8.8.8"), invalid)
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(context.Background(), Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{"8.8.8.8"},
		ReferenceCandidates: []string{"1.1.1.1"},
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
	if result.Status != StatusStopped || result.StopReason != StopInvalidProbeEvidence ||
		len(result.Attempts) != 1 {
		t.Fatalf("terminal evidence = %#v", result)
	}
}

func TestObserveRejectsValidEvidenceThatChangesRequestOrAdapter(t *testing.T) {
	t.Parallel()

	tests := map[string]webobservation.Result{
		"dial target": failedObservation("8.8.4.4"),
		"adapter": func() webobservation.Result {
			result := failedObservation("1.1.1.1")
			result.Source.Backend = "other-scripted-web"
			return result
		}(),
	}
	for name, second := range tests {
		second := second
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			web := webobservationtest.New(failedObservation("8.8.8.8"), second)
			observer := newTestObserver(t, Config{}, web)
			result := observer.Observe(context.Background(), Request{
				Hostname:            "example.com",
				LocalCandidates:     []string{"8.8.8.8"},
				ReferenceCandidates: []string{"1.1.1.1"},
			})
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if result.Status != StatusStopped || result.StopReason != StopInvalidProbeEvidence ||
				len(result.Attempts) != 1 {
				t.Fatalf("result = %#v", result)
			}
		})
	}
}

func TestObserveTreatsCancelledAttemptAsAggregateCancellation(t *testing.T) {
	t.Parallel()

	web := webobservationtest.New(
		failedObservation("8.8.8.8"),
		cancelledObservation("1.1.1.1"),
	)
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(context.Background(), Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{"8.8.8.8"},
		ReferenceCandidates: []string{"1.1.1.1"},
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCancelled || result.StopReason != StopCancelled || len(result.Attempts) != 2 {
		t.Fatalf("terminal result = %#v", result)
	}
}

func TestObserveCancellationDiscardsLateSuccess(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	web := webObserverFunc(func(_ context.Context, _ webobservation.Request) webobservation.Result {
		cancel()
		return successfulObservation("8.8.8.8")
	})
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(ctx, Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{"8.8.8.8"},
		ReferenceCandidates: []string{"1.1.1.1"},
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusCancelled || len(result.Attempts) != 0 {
		t.Fatalf("late success was retained: %#v", result)
	}
}

func TestObserveAlreadyExpiredContextStopsWithoutCallingWeb(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	web := webobservationtest.New()
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(ctx, Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{"8.8.8.8"},
		ReferenceCandidates: []string{"1.1.1.1"},
	})
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	if result.Status != StatusStopped || result.StopReason != StopRecheckTimeout ||
		len(result.Attempts) != 0 || len(web.Calls()) != 0 {
		t.Fatalf("expired-context result = %#v", result)
	}
}

func TestNewObserverValidatesDependenciesAndTimeout(t *testing.T) {
	t.Parallel()

	web := webobservationtest.New()
	created := newTestObserver(t, Config{}, web)
	if created.timeout != defaultTimeout {
		t.Fatalf("default timeout = %s, want %s", created.timeout, defaultTimeout)
	}
	if _, err := New(Config{Timeout: -1}); err == nil {
		t.Fatal("New(negative timeout) error = nil")
	}
	if _, err := New(Config{Timeout: maximumTimeout + time.Nanosecond}); err == nil {
		t.Fatal("New(too large timeout) error = nil")
	}
	if _, err := newObserver(Config{}, dependencies{platform: testPlatform}); err == nil {
		t.Fatal("newObserver(nil Web adapter) error = nil")
	}
	if _, err := newObserver(Config{}, dependencies{
		platform: probe.Platform{OS: "testos"}, web: web,
	}); err == nil {
		t.Fatal("newObserver(incomplete platform) error = nil")
	}
}

func newTestObserver(
	t *testing.T,
	config Config,
	web webobservation.Observer,
) *observer {
	t.Helper()
	created, err := newObserver(config, dependencies{
		now: func() time.Time { return testObservedAt }, platform: testPlatform, web: web,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	return created
}

type webObserverFunc func(context.Context, webobservation.Request) webobservation.Result

func (f webObserverFunc) Observe(
	ctx context.Context,
	request webobservation.Request,
) webobservation.Result {
	return f(ctx, request)
}

func TestObserverInputSlicesAreIndependent(t *testing.T) {
	t.Parallel()

	local := []string{"8.8.8.8"}
	reference := []string{"1.1.1.1"}
	web := webobservationtest.New(failedObservation(local[0]), failedObservation(reference[0]))
	observer := newTestObserver(t, Config{}, web)
	result := observer.Observe(context.Background(), Request{
		Hostname: "example.com", LocalCandidates: local, ReferenceCandidates: reference,
	})
	local[0] = "9.9.9.9"
	reference[0] = "8.8.4.4"
	if !reflect.DeepEqual(result.Input.LocalCandidates, []string{"8.8.8.8"}) ||
		!reflect.DeepEqual(result.Input.ReferenceCandidates, []string{"1.1.1.1"}) {
		t.Fatalf("result input aliases caller slices: %#v", result.Input)
	}
}
