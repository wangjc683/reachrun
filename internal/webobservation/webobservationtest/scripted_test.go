package webobservationtest

import (
	"context"
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

func TestScriptedReturnsQueueAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := webobservation.Result{Outcome: probe.OutcomeSucceeded}
	second := webobservation.Result{Outcome: probe.OutcomeFailed}
	results := []webobservation.Result{first, second}
	observer := New(results...)
	results[0].Outcome = probe.OutcomeFailed

	requestOne := webobservation.Request{
		Scheme:   webobservation.SchemeHTTPS,
		Hostname: "one.example",
		DialIP:   "8.8.8.8",
	}
	requestTwo := webobservation.Request{
		Scheme:   webobservation.SchemeHTTP,
		Hostname: "two.example",
		DialIP:   "1.1.1.1",
	}
	if got := observer.Observe(context.Background(), requestOne); got.Outcome != first.Outcome {
		t.Fatalf("first result outcome = %q, want %q", got.Outcome, first.Outcome)
	}
	if got := observer.Observe(context.Background(), requestTwo); got.Outcome != second.Outcome {
		t.Fatalf("second result outcome = %q, want %q", got.Outcome, second.Outcome)
	}
	if remaining := observer.Remaining(); remaining != 0 {
		t.Fatalf("Remaining() = %d, want 0", remaining)
	}

	calls := observer.Calls()
	if len(calls) != 2 || calls[0].Request != requestOne || calls[1].Request != requestTwo {
		t.Fatalf("Calls() = %#v", calls)
	}
	calls[0].Request.Hostname = "changed.example"
	if got := observer.Calls()[0].Request.Hostname; got != requestOne.Hostname {
		t.Fatalf("Calls() did not return a defensive copy: %q", got)
	}
}

func TestScriptedPanicsWhenQueueIsExhausted(t *testing.T) {
	t.Parallel()

	observer := New()
	defer func() {
		if recover() == nil {
			t.Fatal("Observe() did not panic on queue exhaustion")
		}
	}()
	observer.Observe(context.Background(), webobservation.Request{})
}
