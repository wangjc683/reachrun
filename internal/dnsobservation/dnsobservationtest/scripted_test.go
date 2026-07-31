package dnsobservationtest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/probe"
)

func TestScriptedReturnsExactQueueAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := dnsobservation.Result{Outcome: probe.OutcomeSucceeded}
	second := dnsobservation.Result{
		Outcome: probe.OutcomeFailed,
		Failure: &probe.Failure{Code: dnsobservation.FailureDNSTransport},
	}
	source := []dnsobservation.Result{first, second}
	observer := New(source...)
	source[0].Outcome = probe.OutcomeCancelled

	requests := []dnsobservation.Request{
		{Hostname: "one.example", QueryType: dnsobservation.QueryTypeA, Resolver: "one", Transport: dnsobservation.TransportUDP},
		{Hostname: "two.example", QueryType: dnsobservation.QueryTypeAAAA, Resolver: "two", Transport: dnsobservation.TransportDoH},
	}
	if got := observer.Observe(context.Background(), requests[0]); !reflect.DeepEqual(got, first) {
		t.Fatalf("first result = %#v, want exact %#v", got, first)
	}
	if observer.Remaining() != 1 {
		t.Fatalf("Remaining() = %d, want 1", observer.Remaining())
	}
	if got := observer.Observe(context.Background(), requests[1]); !reflect.DeepEqual(got, second) {
		t.Fatalf("second result = %#v, want exact %#v", got, second)
	}
	if observer.Remaining() != 0 {
		t.Fatalf("Remaining() = %d, want 0", observer.Remaining())
	}

	wantCalls := []Call{{Request: requests[0]}, {Request: requests[1]}}
	calls := observer.Calls()
	if !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("Calls() = %#v, want %#v", calls, wantCalls)
	}
	calls[0].Request.Hostname = "changed.example"
	if got := observer.Calls()[0].Request.Hostname; got != "one.example" {
		t.Fatalf("Calls() snapshot mutation changed history to %q", got)
	}
}

func TestScriptedPanicsOnQueueExhaustion(t *testing.T) {
	t.Parallel()

	observer := New()
	request := dnsobservation.Request{Hostname: "unexpected.example"}
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Fatal("Observe() did not panic on exhausted queue")
		}
		calls := observer.Calls()
		if len(calls) != 1 || calls[0].Request != request {
			t.Fatalf("Calls() after exhaustion = %#v, want unexpected call recorded", calls)
		}
	}()

	observer.Observe(context.Background(), request)
}
