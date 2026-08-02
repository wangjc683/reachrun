package sshobservationtest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/sshobservation"
)

func TestScriptedReturnsExactQueueAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := sshobservation.Result{Input: sshobservation.Input{DialIP: "first"}}
	second := sshobservation.Result{Input: sshobservation.Input{DialIP: "second"}}
	adapter := New(first, second)
	requests := []sshobservation.Request{
		{DialIP: "1.1.1.1"},
		{DialIP: "8.8.8.8", Port: 2222},
	}
	if got := adapter.Observe(context.Background(), requests[0]); !reflect.DeepEqual(got, first) {
		t.Fatalf("first result = %#v, want %#v", got, first)
	}
	if got := adapter.Observe(context.Background(), requests[1]); !reflect.DeepEqual(got, second) {
		t.Fatalf("second result = %#v, want %#v", got, second)
	}
	wantCalls := []Call{{Request: requests[0]}, {Request: requests[1]}}
	if got := adapter.Calls(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", got, wantCalls)
	}
	if got := adapter.Remaining(); got != 0 {
		t.Fatalf("Remaining() = %d, want 0", got)
	}
}

func TestScriptedPanicsWhenQueueIsExhausted(t *testing.T) {
	t.Parallel()

	adapter := New()
	defer func() {
		if recover() == nil {
			t.Fatal("Observe() did not panic")
		}
	}()
	adapter.Observe(context.Background(), sshobservation.Request{})
}
