package dnshttpspathtest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/dnshttpspath"
)

func TestScriptedReturnsQueueAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := dnshttpspath.Result{Status: dnshttpspath.StatusCompleted}
	second := dnshttpspath.Result{Status: dnshttpspath.StatusStopped}
	source := []dnshttpspath.Result{first, second}
	observer := New(source...)
	source[0].Status = dnshttpspath.StatusCancelled
	requests := []dnshttpspath.Request{
		{Hostname: "one.example", Resolver: "one", Transport: "udp"},
		{Hostname: "two.example", Resolver: "two", Transport: "doh"},
	}

	if got := observer.Observe(context.Background(), requests[0]); !reflect.DeepEqual(got, first) {
		t.Fatalf("first result = %#v, want %#v", got, first)
	}
	if got := observer.Observe(context.Background(), requests[1]); !reflect.DeepEqual(got, second) {
		t.Fatalf("second result = %#v, want %#v", got, second)
	}
	wantCalls := []Call{{Request: requests[0]}, {Request: requests[1]}}
	if calls := observer.Calls(); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", calls, wantCalls)
	}
	if observer.Remaining() != 0 {
		t.Fatalf("Remaining() = %d, want 0", observer.Remaining())
	}
}

func TestScriptedPanicsOnExhaustion(t *testing.T) {
	t.Parallel()

	observer := New()
	request := dnshttpspath.Request{Hostname: "unexpected.example"}
	defer func() {
		if recover() == nil {
			t.Fatal("Observe() did not panic")
		}
		if calls := observer.Calls(); len(calls) != 1 || calls[0].Request != request {
			t.Fatalf("calls after panic = %#v", calls)
		}
	}()
	observer.Observe(context.Background(), request)
}
