package webpathtest

import (
	"context"
	"testing"

	"github.com/wangjc683/reachrun/internal/webpath"
)

func TestScriptedReturnsQueueAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := webpath.Result{Status: webpath.StatusCompleted}
	second := webpath.Result{Status: webpath.StatusStopped}
	results := []webpath.Result{first, second}
	observer := New(results...)
	results[0].Status = webpath.StatusStopped

	requestOne := webpath.Request{Hostname: "one.example"}
	requestTwo := webpath.Request{Hostname: "two.example"}
	if got := observer.Observe(context.Background(), requestOne); got.Status != first.Status {
		t.Fatalf("first result status = %q, want %q", got.Status, first.Status)
	}
	if got := observer.Observe(context.Background(), requestTwo); got.Status != second.Status {
		t.Fatalf("second result status = %q, want %q", got.Status, second.Status)
	}
	if observer.Remaining() != 0 {
		t.Fatalf("Remaining() = %d, want 0", observer.Remaining())
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
	observer.Observe(context.Background(), webpath.Request{})
}
