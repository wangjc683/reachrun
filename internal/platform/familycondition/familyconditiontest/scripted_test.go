package familyconditiontest

import (
	"context"
	"testing"

	"github.com/wangjc683/reachrun/internal/platform/familycondition"
)

func TestScriptedReturnsFiniteQueueAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := familycondition.Result{}
	first.DurationMS = 1
	second := familycondition.Result{}
	second.DurationMS = 2
	observer := New(first, second)

	if result := observer.Observe(context.Background()); result.DurationMS != 1 {
		t.Fatalf("first duration = %d, want 1", result.DurationMS)
	}
	if result := observer.Observe(context.Background()); result.DurationMS != 2 {
		t.Fatalf("second duration = %d, want 2", result.DurationMS)
	}
	if got := len(observer.Calls()); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
	if got := observer.Remaining(); got != 0 {
		t.Fatalf("remaining = %d, want 0", got)
	}

	defer func() {
		if recover() == nil {
			t.Fatal("exhausted Observe() did not panic")
		}
	}()
	observer.Observe(context.Background())
}
