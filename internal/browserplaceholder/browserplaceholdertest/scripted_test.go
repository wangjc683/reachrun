package browserplaceholdertest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/browserplaceholder"
)

func TestScriptedEmitsFallbackAndReturnsFiniteQueue(t *testing.T) {
	t.Parallel()

	fallback := browserplaceholder.Fallback{URL: "http://127.0.0.1:40000/"}
	result := browserplaceholder.Result{DurationMS: 3}
	runner := New(Step{Fallback: &fallback, Result: result})
	var gotFallback browserplaceholder.Fallback
	got := runner.Run(context.Background(), func(value browserplaceholder.Fallback) error {
		gotFallback = value
		return nil
	})
	if !reflect.DeepEqual(got, result) || !reflect.DeepEqual(gotFallback, fallback) {
		t.Fatalf("result/fallback = %#v/%#v, want %#v/%#v", got, gotFallback, result, fallback)
	}
	if runner.Calls() != 1 || runner.Remaining() != 0 {
		t.Fatalf("calls/remaining = %d/%d, want 1/0", runner.Calls(), runner.Remaining())
	}
	defer func() {
		if recover() == nil {
			t.Fatal("exhausted Run() did not panic")
		}
	}()
	runner.Run(context.Background(), func(browserplaceholder.Fallback) error { return nil })
}
