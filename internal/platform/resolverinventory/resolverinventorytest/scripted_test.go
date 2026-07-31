package resolverinventorytest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/platform/resolverinventory"
)

func TestScriptedReturnsExactResultsAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := resolverinventory.Result{Input: resolverinventory.Input{}}
	second := resolverinventory.Result{Input: resolverinventory.Input{}}
	observer := New(first, second)

	if got := observer.Observe(context.Background()); !reflect.DeepEqual(got, first) {
		t.Fatalf("first result = %#v, want %#v", got, first)
	}
	if got := observer.Observe(context.Background()); !reflect.DeepEqual(got, second) {
		t.Fatalf("second result = %#v, want %#v", got, second)
	}
	if observer.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", observer.Remaining())
	}
	if got := observer.Calls(); !reflect.DeepEqual(got, []Call{{}, {}}) {
		t.Fatalf("calls = %#v, want two calls", got)
	}
}

func TestScriptedPanicsWhenExhausted(t *testing.T) {
	t.Parallel()

	observer := New()
	defer func() {
		if recover() == nil {
			t.Fatal("Observe() did not panic after scripted results were exhausted")
		}
	}()
	observer.Observe(context.Background())
}
