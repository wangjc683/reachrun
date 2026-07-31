package systemresolvertest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
)

func TestScriptedReturnsExactResultsAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := systemresolver.Result{Input: systemresolver.Input{Hostname: "first.example"}}
	second := systemresolver.Result{Input: systemresolver.Input{Hostname: "second.example"}}
	resolver := New(first, second)

	if got := resolver.Resolve(context.Background(), "one.example"); !reflect.DeepEqual(got, first) {
		t.Fatalf("first result = %#v, want %#v", got, first)
	}
	if got := resolver.Resolve(context.Background(), "two.example"); !reflect.DeepEqual(got, second) {
		t.Fatalf("second result = %#v, want %#v", got, second)
	}
	if resolver.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", resolver.Remaining())
	}

	wantCalls := []Call{{Hostname: "one.example"}, {Hostname: "two.example"}}
	if got := resolver.Calls(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", got, wantCalls)
	}
}

func TestScriptedPanicsWhenExhausted(t *testing.T) {
	t.Parallel()

	resolver := New()
	defer func() {
		if recover() == nil {
			t.Fatal("Resolve() did not panic after scripted results were exhausted")
		}
	}()

	resolver.Resolve(context.Background(), "unexpected.example")
}
