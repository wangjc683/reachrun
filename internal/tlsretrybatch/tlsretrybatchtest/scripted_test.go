package tlsretrybatchtest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/tlsretrybatch"
)

func TestScriptedReturnsFiniteQueueAndDefensiveCalls(t *testing.T) {
	t.Parallel()

	first := tlsretrybatch.Result{DurationMS: 1}
	second := tlsretrybatch.Result{DurationMS: 2}
	observer := New(first, second)
	request := tlsretrybatch.Request{Targets: []string{"8.8.8.8"}}
	if result := observer.Observe(context.Background(), request); result.DurationMS != 1 {
		t.Fatalf("first duration = %d, want 1", result.DurationMS)
	}
	request.Targets[0] = "1.1.1.1"
	if result := observer.Observe(context.Background(), request); result.DurationMS != 2 {
		t.Fatalf("second duration = %d, want 2", result.DurationMS)
	}
	want := []Call{
		{Request: tlsretrybatch.Request{Targets: []string{"8.8.8.8"}}},
		{Request: tlsretrybatch.Request{Targets: []string{"1.1.1.1"}}},
	}
	if got := observer.Calls(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %#v, want %#v", got, want)
	}
	if observer.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", observer.Remaining())
	}
	defer func() {
		if recover() == nil {
			t.Fatal("exhausted Observe() did not panic")
		}
	}()
	observer.Observe(context.Background(), request)
}
