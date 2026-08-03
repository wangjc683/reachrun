package browseropenertest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/platform/browseropener"
)

func TestScriptedReturnsFiniteQueueAndRecordsCalls(t *testing.T) {
	t.Parallel()

	first := browseropener.Result{Backend: "scripted", URL: "first", Status: browseropener.StatusOpened}
	second := browseropener.Result{Backend: "scripted", URL: "second", Status: browseropener.StatusOpened}
	opener := New(first, second)
	if got := opener.Open(context.Background(), "first"); !reflect.DeepEqual(got, first) {
		t.Fatalf("first result = %#v, want %#v", got, first)
	}
	if got := opener.Open(context.Background(), "second"); !reflect.DeepEqual(got, second) {
		t.Fatalf("second result = %#v, want %#v", got, second)
	}
	wantCalls := []Call{{URL: "first"}, {URL: "second"}}
	if got := opener.Calls(); !reflect.DeepEqual(got, wantCalls) {
		t.Fatalf("calls = %#v, want %#v", got, wantCalls)
	}
	if opener.Remaining() != 0 {
		t.Fatalf("remaining = %d, want 0", opener.Remaining())
	}
	defer func() {
		if recover() == nil {
			t.Fatal("exhausted Open() did not panic")
		}
	}()
	opener.Open(context.Background(), "third")
}
