package tlsobservationtest

import (
	"context"
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

func TestScriptedReturnsFiniteResultsAndRecordsCalls(t *testing.T) {
	t.Parallel()

	want := tlsobservation.Result{}
	observer := New(want)
	request := tlsobservation.Request{DialIP: "93.184.216.34"}
	if got := observer.Observe(context.Background(), request); !reflect.DeepEqual(got, want) {
		t.Fatalf("Observe() = %#v, want %#v", got, want)
	}
	if got := observer.Calls(); !reflect.DeepEqual(got, []Call{{Request: request}}) {
		t.Fatalf("Calls() = %#v", got)
	}
	if remaining := observer.Remaining(); remaining != 0 {
		t.Fatalf("Remaining() = %d, want 0", remaining)
	}
}
