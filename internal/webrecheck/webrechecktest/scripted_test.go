package webrechecktest

import (
	"context"
	"testing"

	"github.com/wangjc683/reachrun/internal/webrecheck"
)

func TestScriptedRecordsDefensiveRequestCopies(t *testing.T) {
	t.Parallel()

	want := webrecheck.Result{SchemaVersion: webrecheck.SchemaVersion}
	scripted := New(want)
	request := webrecheck.Request{
		Hostname: "example.com", LocalCandidates: []string{"8.8.8.8"}, ReferenceCandidates: []string{"1.1.1.1"},
	}
	if got := scripted.Observe(context.Background(), request); got.SchemaVersion != want.SchemaVersion {
		t.Fatalf("Observe() = %#v", got)
	}
	request.LocalCandidates[0] = "9.9.9.9"
	calls := scripted.Calls()
	if len(calls) != 1 || calls[0].Request.LocalCandidates[0] != "8.8.8.8" {
		t.Fatalf("Calls() = %#v", calls)
	}
	calls[0].Request.ReferenceCandidates[0] = "8.8.4.4"
	if got := scripted.Calls()[0].Request.ReferenceCandidates[0]; got != "1.1.1.1" {
		t.Fatalf("Calls() returned aliased request %q", got)
	}
	if scripted.Remaining() != 0 {
		t.Fatalf("Remaining() = %d", scripted.Remaining())
	}
}

func TestScriptedPanicsOnExhaustion(t *testing.T) {
	t.Parallel()

	scripted := New()
	defer func() {
		if recover() == nil {
			t.Fatal("Observe() did not panic on exhaustion")
		}
	}()
	scripted.Observe(context.Background(), webrecheck.Request{})
}
