package main

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver/systemresolvertest"
	"github.com/wangjc683/reachrun/internal/probe"
)

func TestRunResolvePrintsJSONAndReturnsOutcomeExitCode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result systemresolver.Result
		code   int
	}{
		"succeeded": {
			result: cliSuccessResult(),
			code:   0,
		},
		"failed": {
			result: cliFailureResult(probe.OutcomeFailed, probe.FailureNameUnresolved),
			code:   1,
		},
		"cancelled": {
			result: cliFailureResult(probe.OutcomeCancelled, probe.FailureCancelled),
			code:   130,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolver := systemresolvertest.New(test.result)
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"resolve", "example.com"},
				&stdout,
				&stderr,
				resolver,
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d", code, test.code)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}

			var decoded systemresolver.Result
			if err := json.Unmarshal(stdout.Bytes(), &decoded); err != nil {
				t.Fatalf("unmarshal stdout %q: %v", stdout.String(), err)
			}
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			if got := resolver.Calls(); !reflect.DeepEqual(got, []systemresolvertest.Call{{Hostname: "example.com"}}) {
				t.Fatalf("calls = %#v", got)
			}
		})
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(context.Background(), []string{"resolve"}, &stdout, &stderr, resolver)

	if code != 2 {
		t.Fatalf("run() = %d, want 2", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "Usage: reachrun resolve <hostname>") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
	if len(resolver.Calls()) != 0 {
		t.Fatalf("resolver calls = %#v, want none", resolver.Calls())
	}
}

func TestRunRejectsInvalidResolverEnvelope(t *testing.T) {
	t.Parallel()

	resolver := systemresolvertest.New(systemresolver.Result{})
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"resolve", "example.com"},
		&stdout,
		&stderr,
		resolver,
	)

	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "invalid system resolver result") {
		t.Fatalf("stderr = %q, want validation error", stderr.String())
	}
}

func cliSuccessResult() systemresolver.Result {
	evidence := systemresolver.Evidence{
		Addresses: []systemresolver.Address{{IP: "192.0.2.1", Family: systemresolver.FamilyIPv4}},
	}
	return cliResult(probe.OutcomeSucceeded, &evidence, nil)
}

func cliFailureResult(outcome probe.Outcome, code probe.FailureCode) systemresolver.Result {
	return cliResult(outcome, nil, &probe.Failure{Code: code, Detail: "scripted failure"})
}

func cliResult(
	outcome probe.Outcome,
	evidence *systemresolver.Evidence,
	failure *probe.Failure,
) systemresolver.Result {
	return systemresolver.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindSystemResolution,
		ObservedAt:    time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC),
		DurationMS:    1,
		Platform:      probe.Platform{OS: "testos", Arch: "testarch"},
		Source: probe.Source{
			Backend:    "scripted",
			Capability: probe.CapabilityDegraded,
			Reason:     "scripted_fixture",
		},
		Input:    systemresolver.Input{Hostname: "example.com"},
		Outcome:  outcome,
		Evidence: evidence,
		Failure:  failure,
	}
}
