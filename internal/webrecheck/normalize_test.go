package webrecheck

import (
	"reflect"
	"testing"

	"github.com/wangjc683/reachrun/internal/webobservation"
)

func TestNormalizeRequestCanonicalizesAndDeduplicatesCandidates(t *testing.T) {
	t.Parallel()

	input, err := normalizeRequest(Request{
		Hostname:            " EXAMPLE.COM. ",
		LocalCandidates:     []string{"::ffff:8.8.8.8", "8.8.8.8", " 1.0.0.1 "},
		ReferenceCandidates: []string{"1.1.1.1", "8.8.4.4"},
	})
	if err != nil {
		t.Fatalf("normalizeRequest() error = %v", err)
	}
	if input.Hostname != "example.com" || input.URL != "https://example.com/" ||
		input.Scheme != webobservation.SchemeHTTPS || input.Family != webobservation.FamilyIPv4 ||
		input.Port != httpsPort || input.Method != httpMethod || input.Path != httpPath ||
		input.CandidateLimitPerSource != candidateLimitPerSource ||
		input.RetryLimit != retryLimit || input.RedirectLimit != redirectLimit {
		t.Fatalf("normalized fixed input = %#v", input)
	}
	if want := []string{"8.8.8.8", "1.0.0.1"}; !reflect.DeepEqual(input.LocalCandidates, want) {
		t.Fatalf("local candidates = %#v, want %#v", input.LocalCandidates, want)
	}
	if want := []string{"1.1.1.1", "8.8.4.4"}; !reflect.DeepEqual(input.ReferenceCandidates, want) {
		t.Fatalf("reference candidates = %#v, want %#v", input.ReferenceCandidates, want)
	}
}

func TestNormalizeRequestRejectsUnsafeOrIncomparableInput(t *testing.T) {
	t.Parallel()

	tests := map[string]Request{
		"invalid hostname": {
			Hostname: "localhost", LocalCandidates: []string{"8.8.8.8"}, ReferenceCandidates: []string{"1.1.1.1"},
		},
		"empty local": {
			Hostname: "example.com", ReferenceCandidates: []string{"1.1.1.1"},
		},
		"empty reference": {
			Hostname: "example.com", LocalCandidates: []string{"8.8.8.8"},
		},
		"private local": {
			Hostname: "example.com", LocalCandidates: []string{"10.0.0.1"}, ReferenceCandidates: []string{"1.1.1.1"},
		},
		"mixed local family": {
			Hostname: "example.com", LocalCandidates: []string{"8.8.8.8", "2606:4700:4700::1111"}, ReferenceCandidates: []string{"1.1.1.1"},
		},
		"cross source family": {
			Hostname: "example.com", LocalCandidates: []string{"8.8.8.8"}, ReferenceCandidates: []string{"2606:4700:4700::1111"},
		},
	}

	for name, request := range tests {
		request := request
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input, err := normalizeRequest(request)
			if err == nil {
				t.Fatalf("normalizeRequest() error = nil; input = %#v", input)
			}
			if input.LocalCandidates == nil || input.ReferenceCandidates == nil {
				t.Fatalf("invalid input lost explicit candidate arrays: %#v", input)
			}
		})
	}
}

func TestScheduleAlternatesAndBoundsSources(t *testing.T) {
	t.Parallel()

	input, err := normalizeRequest(Request{
		Hostname:            "example.com",
		LocalCandidates:     []string{"8.8.8.8", "1.0.0.1", "9.9.9.9"},
		ReferenceCandidates: []string{"1.1.1.1", "8.8.4.4", "149.112.112.112"},
	})
	if err != nil {
		t.Fatalf("normalizeRequest() error = %v", err)
	}
	got := schedule(input)
	want := []scheduledCandidate{
		{source: CandidateLocal, ip: "8.8.8.8"},
		{source: CandidateReference, ip: "1.1.1.1"},
		{source: CandidateLocal, ip: "1.0.0.1"},
		{source: CandidateReference, ip: "8.8.4.4"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("schedule = %#v, want %#v", got, want)
	}
	if omittedCandidates(input.LocalCandidates) != 1 || omittedCandidates(input.ReferenceCandidates) != 1 {
		t.Fatal("omitted candidate counts do not match bounded schedule")
	}
}
