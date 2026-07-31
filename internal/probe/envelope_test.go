package probe

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

type testInput struct {
	Name string `json:"name"`
}

type testEvidence struct {
	Value string `json:"value"`
}

func TestEnvelopeJSONContract(t *testing.T) {
	t.Parallel()

	evidence := testEvidence{Value: "observed"}
	envelope := validTestEnvelope()
	envelope.Evidence = &evidence

	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	want := `{"schema_version":1,"probe":"system_resolution","observed_at":"2026-08-01T00:00:00Z","duration_ms":12,"platform":{"os":"testos","arch":"testarch"},"source":{"backend":"test-backend","capability":"native"},"input":{"name":"example.com"},"outcome":"succeeded","evidence":{"value":"observed"}}`
	if string(encoded) != want {
		t.Fatalf("unexpected JSON contract\n got: %s\nwant: %s", encoded, want)
	}
	if strings.Contains(string(encoded), `"failure"`) {
		t.Fatalf("success JSON must omit failure: %s", encoded)
	}
}

func TestEnvelopeValidateAcceptsTerminalShapes(t *testing.T) {
	t.Parallel()

	tests := map[string]Envelope[testInput, testEvidence]{
		"succeeded": validTestEnvelope(),
		"failed": func() Envelope[testInput, testEvidence] {
			envelope := validTestEnvelope()
			envelope.Outcome = OutcomeFailed
			envelope.Evidence = nil
			envelope.Failure = &Failure{Code: FailureNameUnresolved, Detail: "not found"}
			return envelope
		}(),
		"cancelled": func() Envelope[testInput, testEvidence] {
			envelope := validTestEnvelope()
			envelope.Outcome = OutcomeCancelled
			envelope.Evidence = nil
			envelope.Failure = &Failure{Code: FailureCancelled}
			return envelope
		}(),
	}

	for name, envelope := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := envelope.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestEnvelopeValidateRejectsBrokenInvariants(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Envelope[testInput, testEvidence]){
		"schema version": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.SchemaVersion = 2
		},
		"probe": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Probe = ""
		},
		"observed at": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.ObservedAt = time.Time{}
		},
		"observed at not utc": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.ObservedAt = time.Date(
				2026,
				time.August,
				1,
				8,
				0,
				0,
				0,
				time.FixedZone("UTC+8", 8*60*60),
			)
		},
		"duration": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.DurationMS = -1
		},
		"platform": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Platform.OS = ""
		},
		"backend": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Source.Backend = ""
		},
		"capability": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Source.Capability = "unknown"
		},
		"degraded without reason": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Source.Capability = CapabilityDegraded
		},
		"native with reason": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Source.Reason = "unexpected"
		},
		"outcome": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Outcome = "unknown"
		},
		"success without evidence": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Evidence = nil
		},
		"success with failure": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Failure = &Failure{Code: FailureResolutionFailure}
		},
		"failure without detail": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Outcome = OutcomeFailed
			envelope.Evidence = nil
			envelope.Failure = nil
		},
		"failure with evidence": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Outcome = OutcomeFailed
			envelope.Failure = &Failure{Code: FailureResolutionFailure}
		},
		"failure with cancelled code": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Outcome = OutcomeFailed
			envelope.Evidence = nil
			envelope.Failure = &Failure{Code: FailureCancelled}
		},
		"cancelled without cancelled code": func(envelope *Envelope[testInput, testEvidence]) {
			envelope.Outcome = OutcomeCancelled
			envelope.Evidence = nil
			envelope.Failure = &Failure{Code: FailureTimeout}
		},
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			envelope := validTestEnvelope()
			mutate(&envelope)
			if err := envelope.Validate(); err == nil {
				t.Fatal("Validate() error = nil, want invariant failure")
			}
		})
	}
}

func validTestEnvelope() Envelope[testInput, testEvidence] {
	evidence := testEvidence{Value: "observed"}
	return Envelope[testInput, testEvidence]{
		SchemaVersion: SchemaVersion,
		Probe:         KindSystemResolution,
		ObservedAt:    time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC),
		DurationMS:    12,
		Platform: Platform{
			OS:   "testos",
			Arch: "testarch",
		},
		Source: Source{
			Backend:    "test-backend",
			Capability: CapabilityNative,
		},
		Input:    testInput{Name: "example.com"},
		Outcome:  OutcomeSucceeded,
		Evidence: &evidence,
	}
}
