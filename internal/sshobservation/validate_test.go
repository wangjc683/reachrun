package sshobservation

import (
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestValidateAcceptsReceivedAndUnconfirmedEvidence(t *testing.T) {
	t.Parallel()

	received := validResult()
	if err := Validate(received); err != nil {
		t.Fatalf("Validate(received) error = %v", err)
	}
	unconfirmed := validResult()
	unconfirmed.Evidence.Identification = Identification{
		Status:                   IdentificationUnconfirmed,
		UnconfirmedReason:        UnconfirmedTimeout,
		ClientIdentificationSent: true,
		ExchangeMS:               1,
	}
	if err := Validate(unconfirmed); err != nil {
		t.Fatalf("Validate(unconfirmed) error = %v", err)
	}
}

func TestValidateRejectsBrokenSSHContract(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"probe":                        func(result *Result) { result.Probe = probe.KindWebObservation },
		"port":                         func(result *Result) { result.Input.Port = 0 },
		"client identification":        func(result *Result) { result.Input.ClientIdentification = "custom" },
		"family":                       func(result *Result) { result.Input.Family = FamilyIPv6 },
		"remote":                       func(result *Result) { result.Evidence.RemoteEndpoint = "8.8.8.8:22" },
		"negative TCP timing":          func(result *Result) { result.Evidence.TCPConnectMS = -1 },
		"timing exceeds total":         func(result *Result) { result.Evidence.Identification.ExchangeMS = 3 },
		"unknown status":               func(result *Result) { result.Evidence.Identification.Status = "other" },
		"received with reason":         func(result *Result) { result.Evidence.Identification.UnconfirmedReason = UnconfirmedTimeout },
		"received without client line": func(result *Result) { result.Evidence.Identification.ClientIdentificationSent = false },
		"invalid server line":          func(result *Result) { result.Evidence.Identification.ServerIdentification = "SSH-2.0-bad-software" },
		"server line carries CR":       func(result *Result) { result.Evidence.Identification.ServerIdentification += "\r" },
		"mismatched parsed fields":     func(result *Result) { result.Evidence.Identification.SoftwareVersion = "other" },
	}

	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validResult()
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatalf("Validate() error = nil; result = %#v", result)
			}
		})
	}
}

func TestValidateRequiresInvalidInputFailureToDescribeInvalidTarget(t *testing.T) {
	t.Parallel()

	result := validResult()
	result.Outcome = probe.OutcomeFailed
	result.Evidence = nil
	result.Failure = &probe.Failure{Code: probe.FailureInvalidInput}
	if err := Validate(result); err == nil {
		t.Fatal("Validate(valid target marked invalid_input) error = nil")
	}

	result.Input = Input{
		DialIP:               "not-an-ip",
		Port:                 DefaultPort,
		ClientIdentification: ClientIdentification,
	}
	if err := Validate(result); err != nil {
		t.Fatalf("Validate(actual invalid input) error = %v", err)
	}
}

func validResult() Result {
	evidence := Evidence{
		RemoteEndpoint: testPublicIPv4 + ":22",
		TCPConnectMS:   1,
		Identification: Identification{
			Status:                   IdentificationReceived,
			ServerIdentification:     "SSH-2.0-OpenSSH_9.9 test",
			ProtocolVersion:          "2.0",
			SoftwareVersion:          "OpenSSH_9.9",
			Comments:                 "test",
			ClientIdentificationSent: true,
			ExchangeMS:               1,
		},
	}
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC),
		DurationMS:    2,
		Platform:      probe.Platform{OS: "testos", Arch: "testarch"},
		Source:        probe.Source{Backend: "scripted", Capability: probe.CapabilityNative},
		Input: Input{
			DialIP: testPublicIPv4, Family: FamilyIPv4, Port: DefaultPort,
			ClientIdentification: ClientIdentification,
		},
		Outcome:  probe.OutcomeSucceeded,
		Evidence: &evidence,
	}
}
