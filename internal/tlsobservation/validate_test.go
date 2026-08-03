package tlsobservation

import (
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestValidateAcceptsCompletedAndUnconfirmedEvidence(t *testing.T) {
	t.Parallel()

	completed := validResult()
	if err := Validate(completed); err != nil {
		t.Fatalf("Validate(completed) error = %v", err)
	}
	unconfirmed := validResult()
	unconfirmed.Evidence.TLS = unconfirmedTLS(1, UnconfirmedHandshakeTimeout)
	if err := Validate(unconfirmed); err != nil {
		t.Fatalf("Validate(unconfirmed) error = %v", err)
	}
}

func TestValidateRejectsBrokenTLSContract(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"probe":                  func(result *Result) { result.Probe = probe.KindWebObservation },
		"port":                   func(result *Result) { result.Input.Port = 8443 },
		"SNI mode":               func(result *Result) { result.Input.SNIMode = "sent" },
		"identity mode":          func(result *Result) { result.Input.IdentityVerification = "verified" },
		"family":                 func(result *Result) { result.Input.Family = FamilyIPv6 },
		"remote":                 func(result *Result) { result.Evidence.RemoteEndpoint = "8.8.8.8:443" },
		"negative TCP timing":    func(result *Result) { result.Evidence.TCPConnectMS = -1 },
		"negative TLS timing":    func(result *Result) { result.Evidence.TLS.HandshakeMS = -1 },
		"timing exceeds total":   func(result *Result) { result.Evidence.TLS.HandshakeMS = 3 },
		"unknown status":         func(result *Result) { result.Evidence.TLS.Status = "other" },
		"completed with reason":  func(result *Result) { result.Evidence.TLS.UnconfirmedReason = UnconfirmedHandshakeFailure },
		"completed without leaf": func(result *Result) { result.Evidence.TLS.Leaf = nil },
		"uppercase fingerprint": func(result *Result) {
			result.Evidence.TLS.Leaf.SHA256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		},
		"unconfirmed with version": func(result *Result) {
			result.Evidence.TLS = unconfirmedTLS(1, UnconfirmedHandshakeFailure)
			result.Evidence.TLS.Version = "TLS1.3"
		},
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
		Port:                 Port,
		SNIMode:              SNIOmittedNoHostname,
		IdentityVerification: IdentityNotPerformedNoHostname,
	}
	if err := Validate(result); err != nil {
		t.Fatalf("Validate(actual invalid input) error = %v", err)
	}
}

func validResult() Result {
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	evidence := Evidence{
		RemoteEndpoint: testPublicIPv4 + ":443",
		TCPConnectMS:   1,
		TLS: TLS{
			Status:           TLSCompleted,
			HandshakeMS:      1,
			Version:          "TLS1.3",
			CipherSuite:      "TLS_AES_128_GCM_SHA256",
			PeerCertificates: 1,
			Leaf: &LeafCertificate{
				SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				NotBefore: notBefore,
				NotAfter:  notBefore.Add(24 * time.Hour),
			},
		},
	}
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    time.Date(2026, time.August, 3, 0, 0, 0, 0, time.UTC),
		DurationMS:    2,
		Platform:      probe.Platform{OS: "testos", Arch: "testarch"},
		Source:        probe.Source{Backend: "scripted", Capability: probe.CapabilityNative},
		Input: Input{
			DialIP:               testPublicIPv4,
			Family:               FamilyIPv4,
			Port:                 Port,
			SNIMode:              SNIOmittedNoHostname,
			IdentityVerification: IdentityNotPerformedNoHostname,
		},
		Outcome:  probe.OutcomeSucceeded,
		Evidence: &evidence,
	}
}
