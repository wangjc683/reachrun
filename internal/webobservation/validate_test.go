package webobservation

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestResultJSONContract(t *testing.T) {
	t.Parallel()

	result := validHTTPResult()
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	want := `{"schema_version":1,"probe":"web_observation","observed_at":"2026-08-02T00:00:00Z","duration_ms":12,"platform":{"os":"testos","arch":"testarch"},"source":{"backend":"go-stdlib-http1-direct","capability":"native"},"input":{"scheme":"http","hostname":"example.com","dial_ip":"93.184.216.34","family":"ipv4","port":80,"method":"GET","path":"/"},"outcome":"succeeded","evidence":{"remote_endpoint":"93.184.216.34:80","tcp_connect_ms":3,"http":{"protocol":"HTTP/1.1","status_code":503,"ttfb_ms":8,"retry_after":"120"}}}`
	if string(encoded) != want {
		t.Fatalf("unexpected JSON contract\n got: %s\nwant: %s", encoded, want)
	}
	if strings.Contains(string(encoded), `"failure"`) || strings.Contains(string(encoded), `"tls"`) {
		t.Fatalf("HTTP success JSON includes an inapplicable optional field: %s", encoded)
	}
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsInconsistentHTTPResult(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"wrong probe": func(result *Result) {
			result.Probe = "other"
		},
		"unnormalized hostname": func(result *Result) {
			result.Input.Hostname = "Example.COM"
		},
		"wrong fixed port": func(result *Result) {
			result.Input.Port = 8080
		},
		"remote differs": func(result *Result) {
			result.Evidence.RemoteEndpoint = "93.184.216.35:80"
		},
		"remote is noncanonical": func(result *Result) {
			result.Evidence.RemoteEndpoint = "93.184.216.34:080"
		},
		"negative TCP timing": func(result *Result) {
			result.Evidence.TCPConnectMS = -1
		},
		"negative TTFB": func(result *Result) {
			result.Evidence.HTTP.TTFBMS = -1
		},
		"unsupported protocol": func(result *Result) {
			result.Evidence.HTTP.Protocol = "HTTP/2.0"
		},
		"invalid status": func(result *Result) {
			result.Evidence.HTTP.StatusCode = 700
		},
		"plain HTTP includes TLS": func(result *Result) {
			tlsResult := validHTTPSResult()
			result.Evidence.TLS = tlsResult.Evidence.TLS
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validHTTPResult()
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatalf("Validate(%#v) error = nil", result)
			}
		})
	}
}

func TestValidateRejectsInconsistentHTTPSResult(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"missing TLS": func(result *Result) {
			result.Evidence.TLS = nil
		},
		"server name differs": func(result *Result) {
			result.Evidence.TLS.ServerName = "other.example"
		},
		"no verified chains": func(result *Result) {
			result.Evidence.TLS.VerifiedChains = 0
		},
		"negative handshake timing": func(result *Result) {
			result.Evidence.TLS.HandshakeMS = -1
		},
		"unsupported ALPN": func(result *Result) {
			result.Evidence.TLS.ALPN = "h2"
		},
		"bad leaf hash": func(result *Result) {
			result.Evidence.TLS.Leaf.SHA256 = "not-a-hash"
		},
		"non UTC certificate time": func(result *Result) {
			result.Evidence.TLS.Leaf.NotBefore = time.Date(
				2026, 1, 1, 0, 0, 0, 0,
				time.FixedZone("offset", 3600),
			)
		},
		"reversed validity": func(result *Result) {
			result.Evidence.TLS.Leaf.NotBefore = result.Evidence.TLS.Leaf.NotAfter
		},
		"validity does not overlap attempt": func(result *Result) {
			result.Evidence.TLS.Leaf.NotBefore = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
			result.Evidence.TLS.Leaf.NotAfter = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
		},
		"stage timings exceed total": func(result *Result) {
			result.DurationMS = 14
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validHTTPSResult()
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatalf("Validate(%#v) error = nil", result)
			}
		})
	}
}

func TestValidateRejectsUnsupportedFailureAndInvalidInputMismatch(t *testing.T) {
	t.Parallel()

	unsupported := validHTTPResult()
	unsupported.Outcome = probe.OutcomeFailed
	unsupported.Evidence = nil
	unsupported.Failure = &probe.Failure{Code: "invented"}
	if err := Validate(unsupported); err == nil {
		t.Fatal("Validate(unsupported failure) error = nil")
	}

	validInputInvalidFailure := validHTTPResult()
	validInputInvalidFailure.Outcome = probe.OutcomeFailed
	validInputInvalidFailure.Evidence = nil
	validInputInvalidFailure.Failure = &probe.Failure{Code: probe.FailureInvalidInput}
	if err := Validate(validInputInvalidFailure); err == nil {
		t.Fatal("Validate(valid input with invalid_input) error = nil")
	}

	httpWithTLSFailure := validHTTPResult()
	httpWithTLSFailure.Outcome = probe.OutcomeFailed
	httpWithTLSFailure.Evidence = nil
	httpWithTLSFailure.Failure = &probe.Failure{Code: FailureTLSHandshake}
	if err := Validate(httpWithTLSFailure); err == nil {
		t.Fatal("Validate(HTTP input with TLS failure) error = nil")
	}

	invalidObserver := mustTestObserver(t, Config{}, dependencies{})
	invalid := invalidObserver.Observe(t.Context(), Request{
		Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "192.0.2.1",
	})
	if err := Validate(invalid); err != nil {
		t.Fatalf("Validate(real invalid_input) error = %v", err)
	}
}

func validHTTPResult() Result {
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		DurationMS:    12,
		Platform:      probe.Platform{OS: "testos", Arch: "testarch"},
		Source: probe.Source{
			Backend:    "go-stdlib-http1-direct",
			Capability: probe.CapabilityNative,
		},
		Input: Input{
			Scheme:   SchemeHTTP,
			Hostname: "example.com",
			DialIP:   testPublicIPv4,
			Family:   FamilyIPv4,
			Port:     80,
			Method:   "GET",
			Path:     "/",
		},
		Outcome: probe.OutcomeSucceeded,
		Evidence: &Evidence{
			RemoteEndpoint: testPublicIPv4 + ":80",
			TCPConnectMS:   3,
			HTTP: HTTPObservation{
				Protocol:   "HTTP/1.1",
				StatusCode: httpStatusServiceUnavailable,
				TTFBMS:     8,
				RetryAfter: "120",
			},
		},
	}
}

func validHTTPSResult() Result {
	result := validHTTPResult()
	result.DurationMS = 20
	result.Input.Scheme = SchemeHTTPS
	result.Input.Port = 443
	result.Evidence.RemoteEndpoint = testPublicIPv4 + ":443"
	result.Evidence.TLS = &TLSObservation{
		ServerName:     "example.com",
		Version:        "TLS1.3",
		CipherSuite:    "TLS_AES_128_GCM_SHA256",
		ALPN:           "http/1.1",
		HandshakeMS:    4,
		VerifiedChains: 1,
		Leaf: LeafCertificate{
			SHA256:    strings.Repeat("ab", 32),
			NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			NotAfter:  time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	return result
}

const httpStatusServiceUnavailable = 503
