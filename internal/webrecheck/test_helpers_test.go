package webrecheck

import (
	"net/netip"
	"strings"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

var (
	testObservedAt = time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
	testPlatform   = probe.Platform{OS: "testos", Arch: "testarch"}
	testSource     = probe.Source{Backend: "scripted-web", Capability: probe.CapabilityNative}
)

func successfulObservation(ip string) webobservation.Result {
	input := observationInput(ip)
	evidence := webobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(ip), httpsPort).String(),
		TCPConnectMS:   1,
		TLS: &webobservation.TLSObservation{
			ServerName:     input.Hostname,
			Version:        "TLS1.3",
			CipherSuite:    "TLS_AES_128_GCM_SHA256",
			ALPN:           "http/1.1",
			HandshakeMS:    2,
			VerifiedChains: 1,
			Leaf: webobservation.LeafCertificate{
				SHA256:    strings.Repeat("ab", 32),
				NotBefore: testObservedAt.Add(-time.Hour),
				NotAfter:  testObservedAt.Add(time.Hour),
			},
		},
		HTTP: webobservation.HTTPObservation{
			Protocol: "HTTP/1.1", StatusCode: 200, TTFBMS: 3,
		},
	}
	return webobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         webobservation.ProbeKind,
		ObservedAt:    testObservedAt,
		DurationMS:    10,
		Platform:      testPlatform,
		Source:        testSource,
		Input:         input,
		Outcome:       probe.OutcomeSucceeded,
		Evidence:      &evidence,
	}
}

func failedObservation(ip string) webobservation.Result {
	return webobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         webobservation.ProbeKind,
		ObservedAt:    testObservedAt,
		DurationMS:    4,
		Platform:      testPlatform,
		Source:        testSource,
		Input:         observationInput(ip),
		Outcome:       probe.OutcomeFailed,
		Failure: &probe.Failure{
			Code: webobservation.FailureTCPConnectionRefused,
		},
	}
}

func cancelledObservation(ip string) webobservation.Result {
	return webobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         webobservation.ProbeKind,
		ObservedAt:    testObservedAt,
		DurationMS:    1,
		Platform:      testPlatform,
		Source:        testSource,
		Input:         observationInput(ip),
		Outcome:       probe.OutcomeCancelled,
		Failure:       &probe.Failure{Code: probe.FailureCancelled},
	}
}

func observationInput(ip string) webobservation.Input {
	family := webobservation.FamilyIPv6
	if netip.MustParseAddr(ip).Is4() {
		family = webobservation.FamilyIPv4
	}
	return webobservation.Input{
		Scheme:   webobservation.SchemeHTTPS,
		Hostname: "example.com",
		DialIP:   ip,
		Family:   family,
		Port:     httpsPort,
		Method:   httpMethod,
		Path:     httpPath,
	}
}
