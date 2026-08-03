package dnshttpspath

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/dnsobservation/dnsobservationtest"
	"github.com/wangjc683/reachrun/internal/probe"
)

var (
	testPlatform = probe.Platform{OS: "testos", Arch: "testarch"}
	testTime     = time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)
)

const (
	testResolver  dnsobservation.ResolverID = "test-resolver"
	testTransport dnsobservation.Transport  = dnsobservation.TransportUDP
	testEndpoint                            = "192.0.2.53:53"
)

func TestObserveFollowsAliasesAndResolvesUsableServiceTarget(t *testing.T) {
	t.Parallel()

	results := []dnsobservation.Result{
		httpsAlias("www.example.com", "alias-one.example.net"),
		httpsAlias("alias-one.example.net", "alias-two.example.net"),
		httpsService("alias-two.example.net", 1, "svc.example.net", []dnsobservation.ServiceParameter{
			{Key: serviceParamPort, Name: "port", ValueHex: "01bb"},
			{Key: serviceParamIPv4Hint, Name: "ipv4hint", ValueHex: "cb007109"},
		}),
		addressAnswer("svc.example.net", dnsobservation.QueryTypeA, "203.0.113.10"),
		dnsNoData("svc.example.net", dnsobservation.QueryTypeAAAA),
	}
	observer, scripted := newScriptedObserver(t, results...)

	result := observer.Observe(context.Background(), testRequest(" WWW.Example.COM. "))

	assertValidResult(t, result)
	if result.Status != StatusCompleted || result.Completion != CompletionServiceMode ||
		result.AliasesFollowed != 2 {
		t.Fatalf("terminal result = %#v, want completed two-alias ServiceMode", result)
	}
	if result.Input.Hostname != "www.example.com" {
		t.Fatalf("identity hostname = %q, want original normalized hostname", result.Input.Hostname)
	}
	wantBindings := []BindingDecision{{
		RecordIndex: 0, Priority: 1, AddressHostname: "svc.example.net",
		Usable: true, Reason: BindingUsable,
	}}
	if !reflect.DeepEqual(result.ServiceBindings, wantBindings) {
		t.Fatalf("service bindings = %#v, want %#v", result.ServiceBindings, wantBindings)
	}
	if len(result.AddressTargets) != 1 || result.AddressTargets[0].Hostname != "svc.example.net" ||
		result.AddressTargets[0].Source != TargetServiceMode ||
		len(result.AddressTargets[0].Observations) != 2 {
		t.Fatalf("address targets = %#v, want A/AAAA for ServiceMode target", result.AddressTargets)
	}

	wantCalls := []dnsobservationtest.Call{
		{Request: dnsRequest("www.example.com", dnsobservation.QueryTypeHTTPS)},
		{Request: dnsRequest("alias-one.example.net", dnsobservation.QueryTypeHTTPS)},
		{Request: dnsRequest("alias-two.example.net", dnsobservation.QueryTypeHTTPS)},
		{Request: dnsRequest("svc.example.net", dnsobservation.QueryTypeA)},
		{Request: dnsRequest("svc.example.net", dnsobservation.QueryTypeAAAA)},
	}
	if calls := scripted.Calls(); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("DNS calls = %#v, want same-resolver sequence %#v", calls, wantCalls)
	}
}

func TestObserveUsesAliasFallbackWhenFinalTargetHasNoHTTPSRecord(t *testing.T) {
	t.Parallel()

	observer, scripted := newScriptedObserver(t,
		httpsAlias("www.example.com", "fallback.example.net"),
		dnsNoData("fallback.example.net", dnsobservation.QueryTypeHTTPS),
		addressAnswer("fallback.example.net", dnsobservation.QueryTypeA, "203.0.113.20"),
		dnsNoData("fallback.example.net", dnsobservation.QueryTypeAAAA),
	)

	result := observer.Observe(context.Background(), testRequest("www.example.com"))

	assertValidResult(t, result)
	if result.Status != StatusCompleted || result.Completion != CompletionAliasFallback ||
		result.AliasesFollowed != 1 {
		t.Fatalf("terminal result = %#v, want completed alias fallback", result)
	}
	if len(result.AddressTargets) != 1 ||
		result.AddressTargets[0].Source != TargetAliasFallback ||
		result.AddressTargets[0].Hostname != "fallback.example.net" {
		t.Fatalf("address targets = %#v, want alias target fallback", result.AddressTargets)
	}
	wantCalls := []dnsobservationtest.Call{
		{Request: dnsRequest("www.example.com", dnsobservation.QueryTypeHTTPS)},
		{Request: dnsRequest("fallback.example.net", dnsobservation.QueryTypeHTTPS)},
		{Request: dnsRequest("fallback.example.net", dnsobservation.QueryTypeA)},
		{Request: dnsRequest("fallback.example.net", dnsobservation.QueryTypeAAAA)},
	}
	if calls := scripted.Calls(); !reflect.DeepEqual(calls, wantCalls) {
		t.Fatalf("DNS calls = %#v, want %#v", calls, wantCalls)
	}
}

func TestObserveStopsAliasLoopsAndLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		results    []dnsobservation.Result
		reason     StopReason
		aliasCount int
	}{
		{
			name: "loop",
			results: []dnsobservation.Result{
				httpsAlias("www.example.com", "alias.example.net"),
				httpsAlias("alias.example.net", "www.example.com"),
			},
			reason: StopAliasLoop, aliasCount: 1,
		},
		{
			name: "limit",
			results: []dnsobservation.Result{
				httpsAlias("www.example.com", "one.example.net"),
				httpsAlias("one.example.net", "two.example.net"),
				httpsAlias("two.example.net", "three.example.net"),
				httpsAlias("three.example.net", "four.example.net"),
			},
			reason: StopAliasLimit, aliasCount: aliasLimit,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observer, scripted := newScriptedObserver(t, test.results...)

			result := observer.Observe(context.Background(), testRequest("www.example.com"))

			assertValidResult(t, result)
			if result.Status != StatusStopped || result.StopReason != test.reason ||
				result.AliasesFollowed != test.aliasCount {
				t.Fatalf("terminal result = %#v, want stopped %q after %d aliases", result, test.reason, test.aliasCount)
			}
			if len(result.AddressTargets) != 0 || scripted.Remaining() != 0 {
				t.Fatalf("unexpected address work or scripted remainder: %#v / %d", result.AddressTargets, scripted.Remaining())
			}
		})
	}
}

func TestObserveCompletesUnsupportedServiceModeWithoutAddressQueries(t *testing.T) {
	t.Parallel()

	observer, scripted := newScriptedObserver(t,
		httpsService("www.example.com", 1, "svc.example.net", []dnsobservation.ServiceParameter{
			{Key: serviceParamMandatory, Name: "mandatory", ValueHex: "0009"},
			{Key: 9, Name: "tls-supported-groups", ValueHex: "001d"},
		}),
	)

	result := observer.Observe(context.Background(), testRequest("www.example.com"))

	assertValidResult(t, result)
	if result.Status != StatusCompleted || result.Completion != CompletionUnsupportedServiceMode ||
		len(result.ServiceBindings) != 1 || result.ServiceBindings[0].Usable ||
		result.ServiceBindings[0].Reason != BindingUnsupportedParameters ||
		!reflect.DeepEqual(result.ServiceBindings[0].UnsupportedParameterKeys, []uint16{9}) {
		t.Fatalf("terminal result = %#v, want unsupported mandatory key 9", result)
	}
	if len(result.AddressTargets) != 0 || len(scripted.Calls()) != 1 {
		t.Fatalf("unsupported mode performed address queries: calls=%#v", scripted.Calls())
	}
}

func TestObserveQueriesAllDistinctUsableServiceTargetsByPriority(t *testing.T) {
	t.Parallel()

	first := httpsServices("www.example.com", []dnsobservation.Record{
		serviceRecord("www.example.com", 2, "later.example.net", nil),
		serviceRecord("www.example.com", 1, ".", nil),
		serviceRecord("www.example.com", 3, "later.example.net", nil),
	})
	observer, scripted := newScriptedObserver(t,
		first,
		addressAnswer("www.example.com", dnsobservation.QueryTypeA, "203.0.113.30"),
		dnsNoData("www.example.com", dnsobservation.QueryTypeAAAA),
		addressAnswer("later.example.net", dnsobservation.QueryTypeA, "203.0.113.31"),
		dnsNoData("later.example.net", dnsobservation.QueryTypeAAAA),
	)

	result := observer.Observe(context.Background(), testRequest("www.example.com"))

	assertValidResult(t, result)
	if len(result.AddressTargets) != 2 ||
		result.AddressTargets[0].Hostname != "www.example.com" || result.AddressTargets[0].Priority != 1 ||
		result.AddressTargets[1].Hostname != "later.example.net" || result.AddressTargets[1].Priority != 2 {
		t.Fatalf("priority/deduped targets = %#v", result.AddressTargets)
	}
	if len(scripted.Calls()) != 5 {
		t.Fatalf("DNS calls = %#v, want HTTPS plus two A/AAAA target pairs", scripted.Calls())
	}
}

func TestObserveBoundsServiceTargetsAndReportsOmittedCount(t *testing.T) {
	t.Parallel()

	records := make([]dnsobservation.Record, 0, serviceTargetLimit+2)
	results := make([]dnsobservation.Result, 0, 1+serviceTargetLimit*2)
	for index := 0; index < serviceTargetLimit+2; index++ {
		hostname := fmt.Sprintf("svc-%02d.example.net", index)
		records = append(records, serviceRecord("www.example.com", uint16(index+1), hostname, nil))
	}
	results = append(results, httpsServices("www.example.com", records))
	for index := 0; index < serviceTargetLimit; index++ {
		hostname := fmt.Sprintf("svc-%02d.example.net", index)
		results = append(
			results,
			dnsNoData(hostname, dnsobservation.QueryTypeA),
			dnsNoData(hostname, dnsobservation.QueryTypeAAAA),
		)
	}
	observer, scripted := newScriptedObserver(t, results...)

	result := observer.Observe(context.Background(), testRequest("www.example.com"))

	assertValidResult(t, result)
	if result.Status != StatusCompleted || result.Completion != CompletionServiceMode ||
		len(result.ServiceBindings) != serviceTargetLimit+2 ||
		len(result.AddressTargets) != serviceTargetLimit || result.ServiceTargetsOmitted != 2 {
		t.Fatalf("bounded service targets = %#v", result)
	}
	if len(scripted.Calls()) != 1+serviceTargetLimit*2 {
		t.Fatalf("DNS calls = %d, want bounded %d", len(scripted.Calls()), 1+serviceTargetLimit*2)
	}
}

func TestObservePreservesFailedAndIncompleteAddressEvidence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result dnsobservation.Result
		reason StopReason
	}{
		{
			name:   "failed",
			result: dnsFailure("www.example.com", dnsobservation.QueryTypeA, probe.OutcomeFailed, dnsobservation.FailureDNSTransport),
			reason: StopDNSObservationFailed,
		},
		{
			name:   "incomplete",
			result: dnsIncomplete("www.example.com", dnsobservation.QueryTypeA),
			reason: StopDNSObservationIncomplete,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observer, _ := newScriptedObserver(t,
				dnsNoData("www.example.com", dnsobservation.QueryTypeHTTPS),
				test.result,
				dnsNoData("www.example.com", dnsobservation.QueryTypeAAAA),
			)

			result := observer.Observe(context.Background(), testRequest("www.example.com"))

			assertValidResult(t, result)
			if result.Status != StatusStopped || result.StopReason != test.reason ||
				len(result.AddressTargets) != 1 || len(result.AddressTargets[0].Observations) != 2 {
				t.Fatalf("terminal result = %#v, want partial address evidence with %q", result, test.reason)
			}
		})
	}
}

func TestObserveRejectsInvalidInputAndLateEvidence(t *testing.T) {
	t.Parallel()

	t.Run("invalid input", func(t *testing.T) {
		t.Parallel()
		observer, scripted := newScriptedObserver(t)
		result := observer.Observe(context.Background(), Request{
			Hostname: "https://example.com", Resolver: testResolver, Transport: testTransport,
		})
		assertValidResult(t, result)
		if result.Status != StatusStopped || result.StopReason != StopInvalidInput || len(scripted.Calls()) != 0 {
			t.Fatalf("invalid input result/calls = %#v / %#v", result, scripted.Calls())
		}
	})

	t.Run("parent cancelled", func(t *testing.T) {
		t.Parallel()
		observer, scripted := newScriptedObserver(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := observer.Observe(ctx, testRequest("www.example.com"))
		assertValidResult(t, result)
		if result.Status != StatusCancelled || result.StopReason != StopCancelled || len(scripted.Calls()) != 0 {
			t.Fatalf("cancelled result/calls = %#v / %#v", result, scripted.Calls())
		}
	})

	t.Run("resolver identity changes", func(t *testing.T) {
		t.Parallel()
		changed := addressAnswer("www.example.com", dnsobservation.QueryTypeA, "203.0.113.40")
		changed.Input.Resolver.Endpoint = "192.0.2.54:53"
		changed.Evidence.RemoteEndpoint = "192.0.2.54:53"
		observer, _ := newScriptedObserver(t,
			dnsNoData("www.example.com", dnsobservation.QueryTypeHTTPS),
			changed,
		)
		result := observer.Observe(context.Background(), testRequest("www.example.com"))
		assertValidResult(t, result)
		if result.Status != StatusStopped || result.StopReason != StopInvalidProbeEvidence ||
			len(result.AddressTargets) != 1 || len(result.AddressTargets[0].Observations) != 0 {
			t.Fatalf("resolver identity change result = %#v", result)
		}
	})

	t.Run("invalid probe evidence", func(t *testing.T) {
		t.Parallel()
		observer, _ := newScriptedObserver(t, dnsobservation.Result{})
		result := observer.Observe(context.Background(), testRequest("www.example.com"))
		assertValidResult(t, result)
		if result.Status != StatusStopped || result.StopReason != StopInvalidProbeEvidence ||
			len(result.HTTPSObservations) != 0 {
			t.Fatalf("invalid probe result = %#v", result)
		}
	})
}

func TestResultJSONUsesArraysAndStableOperation(t *testing.T) {
	t.Parallel()

	observer, _ := newScriptedObserver(t,
		dnsNoData("www.example.com", dnsobservation.QueryTypeHTTPS),
		dnsNoData("www.example.com", dnsobservation.QueryTypeA),
		dnsNoData("www.example.com", dnsobservation.QueryTypeAAAA),
	)
	result := observer.Observe(context.Background(), testRequest("www.example.com"))
	assertValidResult(t, result)

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	text := string(encoded)
	for _, fragment := range []string{
		`"operation":"dns_https_path"`,
		`"https_observations":[`,
		`"service_bindings":[]`,
		`"address_targets":[`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("JSON %s does not contain %s", text, fragment)
		}
	}
}

func newScriptedObserver(
	t *testing.T,
	results ...dnsobservation.Result,
) (*observer, *dnsobservationtest.Scripted) {
	t.Helper()
	scripted := dnsobservationtest.New(results...)
	created, err := newObserver(Config{Timeout: time.Second}, dependencies{
		now:      func() time.Time { return testTime },
		platform: testPlatform,
		dns:      scripted,
	})
	if err != nil {
		t.Fatalf("newObserver() error = %v", err)
	}
	return created, scripted
}

func testRequest(hostname string) Request {
	return Request{Hostname: hostname, Resolver: testResolver, Transport: testTransport}
}

func dnsRequest(hostname string, queryType dnsobservation.QueryType) dnsobservation.Request {
	return dnsobservation.Request{
		Hostname: hostname, QueryType: queryType, Resolver: testResolver, Transport: testTransport,
	}
}

func httpsAlias(hostname, target string) dnsobservation.Result {
	return dnsSuccess(hostname, dnsobservation.QueryTypeHTTPS, hostname, []dnsobservation.Record{{
		Name: hostname, Type: dnsobservation.QueryTypeHTTPS, TTL: 60,
		Service: &dnsobservation.ServiceBinding{
			Priority: 0, Target: target, Mode: dnsobservation.ServiceBindingAlias,
			Params: []dnsobservation.ServiceParameter{},
		},
	}}, dnsobservation.AnswerKindAnswer)
}

func httpsService(
	hostname string,
	priority uint16,
	target string,
	params []dnsobservation.ServiceParameter,
) dnsobservation.Result {
	return httpsServices(hostname, []dnsobservation.Record{
		serviceRecord(hostname, priority, target, params),
	})
}

func httpsServices(hostname string, records []dnsobservation.Record) dnsobservation.Result {
	return dnsSuccess(
		hostname,
		dnsobservation.QueryTypeHTTPS,
		hostname,
		records,
		dnsobservation.AnswerKindAnswer,
	)
}

func serviceRecord(
	hostname string,
	priority uint16,
	target string,
	params []dnsobservation.ServiceParameter,
) dnsobservation.Record {
	if params == nil {
		params = []dnsobservation.ServiceParameter{}
	}
	return dnsobservation.Record{
		Name: hostname, Type: dnsobservation.QueryTypeHTTPS, TTL: 60,
		Service: &dnsobservation.ServiceBinding{
			Priority: priority, Target: target, Mode: dnsobservation.ServiceBindingService,
			Params: params,
		},
	}
}

func addressAnswer(
	hostname string,
	queryType dnsobservation.QueryType,
	address string,
) dnsobservation.Result {
	record := dnsobservation.Record{Name: hostname, Type: queryType, TTL: 60, Address: address}
	if queryType == dnsobservation.QueryTypeA {
		record.Family = dnsobservation.IPFamilyIPv4
	} else {
		record.Family = dnsobservation.IPFamilyIPv6
	}
	return dnsSuccess(
		hostname,
		queryType,
		hostname,
		[]dnsobservation.Record{record},
		dnsobservation.AnswerKindAnswer,
	)
}

func dnsNoData(hostname string, queryType dnsobservation.QueryType) dnsobservation.Result {
	return dnsSuccess(
		hostname,
		queryType,
		hostname,
		[]dnsobservation.Record{},
		dnsobservation.AnswerKindNoData,
	)
}

func dnsIncomplete(hostname string, queryType dnsobservation.QueryType) dnsobservation.Result {
	result := dnsNoData(hostname, queryType)
	result.Evidence.AnswerKind = dnsobservation.AnswerKindIncomplete
	result.Evidence.Flags.Truncated = true
	return result
}

func dnsSuccess(
	hostname string,
	queryType dnsobservation.QueryType,
	effectiveName string,
	records []dnsobservation.Record,
	kind dnsobservation.AnswerKind,
) dnsobservation.Result {
	evidence := dnsobservation.Evidence{
		RCode: dnsobservation.ResponseCode{Code: 0, Name: "NOERROR"},
		Flags: dnsobservation.ResponseFlags{
			RecursionDesired: true, RecursionAvailable: true,
		},
		AnswerKind: kind, EffectiveName: effectiveName, Records: records,
		ResponseBytes: 64, RemoteEndpoint: testEndpoint,
	}
	return dnsResult(
		hostname,
		queryType,
		probe.OutcomeSucceeded,
		&evidence,
		nil,
	)
}

func dnsFailure(
	hostname string,
	queryType dnsobservation.QueryType,
	outcome probe.Outcome,
	code probe.FailureCode,
) dnsobservation.Result {
	return dnsResult(
		hostname,
		queryType,
		outcome,
		nil,
		&probe.Failure{Code: code, Detail: "scripted DNS failure"},
	)
}

func dnsResult(
	hostname string,
	queryType dnsobservation.QueryType,
	outcome probe.Outcome,
	evidence *dnsobservation.Evidence,
	failure *probe.Failure,
) dnsobservation.Result {
	return dnsobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         dnsobservation.ProbeKind,
		ObservedAt:    testTime,
		DurationMS:    1,
		Platform:      testPlatform,
		Source: probe.Source{
			Backend: "scripted-dns", Capability: probe.CapabilityNative,
		},
		Input: dnsobservation.Input{
			Hostname: hostname, QueryType: queryType, Class: "IN",
			Resolver:  dnsobservation.ResolverInput{ID: testResolver, Endpoint: testEndpoint},
			Transport: testTransport,
		},
		Outcome: outcome, Evidence: evidence, Failure: failure,
	}
}

func assertValidResult(t *testing.T, result Result) {
	t.Helper()
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v; result = %#v", err, result)
	}
}
