package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/browserplaceholder"
	"github.com/wangjc683/reachrun/internal/browserplaceholder/browserplaceholdertest"
	"github.com/wangjc683/reachrun/internal/dnshttpspath"
	"github.com/wangjc683/reachrun/internal/dnshttpspath/dnshttpspathtest"
	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/dnsobservation/dnsobservationtest"
	"github.com/wangjc683/reachrun/internal/platform/browseropener"
	"github.com/wangjc683/reachrun/internal/platform/familycondition"
	"github.com/wangjc683/reachrun/internal/platform/familycondition/familyconditiontest"
	"github.com/wangjc683/reachrun/internal/platform/resolverinventory"
	"github.com/wangjc683/reachrun/internal/platform/resolverinventory/resolverinventorytest"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver/systemresolvertest"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/sshobservation"
	"github.com/wangjc683/reachrun/internal/sshobservation/sshobservationtest"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
	"github.com/wangjc683/reachrun/internal/tlsobservation/tlsobservationtest"
	"github.com/wangjc683/reachrun/internal/tlsretrybatch"
	"github.com/wangjc683/reachrun/internal/tlsretrybatch/tlsretrybatchtest"
	"github.com/wangjc683/reachrun/internal/webobservation"
	"github.com/wangjc683/reachrun/internal/webobservation/webobservationtest"
	"github.com/wangjc683/reachrun/internal/webpath"
	"github.com/wangjc683/reachrun/internal/webpath/webpathtest"
	"github.com/wangjc683/reachrun/internal/webrecheck"
	"github.com/wangjc683/reachrun/internal/webrecheck/webrechecktest"
)

func TestRunBrowserPlaceholderMapsTerminalReportsAndFallback(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		step         browserplaceholdertest.Step
		code         int
		wantFallback bool
	}{
		"browser command and page request completed": {
			step: browserplaceholdertest.Step{Result: cliBrowserPlaceholderCompletedResult(false)},
			code: 0,
		},
		"terminal fallback and page request completed": {
			step: browserplaceholdertest.Step{
				Fallback: cliBrowserPlaceholderFallback(),
				Result:   cliBrowserPlaceholderCompletedResult(true),
			},
			code:         0,
			wantFallback: true,
		},
		"placeholder timeout": {
			step: browserplaceholdertest.Step{Result: cliBrowserPlaceholderStoppedResult()},
			code: 1,
		},
		"cancelled": {
			step: browserplaceholdertest.Step{Result: cliBrowserPlaceholderCancelledResult()},
			code: 130,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := browserplaceholdertest.New(test.step)
			factory := &scriptedBrowserPlaceholderFactory{runner: runner}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := run(
				context.Background(),
				[]string{"browser-placeholder"},
				&stdout,
				&stderr,
				dependencies{newBrowserPlaceholderRunner: factory.New},
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d", code, test.code)
			}
			if test.wantFallback {
				if !strings.Contains(stderr.String(), "default browser did not open (launch_failed)") ||
					!strings.Contains(stderr.String(), cliBrowserPlaceholderURL) {
					t.Fatalf("stderr = %q, want fallback URL", stderr.String())
				}
			} else if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			decoded := decodeOneJSON[browserplaceholder.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.step.Result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.step.Result)
			}
			if runner.Calls() != 1 || runner.Remaining() != 0 {
				t.Fatalf("runner calls/remaining = %d/%d, want 1/0", runner.Calls(), runner.Remaining())
			}
			if config := factory.singleConfig(t); config.Timeout != phase0BrowserPlaceholderTimeout {
				t.Fatalf("browser-placeholder timeout = %s, want %s", config.Timeout, phase0BrowserPlaceholderTimeout)
			}
		})
	}
}

func TestRunReportsBrowserPlaceholderFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedBrowserPlaceholderFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"browser-placeholder"},
		&stdout,
		&stderr,
		dependencies{newBrowserPlaceholderRunner: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run/stdout = %d/%q, want 1/empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create browser-placeholder runner: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if config := factory.singleConfig(t); config.Timeout != phase0BrowserPlaceholderTimeout {
		t.Fatalf("browser-placeholder timeout = %s, want %s", config.Timeout, phase0BrowserPlaceholderTimeout)
	}
}

func TestRunFamilyConditionsPrintsOneEnvelopeAndReturnsOutcomeExitCode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result familycondition.Result
		code   int
	}{
		"selected IPv4 and unavailable IPv6": {
			result: cliFamilyConditionsSuccessResult(),
			code:   0,
		},
		"route check failure": {
			result: cliFamilyConditionsFailureResult(
				probe.OutcomeFailed,
				familycondition.FailureRouteCheck,
			),
			code: 1,
		},
		"cancelled": {
			result: cliFamilyConditionsFailureResult(
				probe.OutcomeCancelled,
				probe.FailureCancelled,
			),
			code: 130,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			observer := familyconditiontest.New(test.result)
			factory := &scriptedFamilyConditionFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"family-conditions"},
				&stdout,
				&stderr,
				dependencies{newFamilyConditionObserver: factory.New},
			)
			if code != test.code || stderr.Len() != 0 {
				t.Fatalf("run/stderr = %d/%q, want %d/empty", code, stderr.String(), test.code)
			}
			decoded := decodeOneJSON[familycondition.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			if got := len(observer.Calls()); got != 1 {
				t.Fatalf("family-condition calls = %d, want 1", got)
			}
			if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
				t.Fatalf("family-condition timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
			}
		})
	}
}

func TestRunReportsFamilyConditionObserverFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedFamilyConditionFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"family-conditions"},
		&stdout,
		&stderr,
		dependencies{newFamilyConditionObserver: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run/stdout = %d/%q, want 1/empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create address-family-condition observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
		t.Fatalf("family-condition timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
	}
}

func TestRunResolvePrintsOneEnvelopeAndReturnsOutcomeExitCode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result systemresolver.Result
		code   int
	}{
		"succeeded": {
			result: cliSystemResolverSuccessResult(),
			code:   0,
		},
		"failed": {
			result: cliSystemResolverFailureResult(probe.OutcomeFailed, probe.FailureNameUnresolved),
			code:   1,
		},
		"cancelled": {
			result: cliSystemResolverFailureResult(probe.OutcomeCancelled, probe.FailureCancelled),
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
				dependencies{systemResolver: resolver},
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d", code, test.code)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}

			decoded := decodeOneJSON[systemresolver.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			wantCalls := []systemresolvertest.Call{{Hostname: "example.com"}}
			if got := resolver.Calls(); !reflect.DeepEqual(got, wantCalls) {
				t.Fatalf("calls = %#v, want %#v", got, wantCalls)
			}
		})
	}
}

func TestRunResolverInventoryPrintsOneEnvelopeAndReturnsOutcomeExitCode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result resolverinventory.Result
		code   int
	}{
		"succeeded": {
			result: cliInventorySuccessResult(resolverinventory.Group{
				Scope:   resolverinventory.ScopeGlobal,
				Servers: []resolverinventory.Server{{Address: "192.0.2.53", Port: 53}},
			}),
			code: 0,
		},
		"failed": {
			result: cliInventoryFailureResult(probe.OutcomeFailed, resolverinventory.FailureUnavailable),
			code:   1,
		},
		"cancelled": {
			result: cliInventoryFailureResult(probe.OutcomeCancelled, probe.FailureCancelled),
			code:   130,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			observer := resolverinventorytest.New(test.result)
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"resolver-inventory"},
				&stdout,
				&stderr,
				dependencies{resolverInventory: observer},
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d", code, test.code)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}

			decoded := decodeOneJSON[resolverinventory.Result](t, stdout.Bytes())
			if err := resolverinventory.Validate(decoded); err != nil {
				t.Fatalf("decoded inventory Validate() error = %v", err)
			}
			if decoded.Outcome != test.result.Outcome || decoded.Probe != test.result.Probe {
				t.Fatalf(
					"decoded terminal = %q/%q, want %q/%q",
					decoded.Probe,
					decoded.Outcome,
					test.result.Probe,
					test.result.Outcome,
				)
			}
			if got := len(observer.Calls()); got != 1 {
				t.Fatalf("inventory calls = %d, want 1", got)
			}
		})
	}
}

func TestRunDNSObservationMapsFixedProvidersTransportsAndQueryTypes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport dnsobservation.Transport
		provider  string
		queryType dnsobservation.QueryType
		resolver  dnsobservation.ResolverID
		endpoint  string
	}{
		{
			name: "cloudflare udp A", transport: dnsobservation.TransportUDP,
			provider: "cloudflare", queryType: dnsobservation.QueryTypeA,
			resolver: resolverCloudflareWire, endpoint: "1.1.1.1:53",
		},
		{
			name: "cloudflare tcp AAAA", transport: dnsobservation.TransportTCP,
			provider: "cloudflare", queryType: dnsobservation.QueryTypeAAAA,
			resolver: resolverCloudflareWire, endpoint: "1.1.1.1:53",
		},
		{
			name: "cloudflare doh CNAME", transport: dnsobservation.TransportDoH,
			provider: "cloudflare", queryType: dnsobservation.QueryTypeCNAME,
			resolver: resolverCloudflareDoH, endpoint: "https://cloudflare-dns.com/dns-query",
		},
		{
			name: "google udp AAAA", transport: dnsobservation.TransportUDP,
			provider: "google", queryType: dnsobservation.QueryTypeAAAA,
			resolver: resolverGoogleWire, endpoint: "8.8.8.8:53",
		},
		{
			name: "google tcp CNAME", transport: dnsobservation.TransportTCP,
			provider: "google", queryType: dnsobservation.QueryTypeCNAME,
			resolver: resolverGoogleWire, endpoint: "8.8.8.8:53",
		},
		{
			name: "google doh A", transport: dnsobservation.TransportDoH,
			provider: "google", queryType: dnsobservation.QueryTypeA,
			resolver: resolverGoogleDoH, endpoint: "https://dns.google/dns-query",
		},
		{
			name: "cloudflare udp HTTPS", transport: dnsobservation.TransportUDP,
			provider: "cloudflare", queryType: dnsobservation.QueryTypeHTTPS,
			resolver: resolverCloudflareWire, endpoint: "1.1.1.1:53",
		},
		{
			name: "google doh SVCB", transport: dnsobservation.TransportDoH,
			provider: "google", queryType: dnsobservation.QueryTypeSVCB,
			resolver: resolverGoogleDoH, endpoint: "https://dns.google/dns-query",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := cliDNSSuccessResult(
				"example.com",
				test.queryType,
				test.resolver,
				test.transport,
				test.endpoint,
			)
			observer := dnsobservationtest.New(result)
			factory := &scriptedDNSFactory{observer: observer}
			inventory := resolverinventorytest.New()
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{
					"dns-observe",
					string(test.transport),
					test.provider,
					string(test.queryType),
					"example.com",
				},
				&stdout,
				&stderr,
				dependencies{
					resolverInventory: inventory,
					newDNSObserver:    factory.New,
				},
			)
			if code != 0 {
				t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			decoded := decodeOneJSON[dnsobservation.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, result)
			}

			wantRequest := dnsobservation.Request{
				Hostname:  "example.com",
				QueryType: test.queryType,
				Resolver:  test.resolver,
				Transport: test.transport,
			}
			wantCalls := []dnsobservationtest.Call{{Request: wantRequest}}
			if got := observer.Calls(); !reflect.DeepEqual(got, wantCalls) {
				t.Fatalf("DNS calls = %#v, want %#v", got, wantCalls)
			}
			if len(inventory.Calls()) != 0 {
				t.Fatalf("inventory calls = %#v, want none", inventory.Calls())
			}
			assertReferenceResolverConfig(t, factory.singleConfig(t))
		})
	}
}

func TestRunDNSObservationTreatsDNSNegativeAndServerResponsesAsSuccess(t *testing.T) {
	t.Parallel()

	tests := map[string]dnsobservation.Evidence{
		"NXDOMAIN": {
			RCode:          dnsobservation.ResponseCode{Code: 3, Name: "NXDOMAIN"},
			AnswerKind:     dnsobservation.AnswerKindNameError,
			EffectiveName:  "example.com",
			ResponseBytes:  42,
			RemoteEndpoint: "1.1.1.1:53",
		},
		"NODATA": {
			RCode:          dnsobservation.ResponseCode{Code: 0, Name: "NOERROR"},
			AnswerKind:     dnsobservation.AnswerKindNoData,
			EffectiveName:  "example.com",
			ResponseBytes:  42,
			RemoteEndpoint: "1.1.1.1:53",
		},
		"SERVFAIL": {
			RCode:          dnsobservation.ResponseCode{Code: 2, Name: "SERVFAIL"},
			AnswerKind:     dnsobservation.AnswerKindRCodeError,
			EffectiveName:  "example.com",
			ResponseBytes:  42,
			RemoteEndpoint: "1.1.1.1:53",
		},
	}

	for name, evidence := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := cliDNSResult(
				probe.OutcomeSucceeded,
				cliDNSInput(
					"example.com",
					dnsobservation.QueryTypeA,
					resolverCloudflareWire,
					dnsobservation.TransportUDP,
					"1.1.1.1:53",
				),
				&evidence,
				nil,
			)
			observer := dnsobservationtest.New(result)
			factory := &scriptedDNSFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"dns-observe", "udp", "cloudflare", "A", "example.com"},
				&stdout,
				&stderr,
				dependencies{newDNSObserver: factory.New},
			)
			if code != 0 {
				t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
			}
			decodeOneJSON[dnsobservation.Result](t, stdout.Bytes())
		})
	}
}

func TestRunDNSObservationReturnsFailureAndCancellationExitCodes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		result dnsobservation.Result
		code   int
	}{
		"failed": {
			result: cliDNSFailureResult(
				probe.OutcomeFailed,
				dnsobservation.FailureDNSTransport,
				resolverCloudflareWire,
				"1.1.1.1:53",
			),
			code: 1,
		},
		"cancelled": {
			result: cliDNSFailureResult(
				probe.OutcomeCancelled,
				probe.FailureCancelled,
				resolverCloudflareWire,
				"1.1.1.1:53",
			),
			code: 130,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			factory := &scriptedDNSFactory{observer: dnsobservationtest.New(test.result)}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"dns-observe", "udp", "cloudflare", "A", "example.com"},
				&stdout,
				&stderr,
				dependencies{newDNSObserver: factory.New},
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d", code, test.code)
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			decoded := decodeOneJSON[dnsobservation.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
		})
	}
}

func TestRunDNSObservationSelectsCurrentResolverAndIPv6Zone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		transport      dnsobservation.Transport
		server         resolverinventory.Server
		groupInterface string
		interfaceIndex uint32
		wantAddress    string
	}{
		{
			name: "IPv4 over TCP", transport: dnsobservation.TransportTCP,
			server:      resolverinventory.Server{Address: "192.0.2.53", Port: 53},
			wantAddress: "192.0.2.53",
		},
		{
			name: "ordinary IPv6 ignores zone", transport: dnsobservation.TransportUDP,
			server:         resolverinventory.Server{Address: "2001:db8::53", Port: 53, Zone: "ignored"},
			groupInterface: "en0", interfaceIndex: 7,
			wantAddress: "2001:db8::53",
		},
		{
			name: "link-local uses server zone first", transport: dnsobservation.TransportUDP,
			server:         resolverinventory.Server{Address: "fe80::53", Port: 53, Zone: "server-zone"},
			groupInterface: "en0", interfaceIndex: 7,
			wantAddress: "fe80::53%server-zone",
		},
		{
			name: "link-local falls back to interface", transport: dnsobservation.TransportUDP,
			server:         resolverinventory.Server{Address: "fe80::53", Port: 53},
			groupInterface: "en0", interfaceIndex: 7,
			wantAddress: "fe80::53%en0",
		},
		{
			name: "link-local falls back to interface index", transport: dnsobservation.TransportUDP,
			server:         resolverinventory.Server{Address: "fe80::53", Port: 53},
			interfaceIndex: 7,
			wantAddress:    "fe80::53%7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			inventoryResult := cliInventorySuccessResult(resolverinventory.Group{
				Scope:          resolverinventory.ScopeGlobal,
				Servers:        []resolverinventory.Server{test.server},
				Interface:      test.groupInterface,
				InterfaceIndex: test.interfaceIndex,
			})
			inventory := resolverinventorytest.New(inventoryResult)
			wantAddress := netip.MustParseAddr(test.wantAddress)
			result := cliDNSSuccessResult(
				"example.com",
				dnsobservation.QueryTypeA,
				resolverCurrent,
				test.transport,
				netip.AddrPortFrom(wantAddress, 53).String(),
			)
			observer := dnsobservationtest.New(result)
			factory := &scriptedDNSFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{
					"dns-observe",
					string(test.transport),
					"current",
					"A",
					"example.com",
				},
				&stdout,
				&stderr,
				dependencies{
					resolverInventory: inventory,
					newDNSObserver:    factory.New,
				},
			)
			if code != 0 {
				t.Fatalf("run() = %d, want 0; stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			decodeOneJSON[dnsobservation.Result](t, stdout.Bytes())
			if got := len(inventory.Calls()); got != 1 {
				t.Fatalf("inventory calls = %d, want 1", got)
			}

			config := factory.singleConfig(t)
			assertReferenceResolverConfig(t, dnsobservation.Config{
				Resolvers: config.Resolvers[:4],
				Timeout:   config.Timeout,
			})
			if len(config.Resolvers) != 5 {
				t.Fatalf("configured resolvers = %d, want 5", len(config.Resolvers))
			}
			current := config.Resolvers[4]
			if current.ID != resolverCurrent || current.WireIP != wantAddress {
				t.Fatalf("current endpoint = %#v, want %q/%q", current, resolverCurrent, wantAddress)
			}
			wantRequest := dnsobservation.Request{
				Hostname:  "example.com",
				QueryType: dnsobservation.QueryTypeA,
				Resolver:  resolverCurrent,
				Transport: test.transport,
			}
			if got := observer.Calls(); !reflect.DeepEqual(got, []dnsobservationtest.Call{{Request: wantRequest}}) {
				t.Fatalf("DNS calls = %#v, want request %#v", got, wantRequest)
			}
		})
	}
}

func TestCurrentResolverEndpointSelectsFirstUsablePort53Server(t *testing.T) {
	t.Parallel()

	result := cliInventorySuccessResult(
		resolverinventory.Group{
			Scope: resolverinventory.ScopeGlobal,
			Servers: []resolverinventory.Server{
				{Address: "192.0.2.1", Port: 5353},
				{Address: "224.0.0.251", Port: 53},
			},
		},
		resolverinventory.Group{
			Scope:   resolverinventory.ScopeScoped,
			Servers: []resolverinventory.Server{{Address: "192.0.2.53", Port: 53}},
		},
	)

	endpoint, err := currentResolverEndpoint(result)
	if err != nil {
		t.Fatalf("currentResolverEndpoint() error = %v", err)
	}
	want := netip.MustParseAddr("192.0.2.53")
	if endpoint.ID != resolverCurrent || endpoint.WireIP != want {
		t.Fatalf("endpoint = %#v, want %q/%q", endpoint, resolverCurrent, want)
	}
}

func TestRunDNSObservationReturnsOneDNSFailureWhenCurrentResolverCannotBeSelected(t *testing.T) {
	t.Parallel()

	tests := map[string]resolverinventory.Result{
		"inventory failed": cliInventoryFailureResult(
			probe.OutcomeFailed,
			resolverinventory.FailureUnavailable,
		),
		"inventory invalid": {},
		"inventory has no group": cliInventoryResult(
			probe.OutcomeSucceeded,
			&resolverinventory.Evidence{Groups: []resolverinventory.Group{}},
			nil,
		),
		"no resolver uses supported port": cliInventorySuccessResult(resolverinventory.Group{
			Scope:   resolverinventory.ScopeGlobal,
			Servers: []resolverinventory.Server{{Address: "192.0.2.1", Port: 5353}},
		}),
		"link-local resolver has no zone": cliInventorySuccessResult(resolverinventory.Group{
			Scope:   resolverinventory.ScopeGlobal,
			Servers: []resolverinventory.Server{{Address: "fe80::53", Port: 53}},
		}),
		"multicast resolver is not dialled": cliInventorySuccessResult(resolverinventory.Group{
			Scope:   resolverinventory.ScopeGlobal,
			Servers: []resolverinventory.Server{{Address: "224.0.0.251", Port: 53}},
		}),
		"limited broadcast resolver is not dialled": cliInventorySuccessResult(resolverinventory.Group{
			Scope:   resolverinventory.ScopeGlobal,
			Servers: []resolverinventory.Server{{Address: "255.255.255.255", Port: 53}},
		}),
	}

	for name, inventoryResult := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inventory := resolverinventorytest.New(inventoryResult)
			dnsResult := cliDNSFailureResult(
				probe.OutcomeFailed,
				probe.FailureInvalidInput,
				resolverCurrent,
				"",
			)
			observer := dnsobservationtest.New(dnsResult)
			factory := &scriptedDNSFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"dns-observe", "udp", "current", "A", "example.com"},
				&stdout,
				&stderr,
				dependencies{
					resolverInventory: inventory,
					newDNSObserver:    factory.New,
				},
			)
			if code != 1 {
				t.Fatalf("run() = %d, want 1", code)
			}
			if !strings.Contains(stderr.String(), "current resolver unavailable") {
				t.Fatalf("stderr = %q, want current-resolver diagnostic", stderr.String())
			}
			decoded := decodeOneJSON[dnsobservation.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, dnsResult) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, dnsResult)
			}
			if got := len(inventory.Calls()); got != 1 {
				t.Fatalf("inventory calls = %d, want 1", got)
			}
			assertReferenceResolverConfig(t, factory.singleConfig(t))
			wantRequest := dnsobservation.Request{
				Hostname:  "example.com",
				QueryType: dnsobservation.QueryTypeA,
				Resolver:  resolverCurrent,
				Transport: dnsobservation.TransportUDP,
			}
			if got := observer.Calls(); !reflect.DeepEqual(got, []dnsobservationtest.Call{{Request: wantRequest}}) {
				t.Fatalf("DNS calls = %#v, want request %#v", got, wantRequest)
			}
		})
	}
}

func TestRunDNSObservationCurrentCancellationReturnsOneCancelledDNSEnvelope(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		parent    func() context.Context
		inventory resolverinventory.Result
	}{
		"inventory reports cancellation": {
			parent: context.Background,
			inventory: cliInventoryFailureResult(
				probe.OutcomeCancelled,
				probe.FailureCancelled,
			),
		},
		"parent is cancelled": {
			parent: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			inventory: cliInventoryFailureResult(
				probe.OutcomeFailed,
				resolverinventory.FailureUnavailable,
			),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inventory := resolverinventorytest.New(test.inventory)
			dnsResult := cliDNSFailureResult(
				probe.OutcomeCancelled,
				probe.FailureCancelled,
				resolverCurrent,
				"",
			)
			observer := dnsObserverFunc(func(
				ctx context.Context,
				request dnsobservation.Request,
			) dnsobservation.Result {
				if !errors.Is(ctx.Err(), context.Canceled) {
					t.Fatalf("DNS context error = %v, want context.Canceled", ctx.Err())
				}
				if request.Resolver != resolverCurrent {
					t.Fatalf("resolver = %q, want %q", request.Resolver, resolverCurrent)
				}
				return dnsResult
			})
			factory := &scriptedDNSFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				test.parent(),
				[]string{"dns-observe", "udp", "current", "A", "example.com"},
				&stdout,
				&stderr,
				dependencies{
					resolverInventory: inventory,
					newDNSObserver:    factory.New,
				},
			)
			if code != 130 {
				t.Fatalf("run() = %d, want 130; stderr = %q", code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty for cancellation", stderr.String())
			}
			decoded := decodeOneJSON[dnsobservation.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, dnsResult) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, dnsResult)
			}
			if got := len(inventory.Calls()); got != 1 {
				t.Fatalf("inventory calls = %d, want 1", got)
			}
			assertReferenceResolverConfig(t, factory.singleConfig(t))
		})
	}
}

func TestRunDNSHTTPSPathMapsFixedProviderAndPrintsAggregate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport dnsobservation.Transport
		provider  string
		resolver  dnsobservation.ResolverID
		endpoint  string
	}{
		{
			name: "cloudflare UDP", transport: dnsobservation.TransportUDP,
			provider: "cloudflare", resolver: resolverCloudflareWire, endpoint: "1.1.1.1:53",
		},
		{
			name: "google DoH", transport: dnsobservation.TransportDoH,
			provider: "google", resolver: resolverGoogleDoH, endpoint: "https://dns.google/dns-query",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result := cliDNSHTTPSPathSuccessResult(test.resolver, test.transport, test.endpoint)
			path := dnshttpspathtest.New(result)
			factory := &scriptedDNSHTTPSPathFactory{observer: path}
			inventory := resolverinventorytest.New()
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"dns-https-path", string(test.transport), test.provider, "example.com"},
				&stdout,
				&stderr,
				dependencies{
					resolverInventory:       inventory,
					newDNSHTTPSPathObserver: factory.New,
				},
			)
			if code != 0 || stderr.Len() != 0 {
				t.Fatalf("run/stderr = %d/%q, want 0/empty", code, stderr.String())
			}
			decoded := decodeOneJSON[dnshttpspath.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, result)
			}
			wantRequest := dnshttpspath.Request{
				Hostname: "example.com", Resolver: test.resolver, Transport: test.transport,
			}
			if calls := path.Calls(); !reflect.DeepEqual(calls, []dnshttpspathtest.Call{{Request: wantRequest}}) {
				t.Fatalf("path calls = %#v, want %#v", calls, wantRequest)
			}
			if len(inventory.Calls()) != 0 {
				t.Fatalf("inventory calls = %#v, want none", inventory.Calls())
			}
			config := factory.singleConfig(t)
			if config.Timeout != phase0DNSHTTPSPathTimeout {
				t.Fatalf("path timeout = %s, want %s", config.Timeout, phase0DNSHTTPSPathTimeout)
			}
			assertReferenceResolverConfig(t, config.DNS)
		})
	}
}

func TestRunDNSHTTPSPathReturnsTerminalExitCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result dnshttpspath.Result
		code   int
	}{
		{
			name: "stopped",
			result: cliDNSHTTPSPathTerminalResult(
				dnshttpspath.StatusStopped,
				dnshttpspath.StopPathTimeout,
				"path deadline exceeded",
			),
			code: 1,
		},
		{
			name: "cancelled",
			result: cliDNSHTTPSPathTerminalResult(
				dnshttpspath.StatusCancelled,
				dnshttpspath.StopCancelled,
				"context canceled",
			),
			code: 130,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := dnshttpspathtest.New(test.result)
			factory := &scriptedDNSHTTPSPathFactory{observer: path}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"dns-https-path", "udp", "cloudflare", "example.com"},
				&stdout,
				&stderr,
				dependencies{newDNSHTTPSPathObserver: factory.New},
			)
			if code != test.code || stderr.Len() != 0 {
				t.Fatalf("run/stderr = %d/%q, want %d/empty", code, stderr.String(), test.code)
			}
			decoded := decodeOneJSON[dnshttpspath.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
		})
	}
}

func TestRunWebObservationMapsRequestAndReturnsOutcomeExitCode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		scheme   webobservation.Scheme
		hostname string
		dialIP   string
		result   webobservation.Result
		code     int
	}{
		{
			name:     "HTTP IPv4 success",
			scheme:   webobservation.SchemeHTTP,
			hostname: "example.com",
			dialIP:   "93.184.216.34",
			result:   cliWebSuccessResult("example.com", "93.184.216.34"),
			code:     0,
		},
		{
			name:     "HTTPS IPv6 failure",
			scheme:   webobservation.SchemeHTTPS,
			hostname: "example.com",
			dialIP:   "2606:4700:4700::1111",
			result: cliWebFailureResult(
				webobservation.SchemeHTTPS,
				"example.com",
				"2606:4700:4700::1111",
				probe.OutcomeFailed,
				webobservation.FailureTLSHandshake,
			),
			code: 1,
		},
		{
			name:     "HTTPS cancellation",
			scheme:   webobservation.SchemeHTTPS,
			hostname: "example.com",
			dialIP:   "2606:4700:4700::1111",
			result: cliWebFailureResult(
				webobservation.SchemeHTTPS,
				"example.com",
				"2606:4700:4700::1111",
				probe.OutcomeCancelled,
				probe.FailureCancelled,
			),
			code: 130,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observer := webobservationtest.New(test.result)
			factory := &scriptedWebFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"web-observe", string(test.scheme), test.hostname, test.dialIP},
				&stdout,
				&stderr,
				dependencies{newWebObserver: factory.New},
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d; stderr = %q", code, test.code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			decoded := decodeOneJSON[webobservation.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}

			wantRequest := webobservation.Request{
				Scheme:   test.scheme,
				Hostname: test.hostname,
				DialIP:   test.dialIP,
			}
			wantCalls := []webobservationtest.Call{{Request: wantRequest}}
			if got := observer.Calls(); !reflect.DeepEqual(got, wantCalls) {
				t.Fatalf("Web calls = %#v, want %#v", got, wantCalls)
			}
			if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
				t.Fatalf("Web timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
			}
		})
	}
}

func TestRunWebObservationPassesInvalidHostnameAndIPToObserver(t *testing.T) {
	t.Parallel()

	result := cliWebInvalidInputResult("bad/name", "not-an-ip")
	observer := webobservationtest.New(result)
	factory := &scriptedWebFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		context.Background(),
		[]string{"web-observe", "http", "bad/name", "not-an-ip"},
		&stdout,
		&stderr,
		dependencies{newWebObserver: factory.New},
	)
	if code != 1 {
		t.Fatalf("run() = %d, want 1; stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	decoded := decodeOneJSON[webobservation.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	wantRequest := webobservation.Request{
		Scheme:   webobservation.SchemeHTTP,
		Hostname: "bad/name",
		DialIP:   "not-an-ip",
	}
	if got := observer.Calls(); !reflect.DeepEqual(got, []webobservationtest.Call{{Request: wantRequest}}) {
		t.Fatalf("Web calls = %#v, want request %#v", got, wantRequest)
	}
}

func TestRunReportsWebObserverFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedWebFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"web-observe", "https", "example.com", "93.184.216.34"},
		&stdout,
		&stderr,
		dependencies{newWebObserver: factory.New},
	)

	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "create Web observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
		t.Fatalf("Web timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
	}
}

func TestRunWebPathPrintsOneReportAndMapsTerminalStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		hostname string
		result   webpath.Result
		code     int
	}{
		{
			name:     "completed",
			hostname: "example.com",
			result:   cliWebPathCompletedResult(),
			code:     0,
		},
		{
			name:     "stopped invalid input",
			hostname: "bad/name",
			result: cliWebPathEmptyResult(
				"bad/name",
				webpath.StatusStopped,
				webpath.StopInvalidInput,
			),
			code: 1,
		},
		{
			name:     "cancelled",
			hostname: "example.com",
			result: cliWebPathEmptyResult(
				"example.com",
				webpath.StatusCancelled,
				webpath.StopCancelled,
			),
			code: 130,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			pathObserver := webpathtest.New(test.result)
			factory := &scriptedWebPathFactory{observer: pathObserver}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"web-path", test.hostname},
				&stdout,
				&stderr,
				dependencies{newWebPathObserver: factory.New},
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d; stderr = %q", code, test.code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			decoded := decodeOneJSON[webpath.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			wantCalls := []webpathtest.Call{{Request: webpath.Request{Hostname: test.hostname}}}
			if calls := pathObserver.Calls(); !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("Web-path calls = %#v, want %#v", calls, wantCalls)
			}
			if config := factory.singleConfig(t); config.Timeout != phase0WebPathTimeout {
				t.Fatalf("Web-path timeout = %s, want %s", config.Timeout, phase0WebPathTimeout)
			}
		})
	}
}

func TestRunReportsWebPathFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedWebPathFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"web-path", "example.com"},
		&stdout,
		&stderr,
		dependencies{newWebPathObserver: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run/stdout = %d/%q, want 1/empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create Web-path observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if config := factory.singleConfig(t); config.Timeout != phase0WebPathTimeout {
		t.Fatalf("Web-path timeout = %s, want %s", config.Timeout, phase0WebPathTimeout)
	}
}

func TestRunWebRecheckPrintsOneReportAndMapsTerminalStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		request  webrecheck.Request
		result   webrecheck.Result
		exitCode int
	}{
		{
			name: "completed bounded candidate sets",
			args: []string{
				"web-recheck", "example.com", "8.8.8.8,1.0.0.1", "1.1.1.1,8.8.4.4",
			},
			request: webrecheck.Request{
				Hostname:            "example.com",
				LocalCandidates:     []string{"8.8.8.8", "1.0.0.1"},
				ReferenceCandidates: []string{"1.1.1.1", "8.8.4.4"},
			},
			result: cliWebRecheckCompletedResult(
				[]string{"8.8.8.8", "1.0.0.1"},
				[]string{"1.1.1.1", "8.8.4.4"},
			),
			exitCode: 0,
		},
		{
			name: "stopped",
			args: []string{"web-recheck", "example.com", "8.8.8.8", "1.1.1.1"},
			request: webrecheck.Request{
				Hostname:            "example.com",
				LocalCandidates:     []string{"8.8.8.8"},
				ReferenceCandidates: []string{"1.1.1.1"},
			},
			result: cliWebRecheckEmptyResult(
				webrecheck.StatusStopped,
				webrecheck.StopRecheckTimeout,
				"scripted timeout",
			),
			exitCode: 1,
		},
		{
			name: "cancelled",
			args: []string{"web-recheck", "example.com", "8.8.8.8", "1.1.1.1"},
			request: webrecheck.Request{
				Hostname:            "example.com",
				LocalCandidates:     []string{"8.8.8.8"},
				ReferenceCandidates: []string{"1.1.1.1"},
			},
			result: cliWebRecheckEmptyResult(
				webrecheck.StatusCancelled,
				webrecheck.StopCancelled,
				"",
			),
			exitCode: 130,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			recheck := webrechecktest.New(test.result)
			factory := &scriptedWebRecheckFactory{observer: recheck}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				test.args,
				&stdout,
				&stderr,
				dependencies{newWebRecheckObserver: factory.New},
			)
			if code != test.exitCode || stderr.Len() != 0 {
				t.Fatalf("run/stderr = %d/%q, want %d/empty", code, stderr.String(), test.exitCode)
			}
			decoded := decodeOneJSON[webrecheck.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			wantCalls := []webrechecktest.Call{{Request: test.request}}
			if calls := recheck.Calls(); !reflect.DeepEqual(calls, wantCalls) {
				t.Fatalf("Web recheck calls = %#v, want %#v", calls, wantCalls)
			}
			if config := factory.singleConfig(t); config.Timeout != phase0WebRecheckTimeout {
				t.Fatalf("Web recheck timeout = %s, want %s", config.Timeout, phase0WebRecheckTimeout)
			}
		})
	}
}

func TestRunReportsWebRecheckFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedWebRecheckFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"web-recheck", "example.com", "8.8.8.8", "1.1.1.1"},
		&stdout,
		&stderr,
		dependencies{newWebRecheckObserver: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run/stdout = %d/%q, want 1/empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create Web candidate recheck observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if config := factory.singleConfig(t); config.Timeout != phase0WebRecheckTimeout {
		t.Fatalf("Web recheck timeout = %s, want %s", config.Timeout, phase0WebRecheckTimeout)
	}
}

func TestRunTLSObservationMapsTerminalEvidenceAndFixedRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		dialIP string
		result tlsobservation.Result
		code   int
	}{
		{
			name:   "completed handshake without identity assertion",
			dialIP: "93.184.216.34",
			result: cliTLSCompletedResult("93.184.216.34"),
			code:   0,
		},
		{
			name:   "reachable but handshake unconfirmed",
			dialIP: "2606:4700:4700::1111",
			result: cliTLSUnconfirmedResult("2606:4700:4700::1111"),
			code:   0,
		},
		{
			name:   "TCP failure",
			dialIP: "93.184.216.34",
			result: cliTLSFailureResult(
				"93.184.216.34",
				probe.OutcomeFailed,
				tlsobservation.FailureTCPConnectionRefused,
			),
			code: 1,
		},
		{
			name:   "cancellation",
			dialIP: "93.184.216.34",
			result: cliTLSFailureResult(
				"93.184.216.34",
				probe.OutcomeCancelled,
				probe.FailureCancelled,
			),
			code: 130,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observer := tlsobservationtest.New(test.result)
			factory := &scriptedTLSFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				[]string{"tls-observe", test.dialIP},
				&stdout,
				&stderr,
				dependencies{newTLSObserver: factory.New},
			)
			if code != test.code || stderr.Len() != 0 {
				t.Fatalf("run/stderr = %d/%q, want %d/empty", code, stderr.String(), test.code)
			}
			decoded := decodeOneJSON[tlsobservation.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			wantRequest := tlsobservation.Request{DialIP: test.dialIP}
			if got := observer.Calls(); !reflect.DeepEqual(got, []tlsobservationtest.Call{{Request: wantRequest}}) {
				t.Fatalf("TLS calls = %#v, want request %#v", got, wantRequest)
			}
			if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
				t.Fatalf("TLS timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
			}
		})
	}
}

func TestRunTLSObservationPassesInvalidIPToObserver(t *testing.T) {
	t.Parallel()

	result := cliTLSInvalidInputResult("not-an-ip")
	observer := tlsobservationtest.New(result)
	factory := &scriptedTLSFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"tls-observe", "not-an-ip"},
		&stdout,
		&stderr,
		dependencies{newTLSObserver: factory.New},
	)
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 1/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[tlsobservation.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
}

func TestRunReportsTLSObserverFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedTLSFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"tls-observe", "93.184.216.34"},
		&stdout,
		&stderr,
		dependencies{newTLSObserver: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run/stdout = %d/%q, want 1/empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create TLS observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
		t.Fatalf("TLS timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
	}
}

func TestRunTLSRetryBatchMapsTerminalReportsAndTargets(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		argument string
		result   tlsretrybatch.Result
		code     int
	}{
		"completed evidence including endpoint failures": {
			argument: "8.8.8.8,1.1.1.1",
			result:   cliTLSRetryBatchCompletedResult([]string{"8.8.8.8", "1.1.1.1"}),
			code:     0,
		},
		"batch timeout": {
			argument: "8.8.8.8",
			result:   cliTLSRetryBatchStoppedResult("8.8.8.8"),
			code:     1,
		},
		"cancelled": {
			argument: "8.8.8.8",
			result:   cliTLSRetryBatchCancelledResult("8.8.8.8"),
			code:     130,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			observer := tlsretrybatchtest.New(test.result)
			factory := &scriptedTLSRetryBatchFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			code := run(
				context.Background(),
				[]string{"tls-retry-batch", test.argument},
				&stdout,
				&stderr,
				dependencies{newTLSRetryBatchObserver: factory.New},
			)
			if code != test.code || stderr.Len() != 0 {
				t.Fatalf("run/stderr = %d/%q, want %d/empty", code, stderr.String(), test.code)
			}
			decoded := decodeOneJSON[tlsretrybatch.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			wantRequest := tlsretrybatch.Request{Targets: strings.Split(test.argument, ",")}
			if got := observer.Calls(); !reflect.DeepEqual(got, []tlsretrybatchtest.Call{{Request: wantRequest}}) {
				t.Fatalf("TLS retry-batch calls = %#v, want %#v", got, wantRequest)
			}
			if config := factory.singleConfig(t); config.Timeout != phase0TLSRetryBatchTimeout {
				t.Fatalf("TLS retry-batch timeout = %s, want %s", config.Timeout, phase0TLSRetryBatchTimeout)
			}
		})
	}
}

func TestRunTLSRetryBatchPassesSemanticInvalidInputToObserver(t *testing.T) {
	t.Parallel()

	result := cliTLSRetryBatchInvalidResult("not-an-ip")
	observer := tlsretrybatchtest.New(result)
	factory := &scriptedTLSRetryBatchFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"tls-retry-batch", "not-an-ip"},
		&stdout,
		&stderr,
		dependencies{newTLSRetryBatchObserver: factory.New},
	)
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 1/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[tlsretrybatch.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
}

func TestRunReportsTLSRetryBatchFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedTLSRetryBatchFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"tls-retry-batch", "8.8.8.8"},
		&stdout,
		&stderr,
		dependencies{newTLSRetryBatchObserver: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run/stdout = %d/%q, want 1/empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create TLS retry-batch observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if config := factory.singleConfig(t); config.Timeout != phase0TLSRetryBatchTimeout {
		t.Fatalf("TLS retry-batch timeout = %s, want %s", config.Timeout, phase0TLSRetryBatchTimeout)
	}
}

func TestRunSSHObservationMapsDefaultAndCustomPorts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		args   []string
		result sshobservation.Result
		code   int
	}{
		{
			name:   "default port receives SSH identification",
			args:   []string{"ssh-observe", "93.184.216.34"},
			result: cliSSHReceivedResult("93.184.216.34", 22),
			code:   0,
		},
		{
			name:   "custom port is reachable but unconfirmed",
			args:   []string{"ssh-observe", "2606:4700:4700::1111", "2222"},
			result: cliSSHUnconfirmedResult("2606:4700:4700::1111", 2222),
			code:   0,
		},
		{
			name: "TCP failure",
			args: []string{"ssh-observe", "93.184.216.34", "22"},
			result: cliSSHFailureResult(
				"93.184.216.34",
				22,
				probe.OutcomeFailed,
				sshobservation.FailureTCPConnectionRefused,
			),
			code: 1,
		},
		{
			name: "cancellation",
			args: []string{"ssh-observe", "93.184.216.34"},
			result: cliSSHFailureResult(
				"93.184.216.34",
				22,
				probe.OutcomeCancelled,
				probe.FailureCancelled,
			),
			code: 130,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			observer := sshobservationtest.New(test.result)
			factory := &scriptedSSHFactory{observer: observer}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				test.args,
				&stdout,
				&stderr,
				dependencies{newSSHObserver: factory.New},
			)
			if code != test.code {
				t.Fatalf("run() = %d, want %d; stderr = %q", code, test.code, stderr.String())
			}
			if stderr.Len() != 0 {
				t.Fatalf("stderr = %q, want empty", stderr.String())
			}
			decoded := decodeOneJSON[sshobservation.Result](t, stdout.Bytes())
			if !reflect.DeepEqual(decoded, test.result) {
				t.Fatalf("decoded result = %#v, want %#v", decoded, test.result)
			}
			wantRequest := sshobservation.Request{
				DialIP: test.result.Input.DialIP,
				Port:   test.result.Input.Port,
			}
			if got := observer.Calls(); !reflect.DeepEqual(got, []sshobservationtest.Call{{Request: wantRequest}}) {
				t.Fatalf("SSH calls = %#v, want request %#v", got, wantRequest)
			}
			if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
				t.Fatalf("SSH timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
			}
		})
	}
}

func TestRunSSHObservationPassesInvalidIPToObserver(t *testing.T) {
	t.Parallel()

	result := cliSSHInvalidInputResult("not-an-ip", 22)
	observer := sshobservationtest.New(result)
	factory := &scriptedSSHFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"ssh-observe", "not-an-ip"},
		&stdout,
		&stderr,
		dependencies{newSSHObserver: factory.New},
	)
	if code != 1 || stderr.Len() != 0 {
		t.Fatalf("run() = %d, stderr = %q; want 1 and empty", code, stderr.String())
	}
	decoded := decodeOneJSON[sshobservation.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	wantRequest := sshobservation.Request{DialIP: "not-an-ip", Port: 22}
	if got := observer.Calls(); !reflect.DeepEqual(got, []sshobservationtest.Call{{Request: wantRequest}}) {
		t.Fatalf("SSH calls = %#v, want request %#v", got, wantRequest)
	}
}

func TestRunReportsSSHObserverFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedSSHFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"ssh-observe", "93.184.216.34"},
		&stdout,
		&stderr,
		dependencies{newSSHObserver: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run() = %d, stdout = %q; want 1 and empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create SSH observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
		t.Fatalf("SSH timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
	}
}

func TestRunRejectsInvalidArgumentsWithoutCallingDependencies(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"empty":                              nil,
		"browser placeholder extra argument": {"browser-placeholder", "extra"},
		"family conditions extra argument":   {"family-conditions", "extra"},
		"resolve missing hostname":           {"resolve"},
		"resolve extra argument":             {"resolve", "example.com", "extra"},
		"inventory extra argument":           {"resolver-inventory", "extra"},
		"DNS missing argument":               {"dns-observe", "udp", "cloudflare", "A"},
		"DNS extra argument":                 {"dns-observe", "udp", "cloudflare", "A", "example.com", "extra"},
		"unknown command":                    {"inspect"},
		"unknown transport":                  {"dns-observe", "UDP", "cloudflare", "A", "example.com"},
		"unknown provider":                   {"dns-observe", "udp", "quad9", "A", "example.com"},
		"lowercase query type":               {"dns-observe", "udp", "cloudflare", "a", "example.com"},
		"current does not support DoH":       {"dns-observe", "doh", "current", "A", "example.com"},
		"DNS HTTPS path missing hostname":    {"dns-https-path", "udp", "cloudflare"},
		"DNS HTTPS path extra argument":      {"dns-https-path", "udp", "cloudflare", "example.com", "extra"},
		"DNS HTTPS path unknown transport":   {"dns-https-path", "UDP", "cloudflare", "example.com"},
		"DNS HTTPS path unknown provider":    {"dns-https-path", "udp", "quad9", "example.com"},
		"DNS HTTPS path current DoH":         {"dns-https-path", "doh", "current", "example.com"},
		"Web missing argument":               {"web-observe", "https", "example.com"},
		"Web extra argument":                 {"web-observe", "https", "example.com", "93.184.216.34", "extra"},
		"unknown Web scheme":                 {"web-observe", "HTTPS", "example.com", "93.184.216.34"},
		"Web path missing hostname":          {"web-path"},
		"Web path extra argument":            {"web-path", "example.com", "extra"},
		"Web recheck missing candidates":     {"web-recheck", "example.com", "8.8.8.8"},
		"Web recheck extra argument":         {"web-recheck", "example.com", "8.8.8.8", "1.1.1.1", "extra"},
		"SSH missing IP":                     {"ssh-observe"},
		"SSH extra argument":                 {"ssh-observe", "93.184.216.34", "22", "extra"},
		"SSH nonnumeric port":                {"ssh-observe", "93.184.216.34", "ssh"},
		"SSH zero port":                      {"ssh-observe", "93.184.216.34", "0"},
		"SSH oversized port":                 {"ssh-observe", "93.184.216.34", "65536"},
		"TLS missing IP":                     {"tls-observe"},
		"TLS extra argument":                 {"tls-observe", "93.184.216.34", "extra"},
		"TLS retry batch missing targets":    {"tls-retry-batch"},
		"TLS retry batch extra argument":     {"tls-retry-batch", "8.8.8.8", "extra"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolver := systemresolvertest.New()
			inventory := resolverinventorytest.New()
			factory := &scriptedDNSFactory{observer: dnsobservationtest.New()}
			dnsHTTPSPathFactory := &scriptedDNSHTTPSPathFactory{observer: dnshttpspathtest.New()}
			webFactory := &scriptedWebFactory{observer: webobservationtest.New()}
			webPathFactory := &scriptedWebPathFactory{observer: webpathtest.New()}
			webRecheckFactory := &scriptedWebRecheckFactory{observer: webrechecktest.New()}
			sshFactory := &scriptedSSHFactory{observer: sshobservationtest.New()}
			tlsFactory := &scriptedTLSFactory{observer: tlsobservationtest.New()}
			tlsRetryBatchFactory := &scriptedTLSRetryBatchFactory{observer: tlsretrybatchtest.New()}
			familyConditionFactory := &scriptedFamilyConditionFactory{observer: familyconditiontest.New()}
			browserPlaceholderFactory := &scriptedBrowserPlaceholderFactory{runner: browserplaceholdertest.New()}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				args,
				&stdout,
				&stderr,
				dependencies{
					systemResolver:              resolver,
					resolverInventory:           inventory,
					newDNSObserver:              factory.New,
					newDNSHTTPSPathObserver:     dnsHTTPSPathFactory.New,
					newWebObserver:              webFactory.New,
					newWebPathObserver:          webPathFactory.New,
					newWebRecheckObserver:       webRecheckFactory.New,
					newSSHObserver:              sshFactory.New,
					newTLSObserver:              tlsFactory.New,
					newTLSRetryBatchObserver:    tlsRetryBatchFactory.New,
					newFamilyConditionObserver:  familyConditionFactory.New,
					newBrowserPlaceholderRunner: browserPlaceholderFactory.New,
				},
			)
			if code != 2 {
				t.Fatalf("run() = %d, want 2", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), "Phase 0 diagnostic") ||
				!strings.Contains(stderr.String(), "reachrun browser-placeholder") ||
				!strings.Contains(stderr.String(), "reachrun resolver-inventory") ||
				!strings.Contains(stderr.String(), "reachrun dns-observe") ||
				!strings.Contains(stderr.String(), "reachrun dns-https-path") ||
				!strings.Contains(stderr.String(), "reachrun web-observe") ||
				!strings.Contains(stderr.String(), "reachrun web-path") ||
				!strings.Contains(stderr.String(), "reachrun web-recheck") ||
				!strings.Contains(stderr.String(), "reachrun ssh-observe") ||
				!strings.Contains(stderr.String(), "reachrun tls-observe") ||
				!strings.Contains(stderr.String(), "reachrun tls-retry-batch") ||
				!strings.Contains(stderr.String(), "reachrun family-conditions") {
				t.Fatalf("stderr = %q, want Phase 0 usage", stderr.String())
			}
			if len(resolver.Calls()) != 0 || len(inventory.Calls()) != 0 ||
				len(factory.calls) != 0 || len(dnsHTTPSPathFactory.calls) != 0 || len(webFactory.calls) != 0 ||
				len(webPathFactory.calls) != 0 || len(webRecheckFactory.calls) != 0 || len(sshFactory.calls) != 0 ||
				len(tlsFactory.calls) != 0 || len(tlsRetryBatchFactory.calls) != 0 ||
				len(familyConditionFactory.calls) != 0 || len(browserPlaceholderFactory.calls) != 0 {
				t.Fatalf(
					"dependency calls = resolver %#v, inventory %#v, DNS factory %#v, DNS HTTPS-path factory %#v, Web factory %#v, Web-path factory %#v, Web-recheck factory %#v, SSH factory %#v, TLS factory %#v, TLS retry-batch factory %#v, family-condition factory %#v, browser-placeholder factory %#v; want none",
					resolver.Calls(),
					inventory.Calls(),
					factory.calls,
					dnsHTTPSPathFactory.calls,
					webFactory.calls,
					webPathFactory.calls,
					webRecheckFactory.calls,
					sshFactory.calls,
					tlsFactory.calls,
					tlsRetryBatchFactory.calls,
					familyConditionFactory.calls,
					browserPlaceholderFactory.calls,
				)
			}
		})
	}
}

func TestRunRejectsInvalidReturnedEnvelopes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		args      []string
		deps      dependencies
		wantError string
	}{
		"browser placeholder": {
			args: []string{"browser-placeholder"},
			deps: dependencies{
				newBrowserPlaceholderRunner: (&scriptedBrowserPlaceholderFactory{
					runner: browserplaceholdertest.New(browserplaceholdertest.Step{
						Result: browserplaceholder.Result{},
					}),
				}).New,
			},
			wantError: "invalid browser-placeholder result",
		},
		"address family conditions": {
			args: []string{"family-conditions"},
			deps: dependencies{
				newFamilyConditionObserver: (&scriptedFamilyConditionFactory{
					observer: familyconditiontest.New(familycondition.Result{}),
				}).New,
			},
			wantError: "invalid address-family-condition result",
		},
		"system resolver": {
			args:      []string{"resolve", "example.com"},
			deps:      dependencies{systemResolver: systemresolvertest.New(systemresolver.Result{})},
			wantError: "invalid system resolver result",
		},
		"resolver inventory": {
			args: []string{"resolver-inventory"},
			deps: dependencies{
				resolverInventory: resolverinventorytest.New(resolverinventory.Result{}),
			},
			wantError: "invalid resolver inventory result",
		},
		"DNS observation": {
			args: []string{"dns-observe", "udp", "cloudflare", "A", "example.com"},
			deps: dependencies{
				newDNSObserver: (&scriptedDNSFactory{
					observer: dnsobservationtest.New(dnsobservation.Result{}),
				}).New,
			},
			wantError: "invalid DNS observation result",
		},
		"DNS HTTPS path": {
			args: []string{"dns-https-path", "udp", "cloudflare", "example.com"},
			deps: dependencies{
				newDNSHTTPSPathObserver: (&scriptedDNSHTTPSPathFactory{
					observer: dnshttpspathtest.New(dnshttpspath.Result{}),
				}).New,
			},
			wantError: "invalid DNS HTTPS-path result",
		},
		"Web observation": {
			args: []string{"web-observe", "http", "example.com", "93.184.216.34"},
			deps: dependencies{
				newWebObserver: (&scriptedWebFactory{
					observer: webobservationtest.New(webobservation.Result{}),
				}).New,
			},
			wantError: "invalid Web observation result",
		},
		"Web path": {
			args: []string{"web-path", "example.com"},
			deps: dependencies{
				newWebPathObserver: (&scriptedWebPathFactory{
					observer: webpathtest.New(webpath.Result{}),
				}).New,
			},
			wantError: "invalid Web-path result",
		},
		"Web candidate recheck": {
			args: []string{"web-recheck", "example.com", "8.8.8.8", "1.1.1.1"},
			deps: dependencies{
				newWebRecheckObserver: (&scriptedWebRecheckFactory{
					observer: webrechecktest.New(webrecheck.Result{}),
				}).New,
			},
			wantError: "invalid Web candidate recheck result",
		},
		"SSH observation": {
			args: []string{"ssh-observe", "93.184.216.34"},
			deps: dependencies{
				newSSHObserver: (&scriptedSSHFactory{
					observer: sshobservationtest.New(sshobservation.Result{}),
				}).New,
			},
			wantError: "invalid SSH observation result",
		},
		"TLS observation": {
			args: []string{"tls-observe", "93.184.216.34"},
			deps: dependencies{
				newTLSObserver: (&scriptedTLSFactory{
					observer: tlsobservationtest.New(tlsobservation.Result{}),
				}).New,
			},
			wantError: "invalid TLS observation result",
		},
		"TLS retry batch": {
			args: []string{"tls-retry-batch", "8.8.8.8"},
			deps: dependencies{
				newTLSRetryBatchObserver: (&scriptedTLSRetryBatchFactory{
					observer: tlsretrybatchtest.New(tlsretrybatch.Result{}),
				}).New,
			},
			wantError: "invalid TLS retry-batch result",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(context.Background(), test.args, &stdout, &stderr, test.deps)
			if code != 1 {
				t.Fatalf("run() = %d, want 1", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), test.wantError) {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.wantError)
			}
		})
	}
}

func TestRunReportsDNSObserverFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedDNSFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"dns-observe", "udp", "cloudflare", "A", "example.com"},
		&stdout,
		&stderr,
		dependencies{newDNSObserver: factory.New},
	)

	if code != 1 {
		t.Fatalf("run() = %d, want 1", code)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q, want empty", stdout.String())
	}
	if !strings.Contains(stderr.String(), "create DNS observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	assertReferenceResolverConfig(t, factory.singleConfig(t))
}

func TestRunReportsDNSHTTPSPathFactoryErrorWithoutOutput(t *testing.T) {
	t.Parallel()

	factory := &scriptedDNSHTTPSPathFactory{err: errors.New("scripted factory failure")}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		context.Background(),
		[]string{"dns-https-path", "udp", "cloudflare", "example.com"},
		&stdout,
		&stderr,
		dependencies{newDNSHTTPSPathObserver: factory.New},
	)
	if code != 1 || stdout.Len() != 0 {
		t.Fatalf("run/stdout = %d/%q, want 1/empty", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "create DNS HTTPS-path observer: scripted factory failure") {
		t.Fatalf("stderr = %q, want factory error", stderr.String())
	}
	config := factory.singleConfig(t)
	if config.Timeout != phase0DNSHTTPSPathTimeout {
		t.Fatalf("path timeout = %s, want %s", config.Timeout, phase0DNSHTTPSPathTimeout)
	}
	assertReferenceResolverConfig(t, config.DNS)
}

func TestRunPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	resolver := resolverFunc(func(ctx context.Context, hostname string) systemresolver.Result {
		if hostname != "example.com" {
			t.Fatalf("hostname = %q, want example.com", hostname)
		}
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("probe context has no outer deadline")
		}
		return cliSystemResolverFailureResult(probe.OutcomeCancelled, probe.FailureCancelled)
	})
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		parent,
		[]string{"resolve", "example.com"},
		&stdout,
		&stderr,
		dependencies{systemResolver: resolver},
	)
	if code != 130 {
		t.Fatalf("run() = %d, want 130", code)
	}
	decodeOneJSON[systemresolver.Result](t, stdout.Bytes())
}

func TestRunWebObservationPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	result := cliWebFailureResult(
		webobservation.SchemeHTTPS,
		"example.com",
		"2606:4700:4700::1111",
		probe.OutcomeCancelled,
		probe.FailureCancelled,
	)
	observer := webObserverFunc(func(
		ctx context.Context,
		request webobservation.Request,
	) webobservation.Result {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("Web context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("Web probe context has no outer deadline")
		}
		wantRequest := webobservation.Request{
			Scheme:   webobservation.SchemeHTTPS,
			Hostname: "example.com",
			DialIP:   "2606:4700:4700::1111",
		}
		if !reflect.DeepEqual(request, wantRequest) {
			t.Fatalf("Web request = %#v, want %#v", request, wantRequest)
		}
		return result
	})
	factory := &scriptedWebFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		parent,
		[]string{"web-observe", "https", "example.com", "2606:4700:4700::1111"},
		&stdout,
		&stderr,
		dependencies{newWebObserver: factory.New},
	)
	if code != 130 {
		t.Fatalf("run() = %d, want 130; stderr = %q", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q, want empty", stderr.String())
	}
	decoded := decodeOneJSON[webobservation.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	if got := factory.singleConfig(t); got.Timeout != phase0ProbeTimeout {
		t.Fatalf("Web timeout = %s, want %s", got.Timeout, phase0ProbeTimeout)
	}
}

func TestRunWebPathPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	result := cliWebPathEmptyResult(
		"example.com",
		webpath.StatusCancelled,
		webpath.StopCancelled,
	)
	observer := webPathObserverFunc(func(
		ctx context.Context,
		request webpath.Request,
	) webpath.Result {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("Web-path context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("Web-path context has no outer deadline")
		}
		if request != (webpath.Request{Hostname: "example.com"}) {
			t.Fatalf("Web-path request = %#v", request)
		}
		return result
	})
	factory := &scriptedWebPathFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	code := run(
		parent,
		[]string{"web-path", "example.com"},
		&stdout,
		&stderr,
		dependencies{newWebPathObserver: factory.New},
	)
	if code != 130 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 130/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[webpath.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	if config := factory.singleConfig(t); config.Timeout != phase0WebPathTimeout {
		t.Fatalf("Web-path timeout = %s, want %s", config.Timeout, phase0WebPathTimeout)
	}
}

func TestRunWebRecheckPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	result := cliWebRecheckEmptyResult(
		webrecheck.StatusCancelled,
		webrecheck.StopCancelled,
		"",
	)
	observer := webRecheckObserverFunc(func(
		ctx context.Context,
		request webrecheck.Request,
	) webrecheck.Result {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("Web recheck context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("Web recheck context has no outer deadline")
		}
		want := webrecheck.Request{
			Hostname:            "example.com",
			LocalCandidates:     []string{"8.8.8.8"},
			ReferenceCandidates: []string{"1.1.1.1"},
		}
		if !reflect.DeepEqual(request, want) {
			t.Fatalf("Web recheck request = %#v, want %#v", request, want)
		}
		return result
	})
	factory := &scriptedWebRecheckFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		parent,
		[]string{"web-recheck", "example.com", "8.8.8.8", "1.1.1.1"},
		&stdout,
		&stderr,
		dependencies{newWebRecheckObserver: factory.New},
	)
	if code != 130 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 130/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[webrecheck.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	if config := factory.singleConfig(t); config.Timeout != phase0WebRecheckTimeout {
		t.Fatalf("Web recheck timeout = %s, want %s", config.Timeout, phase0WebRecheckTimeout)
	}
}

func TestRunFamilyConditionsPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	result := cliFamilyConditionsFailureResult(
		probe.OutcomeCancelled,
		probe.FailureCancelled,
	)
	observer := familyConditionObserverFunc(func(ctx context.Context) familycondition.Result {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("family-condition context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("family-condition context has no outer deadline")
		}
		return result
	})
	factory := &scriptedFamilyConditionFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		parent,
		[]string{"family-conditions"},
		&stdout,
		&stderr,
		dependencies{newFamilyConditionObserver: factory.New},
	)
	if code != 130 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 130/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[familycondition.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	if config := factory.singleConfig(t); config.Timeout != phase0ProbeTimeout {
		t.Fatalf("family-condition timeout = %s, want %s", config.Timeout, phase0ProbeTimeout)
	}
}

func TestRunTLSObservationPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	result := cliTLSFailureResult(
		"93.184.216.34",
		probe.OutcomeCancelled,
		probe.FailureCancelled,
	)
	observer := tlsObserverFunc(func(
		ctx context.Context,
		request tlsobservation.Request,
	) tlsobservation.Result {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("TLS context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("TLS probe context has no outer deadline")
		}
		if request != (tlsobservation.Request{DialIP: "93.184.216.34"}) {
			t.Fatalf("TLS request = %#v", request)
		}
		return result
	})
	factory := &scriptedTLSFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		parent,
		[]string{"tls-observe", "93.184.216.34"},
		&stdout,
		&stderr,
		dependencies{newTLSObserver: factory.New},
	)
	if code != 130 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 130/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[tlsobservation.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	if config := factory.singleConfig(t); config.Timeout != phase0ProbeTimeout {
		t.Fatalf("TLS timeout = %s, want %s", config.Timeout, phase0ProbeTimeout)
	}
}

func TestRunTLSRetryBatchPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	result := cliTLSRetryBatchCancelledResult("8.8.8.8")
	observer := tlsRetryBatchObserverFunc(func(
		ctx context.Context,
		request tlsretrybatch.Request,
	) tlsretrybatch.Result {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("TLS retry-batch context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("TLS retry-batch context has no outer deadline")
		}
		want := tlsretrybatch.Request{Targets: []string{"8.8.8.8"}}
		if !reflect.DeepEqual(request, want) {
			t.Fatalf("TLS retry-batch request = %#v, want %#v", request, want)
		}
		return result
	})
	factory := &scriptedTLSRetryBatchFactory{observer: observer}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		parent,
		[]string{"tls-retry-batch", "8.8.8.8"},
		&stdout,
		&stderr,
		dependencies{newTLSRetryBatchObserver: factory.New},
	)
	if code != 130 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 130/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[tlsretrybatch.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	if config := factory.singleConfig(t); config.Timeout != phase0TLSRetryBatchTimeout {
		t.Fatalf("TLS retry-batch timeout = %s, want %s", config.Timeout, phase0TLSRetryBatchTimeout)
	}
}

func TestRunBrowserPlaceholderPropagatesParentCancellationAndAddsOuterDeadline(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(context.Background())
	cancel()
	result := cliBrowserPlaceholderCancelledResult()
	runner := browserPlaceholderRunnerFunc(func(
		ctx context.Context,
		notify browserplaceholder.FallbackNotifier,
	) browserplaceholder.Result {
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("browser-placeholder context error = %v, want context.Canceled", ctx.Err())
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("browser-placeholder context has no outer deadline")
		}
		if notify == nil {
			t.Fatal("browser-placeholder fallback notifier is nil")
		}
		return result
	})
	factory := &scriptedBrowserPlaceholderFactory{runner: runner}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := run(
		parent,
		[]string{"browser-placeholder"},
		&stdout,
		&stderr,
		dependencies{newBrowserPlaceholderRunner: factory.New},
	)
	if code != 130 || stderr.Len() != 0 {
		t.Fatalf("run/stderr = %d/%q, want 130/empty", code, stderr.String())
	}
	decoded := decodeOneJSON[browserplaceholder.Result](t, stdout.Bytes())
	if !reflect.DeepEqual(decoded, result) {
		t.Fatalf("decoded result = %#v, want %#v", decoded, result)
	}
	if config := factory.singleConfig(t); config.Timeout != phase0BrowserPlaceholderTimeout {
		t.Fatalf("browser-placeholder timeout = %s, want %s", config.Timeout, phase0BrowserPlaceholderTimeout)
	}
}

type scriptedDNSFactory struct {
	observer dnsobservation.Observer
	err      error
	calls    []dnsobservation.Config
}

type scriptedDNSHTTPSPathFactory struct {
	observer dnshttpspath.Observer
	err      error
	calls    []dnshttpspath.Config
}

func (f *scriptedDNSHTTPSPathFactory) New(config dnshttpspath.Config) (dnshttpspath.Observer, error) {
	config.DNS.Resolvers = append([]dnsobservation.ResolverEndpoint(nil), config.DNS.Resolvers...)
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedDNSHTTPSPathFactory) singleConfig(t *testing.T) dnshttpspath.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("DNS HTTPS-path factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

func (f *scriptedDNSFactory) New(config dnsobservation.Config) (dnsobservation.Observer, error) {
	config.Resolvers = append([]dnsobservation.ResolverEndpoint(nil), config.Resolvers...)
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedDNSFactory) singleConfig(t *testing.T) dnsobservation.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

type scriptedWebFactory struct {
	observer webobservation.Observer
	err      error
	calls    []webobservation.Config
}

type scriptedWebPathFactory struct {
	observer webpath.Observer
	err      error
	calls    []webpath.Config
}

type scriptedWebRecheckFactory struct {
	observer webrecheck.Observer
	err      error
	calls    []webrecheck.Config
}

type scriptedSSHFactory struct {
	observer sshobservation.Observer
	err      error
	calls    []sshobservation.Config
}

type scriptedTLSFactory struct {
	observer tlsobservation.Observer
	err      error
	calls    []tlsobservation.Config
}

type scriptedTLSRetryBatchFactory struct {
	observer tlsretrybatch.Observer
	err      error
	calls    []tlsretrybatch.Config
}

type scriptedBrowserPlaceholderFactory struct {
	runner browserplaceholder.Runner
	err    error
	calls  []browserplaceholder.Config
}

func (f *scriptedBrowserPlaceholderFactory) New(
	config browserplaceholder.Config,
) (browserplaceholder.Runner, error) {
	f.calls = append(f.calls, config)
	return f.runner, f.err
}

func (f *scriptedBrowserPlaceholderFactory) singleConfig(t *testing.T) browserplaceholder.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("browser-placeholder factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

func (f *scriptedTLSRetryBatchFactory) New(
	config tlsretrybatch.Config,
) (tlsretrybatch.Observer, error) {
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedTLSRetryBatchFactory) singleConfig(t *testing.T) tlsretrybatch.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("TLS retry-batch factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

type scriptedFamilyConditionFactory struct {
	observer familycondition.Observer
	err      error
	calls    []familycondition.Config
}

func (f *scriptedFamilyConditionFactory) New(
	config familycondition.Config,
) (familycondition.Observer, error) {
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedFamilyConditionFactory) singleConfig(t *testing.T) familycondition.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("family-condition factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

func (f *scriptedTLSFactory) New(config tlsobservation.Config) (tlsobservation.Observer, error) {
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedTLSFactory) singleConfig(t *testing.T) tlsobservation.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("TLS factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

func (f *scriptedSSHFactory) New(config sshobservation.Config) (sshobservation.Observer, error) {
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedSSHFactory) singleConfig(t *testing.T) sshobservation.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("SSH factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

func (f *scriptedWebFactory) New(config webobservation.Config) (webobservation.Observer, error) {
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedWebFactory) singleConfig(t *testing.T) webobservation.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("Web factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

func (f *scriptedWebPathFactory) New(config webpath.Config) (webpath.Observer, error) {
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedWebPathFactory) singleConfig(t *testing.T) webpath.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("Web-path factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

func (f *scriptedWebRecheckFactory) New(config webrecheck.Config) (webrecheck.Observer, error) {
	f.calls = append(f.calls, config)
	return f.observer, f.err
}

func (f *scriptedWebRecheckFactory) singleConfig(t *testing.T) webrecheck.Config {
	t.Helper()
	if len(f.calls) != 1 {
		t.Fatalf("Web recheck factory calls = %d, want 1", len(f.calls))
	}
	return f.calls[0]
}

type resolverFunc func(context.Context, string) systemresolver.Result

func (f resolverFunc) Resolve(ctx context.Context, hostname string) systemresolver.Result {
	return f(ctx, hostname)
}

type dnsObserverFunc func(context.Context, dnsobservation.Request) dnsobservation.Result

func (f dnsObserverFunc) Observe(
	ctx context.Context,
	request dnsobservation.Request,
) dnsobservation.Result {
	return f(ctx, request)
}

type webObserverFunc func(context.Context, webobservation.Request) webobservation.Result

func (f webObserverFunc) Observe(
	ctx context.Context,
	request webobservation.Request,
) webobservation.Result {
	return f(ctx, request)
}

type webPathObserverFunc func(context.Context, webpath.Request) webpath.Result

func (f webPathObserverFunc) Observe(
	ctx context.Context,
	request webpath.Request,
) webpath.Result {
	return f(ctx, request)
}

type webRecheckObserverFunc func(context.Context, webrecheck.Request) webrecheck.Result

func (f webRecheckObserverFunc) Observe(
	ctx context.Context,
	request webrecheck.Request,
) webrecheck.Result {
	return f(ctx, request)
}

type dnsHTTPSPathObserverFunc func(context.Context, dnshttpspath.Request) dnshttpspath.Result

func (f dnsHTTPSPathObserverFunc) Observe(
	ctx context.Context,
	request dnshttpspath.Request,
) dnshttpspath.Result {
	return f(ctx, request)
}

type sshObserverFunc func(context.Context, sshobservation.Request) sshobservation.Result

func (f sshObserverFunc) Observe(
	ctx context.Context,
	request sshobservation.Request,
) sshobservation.Result {
	return f(ctx, request)
}

type tlsObserverFunc func(context.Context, tlsobservation.Request) tlsobservation.Result

func (f tlsObserverFunc) Observe(
	ctx context.Context,
	request tlsobservation.Request,
) tlsobservation.Result {
	return f(ctx, request)
}

type tlsRetryBatchObserverFunc func(context.Context, tlsretrybatch.Request) tlsretrybatch.Result

func (f tlsRetryBatchObserverFunc) Observe(
	ctx context.Context,
	request tlsretrybatch.Request,
) tlsretrybatch.Result {
	return f(ctx, request)
}

type browserPlaceholderRunnerFunc func(
	context.Context,
	browserplaceholder.FallbackNotifier,
) browserplaceholder.Result

func (f browserPlaceholderRunnerFunc) Run(
	ctx context.Context,
	notify browserplaceholder.FallbackNotifier,
) browserplaceholder.Result {
	return f(ctx, notify)
}

type familyConditionObserverFunc func(context.Context) familycondition.Result

func (f familyConditionObserverFunc) Observe(ctx context.Context) familycondition.Result {
	return f(ctx)
}

func assertReferenceResolverConfig(t *testing.T, config dnsobservation.Config) {
	t.Helper()
	want := dnsobservation.Config{
		Timeout: phase0ProbeTimeout,
		Resolvers: []dnsobservation.ResolverEndpoint{
			{ID: resolverCloudflareWire, WireIP: netip.MustParseAddr("1.1.1.1")},
			{
				ID:           resolverCloudflareDoH,
				DoHURL:       "https://cloudflare-dns.com/dns-query",
				DoHBootstrap: netip.MustParseAddr("1.1.1.1"),
			},
			{ID: resolverGoogleWire, WireIP: netip.MustParseAddr("8.8.8.8")},
			{
				ID:           resolverGoogleDoH,
				DoHURL:       "https://dns.google/dns-query",
				DoHBootstrap: netip.MustParseAddr("8.8.8.8"),
			},
		},
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("DNS config = %#v, want %#v", config, want)
	}
}

func decodeOneJSON[T any](t *testing.T, data []byte) T {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	var result T
	if err := decoder.Decode(&result); err != nil {
		t.Fatalf("decode stdout %q: %v", string(data), err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("stdout contains more than one JSON value: %q", string(data))
	}
	return result
}

func cliFamilyConditionsSuccessResult() familycondition.Result {
	evidence := familycondition.Evidence{Conditions: []familycondition.Condition{
		{
			Family:           familycondition.FamilyIPv4,
			Network:          "udp4",
			RouteTarget:      familycondition.IPv4RouteTarget,
			Status:           familycondition.StatusRouteSelected,
			Reason:           familycondition.ReasonKernelRouteSelected,
			LocalAddress:     "192.0.2.10",
			PayloadBytesSent: 0,
		},
		{
			Family:           familycondition.FamilyIPv6,
			Network:          "udp6",
			RouteTarget:      familycondition.IPv6RouteTarget,
			Status:           familycondition.StatusUnavailable,
			Reason:           familycondition.ReasonNoRoute,
			PayloadBytesSent: 0,
		},
	}}
	return cliFamilyConditionsResult(probe.OutcomeSucceeded, &evidence, nil)
}

func cliFamilyConditionsFailureResult(
	outcome probe.Outcome,
	code probe.FailureCode,
) familycondition.Result {
	return cliFamilyConditionsResult(
		outcome,
		nil,
		&probe.Failure{Code: code, Detail: "scripted failure"},
	)
}

func cliFamilyConditionsResult(
	outcome probe.Outcome,
	evidence *familycondition.Evidence,
	failure *probe.Failure,
) familycondition.Result {
	return familycondition.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         familycondition.ProbeKind,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         familycondition.Input{},
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func cliSystemResolverSuccessResult() systemresolver.Result {
	evidence := systemresolver.Evidence{
		Addresses: []systemresolver.Address{{IP: "192.0.2.1", Family: systemresolver.FamilyIPv4}},
	}
	return cliSystemResolverResult(probe.OutcomeSucceeded, &evidence, nil)
}

func cliSystemResolverFailureResult(outcome probe.Outcome, code probe.FailureCode) systemresolver.Result {
	return cliSystemResolverResult(outcome, nil, &probe.Failure{Code: code, Detail: "scripted failure"})
}

func cliSystemResolverResult(
	outcome probe.Outcome,
	evidence *systemresolver.Evidence,
	failure *probe.Failure,
) systemresolver.Result {
	return systemresolver.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindSystemResolution,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         systemresolver.Input{Hostname: "example.com"},
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func cliInventorySuccessResult(groups ...resolverinventory.Group) resolverinventory.Result {
	evidence := resolverinventory.Evidence{Groups: groups}
	return cliInventoryResult(probe.OutcomeSucceeded, &evidence, nil)
}

func cliInventoryFailureResult(outcome probe.Outcome, code probe.FailureCode) resolverinventory.Result {
	return cliInventoryResult(outcome, nil, &probe.Failure{Code: code, Detail: "scripted failure"})
}

func cliInventoryResult(
	outcome probe.Outcome,
	evidence *resolverinventory.Evidence,
	failure *probe.Failure,
) resolverinventory.Result {
	return resolverinventory.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindResolverInventory,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         resolverinventory.Input{},
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func cliDNSSuccessResult(
	hostname string,
	queryType dnsobservation.QueryType,
	resolver dnsobservation.ResolverID,
	transport dnsobservation.Transport,
	endpoint string,
) dnsobservation.Result {
	record := dnsobservation.Record{Name: hostname, Type: queryType, TTL: 60}
	effectiveName := hostname
	switch queryType {
	case dnsobservation.QueryTypeA:
		record.Address = "192.0.2.1"
		record.Family = dnsobservation.IPFamilyIPv4
	case dnsobservation.QueryTypeAAAA:
		record.Address = "2001:db8::1"
		record.Family = dnsobservation.IPFamilyIPv6
	case dnsobservation.QueryTypeCNAME:
		record.Target = "target.example.com"
		effectiveName = record.Target
	case dnsobservation.QueryTypeSVCB, dnsobservation.QueryTypeHTTPS:
		record.Service = &dnsobservation.ServiceBinding{
			Priority: 1,
			Target:   "target.example.com",
			Mode:     dnsobservation.ServiceBindingService,
			Params:   []dnsobservation.ServiceParameter{},
		}
	}
	remoteEndpoint := cliDNSRemoteEndpoint(resolver, transport, endpoint)
	evidence := dnsobservation.Evidence{
		RCode: dnsobservation.ResponseCode{Code: 0, Name: "NOERROR"},
		Flags: dnsobservation.ResponseFlags{
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		AnswerKind:     dnsobservation.AnswerKindAnswer,
		EffectiveName:  effectiveName,
		Records:        []dnsobservation.Record{record},
		ResponseBytes:  42,
		RemoteEndpoint: remoteEndpoint,
	}
	if transport == dnsobservation.TransportDoH {
		evidence.DoHStatus = 200
	}
	return cliDNSResult(
		probe.OutcomeSucceeded,
		cliDNSInput(hostname, queryType, resolver, transport, endpoint),
		&evidence,
		nil,
	)
}

func cliDNSNoDataResult(
	hostname string,
	queryType dnsobservation.QueryType,
	resolver dnsobservation.ResolverID,
	transport dnsobservation.Transport,
	endpoint string,
) dnsobservation.Result {
	evidence := dnsobservation.Evidence{
		RCode: dnsobservation.ResponseCode{Code: 0, Name: "NOERROR"},
		Flags: dnsobservation.ResponseFlags{
			RecursionDesired: true, RecursionAvailable: true,
		},
		AnswerKind:     dnsobservation.AnswerKindNoData,
		EffectiveName:  hostname,
		Records:        []dnsobservation.Record{},
		ResponseBytes:  42,
		RemoteEndpoint: cliDNSRemoteEndpoint(resolver, transport, endpoint),
	}
	if transport == dnsobservation.TransportDoH {
		evidence.DoHStatus = 200
	}
	return cliDNSResult(
		probe.OutcomeSucceeded,
		cliDNSInput(hostname, queryType, resolver, transport, endpoint),
		&evidence,
		nil,
	)
}

func cliDNSRemoteEndpoint(
	resolver dnsobservation.ResolverID,
	transport dnsobservation.Transport,
	endpoint string,
) string {
	if transport != dnsobservation.TransportDoH {
		return endpoint
	}
	switch resolver {
	case resolverCloudflareDoH:
		return "1.1.1.1:443"
	case resolverGoogleDoH:
		return "8.8.8.8:443"
	default:
		return "192.0.2.53:443"
	}
}

func cliDNSHTTPSPathSuccessResult(
	resolver dnsobservation.ResolverID,
	transport dnsobservation.Transport,
	endpoint string,
) dnshttpspath.Result {
	https := cliDNSNoDataResult(
		"example.com", dnsobservation.QueryTypeHTTPS, resolver, transport, endpoint,
	)
	a := cliDNSSuccessResult(
		"example.com", dnsobservation.QueryTypeA, resolver, transport, endpoint,
	)
	aaaa := cliDNSSuccessResult(
		"example.com", dnsobservation.QueryTypeAAAA, resolver, transport, endpoint,
	)
	return dnshttpspath.Result{
		SchemaVersion: dnshttpspath.SchemaVersion,
		Operation:     dnshttpspath.Operation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    3,
		Platform:      cliPlatform(),
		Input: dnshttpspath.Input{
			Hostname: "example.com", Resolver: resolver, Transport: transport,
			QueryType: dnsobservation.QueryTypeHTTPS, AliasLimit: 3, ServiceTargetLimit: 8,
			AddressQueryTypes: []dnsobservation.QueryType{
				dnsobservation.QueryTypeA, dnsobservation.QueryTypeAAAA,
			},
		},
		Status:            dnshttpspath.StatusCompleted,
		Completion:        dnshttpspath.CompletionOriginFallback,
		HTTPSObservations: []dnsobservation.Result{https},
		ServiceBindings:   []dnshttpspath.BindingDecision{},
		AddressTargets: []dnshttpspath.AddressTarget{{
			Hostname: "example.com", Source: dnshttpspath.TargetOriginFallback,
			Observations: []dnsobservation.Result{a, aaaa},
		}},
	}
}

func cliDNSHTTPSPathTerminalResult(
	status dnshttpspath.Status,
	reason dnshttpspath.StopReason,
	detail string,
) dnshttpspath.Result {
	return dnshttpspath.Result{
		SchemaVersion: dnshttpspath.SchemaVersion,
		Operation:     dnshttpspath.Operation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Input: dnshttpspath.Input{
			Hostname: "example.com", Resolver: resolverCloudflareWire,
			Transport: dnsobservation.TransportUDP, QueryType: dnsobservation.QueryTypeHTTPS,
			AliasLimit: 3, ServiceTargetLimit: 8,
			AddressQueryTypes: []dnsobservation.QueryType{
				dnsobservation.QueryTypeA, dnsobservation.QueryTypeAAAA,
			},
		},
		Status: status, StopReason: reason, Detail: detail,
		HTTPSObservations: []dnsobservation.Result{},
		ServiceBindings:   []dnshttpspath.BindingDecision{},
		AddressTargets:    []dnshttpspath.AddressTarget{},
	}
}

func cliDNSFailureResult(
	outcome probe.Outcome,
	code probe.FailureCode,
	resolver dnsobservation.ResolverID,
	endpoint string,
) dnsobservation.Result {
	return cliDNSResult(
		outcome,
		cliDNSInput(
			"example.com",
			dnsobservation.QueryTypeA,
			resolver,
			dnsobservation.TransportUDP,
			endpoint,
		),
		nil,
		&probe.Failure{Code: code, Detail: "scripted failure"},
	)
}

func cliDNSInput(
	hostname string,
	queryType dnsobservation.QueryType,
	resolver dnsobservation.ResolverID,
	transport dnsobservation.Transport,
	endpoint string,
) dnsobservation.Input {
	return dnsobservation.Input{
		Hostname:  hostname,
		QueryType: queryType,
		Class:     "IN",
		Resolver: dnsobservation.ResolverInput{
			ID:       resolver,
			Endpoint: endpoint,
		},
		Transport: transport,
	}
}

func cliDNSResult(
	outcome probe.Outcome,
	input dnsobservation.Input,
	evidence *dnsobservation.Evidence,
	failure *probe.Failure,
) dnsobservation.Result {
	return dnsobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         dnsobservation.ProbeKind,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         input,
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func cliWebSuccessResult(hostname, dialIP string) webobservation.Result {
	input := cliWebInput(webobservation.SchemeHTTP, hostname, dialIP)
	evidence := webobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(dialIP), input.Port).String(),
		TCPConnectMS:   1,
		HTTP: webobservation.HTTPObservation{
			Protocol:   "HTTP/1.1",
			StatusCode: 204,
			TTFBMS:     1,
		},
	}
	return cliWebResult(probe.OutcomeSucceeded, input, &evidence, nil)
}

func cliWebFailureResult(
	scheme webobservation.Scheme,
	hostname string,
	dialIP string,
	outcome probe.Outcome,
	code probe.FailureCode,
) webobservation.Result {
	return cliWebResult(
		outcome,
		cliWebInput(scheme, hostname, dialIP),
		nil,
		&probe.Failure{Code: code, Detail: "scripted failure"},
	)
}

func cliWebInvalidInputResult(hostname, dialIP string) webobservation.Result {
	return cliWebResult(
		probe.OutcomeFailed,
		cliWebInput(webobservation.SchemeHTTP, hostname, dialIP),
		nil,
		&probe.Failure{Code: probe.FailureInvalidInput, Detail: "scripted invalid input"},
	)
}

func cliWebInput(
	scheme webobservation.Scheme,
	hostname string,
	dialIP string,
) webobservation.Input {
	input := webobservation.Input{
		Scheme:   scheme,
		Hostname: hostname,
		DialIP:   dialIP,
		Method:   "GET",
		Path:     "/",
	}
	switch scheme {
	case webobservation.SchemeHTTP:
		input.Port = 80
	case webobservation.SchemeHTTPS:
		input.Port = 443
	}
	if address, err := netip.ParseAddr(dialIP); err == nil {
		if address.Unmap().Is4() {
			input.Family = webobservation.FamilyIPv4
		} else {
			input.Family = webobservation.FamilyIPv6
		}
	}
	return input
}

func cliWebResult(
	outcome probe.Outcome,
	input webobservation.Input,
	evidence *webobservation.Evidence,
	failure *probe.Failure,
) webobservation.Result {
	return webobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindWebObservation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    3,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         input,
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func cliWebPathCompletedResult() webpath.Result {
	address := "8.8.8.8"
	resolutionEvidence := systemresolver.Evidence{
		Addresses: []systemresolver.Address{{IP: address, Family: systemresolver.FamilyIPv4}},
	}
	resolution := systemresolver.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindSystemResolution,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         systemresolver.Input{Hostname: "example.com"},
		Outcome:       probe.OutcomeSucceeded,
		Evidence:      &resolutionEvidence,
	}
	webInput := cliWebInput(webobservation.SchemeHTTPS, "example.com", address)
	webEvidence := webobservation.Evidence{
		RemoteEndpoint: "8.8.8.8:443",
		TCPConnectMS:   1,
		TLS: &webobservation.TLSObservation{
			ServerName: "example.com", Version: "TLS1.3", CipherSuite: "TLS_AES_128_GCM_SHA256",
			HandshakeMS: 1, VerifiedChains: 1,
			Leaf: webobservation.LeafCertificate{
				SHA256:    strings.Repeat("a", 64),
				NotBefore: cliObservedAt().Add(-time.Hour),
				NotAfter:  cliObservedAt().Add(time.Hour),
			},
		},
		HTTP: webobservation.HTTPObservation{
			Protocol: "HTTP/1.1", StatusCode: 204, TTFBMS: 1,
		},
	}
	webResult := cliWebResult(probe.OutcomeSucceeded, webInput, &webEvidence, nil)
	result := cliWebPathEmptyResult(
		"example.com",
		webpath.StatusCompleted,
		webpath.StopFinalResponse,
	)
	result.Hops = []webpath.Hop{{
		URL: "https://example.com/", Resolution: resolution,
		Attempts: []webobservation.Result{webResult},
	}}
	return result
}

func cliWebPathEmptyResult(
	hostname string,
	status webpath.Status,
	reason webpath.StopReason,
) webpath.Result {
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	return webpath.Result{
		SchemaVersion: webpath.SchemaVersion,
		Operation:     webpath.Operation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Input: webpath.Input{
			Hostname: normalized, InitialURL: "https://" + normalized + "/", Method: "GET",
			RedirectLimit: 3, CandidateLimitPerFamily: 2,
		},
		Status: status, StopReason: reason, Hops: []webpath.Hop{},
	}
}

func cliWebRecheckCompletedResult(
	local []string,
	reference []string,
) webrecheck.Result {
	result := webrecheck.Result{
		SchemaVersion:              webrecheck.SchemaVersion,
		Operation:                  webrecheck.Operation,
		ObservedAt:                 cliObservedAt(),
		DurationMS:                 4,
		Platform:                   cliPlatform(),
		Input:                      cliWebRecheckInput(local, reference),
		Status:                     webrecheck.StatusCompleted,
		LocalCandidatesOmitted:     max(0, len(local)-2),
		ReferenceCandidatesOmitted: max(0, len(reference)-2),
		Attempts:                   []webrecheck.Attempt{},
	}
	for index := range max(min(len(local), 2), min(len(reference), 2)) {
		if index < len(local) && index < 2 {
			result.Attempts = append(result.Attempts, webrecheck.Attempt{
				CandidateSource: webrecheck.CandidateLocal,
				Observation: cliWebFailureResult(
					webobservation.SchemeHTTPS,
					"example.com",
					local[index],
					probe.OutcomeFailed,
					webobservation.FailureTCPConnectionRefused,
				),
			})
		}
		if index < len(reference) && index < 2 {
			result.Attempts = append(result.Attempts, webrecheck.Attempt{
				CandidateSource: webrecheck.CandidateReference,
				Observation: cliWebFailureResult(
					webobservation.SchemeHTTPS,
					"example.com",
					reference[index],
					probe.OutcomeFailed,
					webobservation.FailureTCPConnectionRefused,
				),
			})
		}
	}
	return result
}

func cliWebRecheckEmptyResult(
	status webrecheck.Status,
	reason webrecheck.StopReason,
	detail string,
) webrecheck.Result {
	return webrecheck.Result{
		SchemaVersion: webrecheck.SchemaVersion,
		Operation:     webrecheck.Operation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    1,
		Platform:      cliPlatform(),
		Input: cliWebRecheckInput(
			[]string{"8.8.8.8"},
			[]string{"1.1.1.1"},
		),
		Status: status, StopReason: reason, Detail: detail,
		Attempts: []webrecheck.Attempt{},
	}
}

func cliWebRecheckInput(local, reference []string) webrecheck.Input {
	return webrecheck.Input{
		Hostname:                "example.com",
		URL:                     "https://example.com/",
		Scheme:                  webobservation.SchemeHTTPS,
		Family:                  webobservation.FamilyIPv4,
		Port:                    443,
		Method:                  "GET",
		Path:                    "/",
		CandidateLimitPerSource: 2,
		RetryLimit:              0,
		RedirectLimit:           0,
		LocalCandidates:         append([]string(nil), local...),
		ReferenceCandidates:     append([]string(nil), reference...),
	}
}

func cliSSHReceivedResult(dialIP string, port uint16) sshobservation.Result {
	evidence := sshobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(dialIP), port).String(),
		TCPConnectMS:   1,
		Identification: sshobservation.Identification{
			Status:                   sshobservation.IdentificationReceived,
			ServerIdentification:     "SSH-2.0-OpenSSH_9.9 test",
			ProtocolVersion:          "2.0",
			SoftwareVersion:          "OpenSSH_9.9",
			Comments:                 "test",
			ClientIdentificationSent: true,
			ExchangeMS:               1,
		},
	}
	return cliSSHResult(
		probe.OutcomeSucceeded,
		cliSSHInput(dialIP, port),
		&evidence,
		nil,
	)
}

func cliSSHUnconfirmedResult(dialIP string, port uint16) sshobservation.Result {
	evidence := sshobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(dialIP), port).String(),
		TCPConnectMS:   1,
		Identification: sshobservation.Identification{
			Status:                   sshobservation.IdentificationUnconfirmed,
			UnconfirmedReason:        sshobservation.UnconfirmedTimeout,
			ClientIdentificationSent: true,
			ExchangeMS:               1,
		},
	}
	return cliSSHResult(
		probe.OutcomeSucceeded,
		cliSSHInput(dialIP, port),
		&evidence,
		nil,
	)
}

func cliSSHFailureResult(
	dialIP string,
	port uint16,
	outcome probe.Outcome,
	code probe.FailureCode,
) sshobservation.Result {
	return cliSSHResult(
		outcome,
		cliSSHInput(dialIP, port),
		nil,
		&probe.Failure{Code: code, Detail: "scripted failure"},
	)
}

func cliSSHInvalidInputResult(dialIP string, port uint16) sshobservation.Result {
	return cliSSHResult(
		probe.OutcomeFailed,
		cliSSHInput(dialIP, port),
		nil,
		&probe.Failure{Code: probe.FailureInvalidInput, Detail: "scripted invalid input"},
	)
}

func cliSSHInput(dialIP string, port uint16) sshobservation.Input {
	input := sshobservation.Input{
		DialIP:               dialIP,
		Port:                 port,
		ClientIdentification: sshobservation.ClientIdentification,
	}
	if address, err := netip.ParseAddr(dialIP); err == nil {
		if address.Unmap().Is4() {
			input.Family = sshobservation.FamilyIPv4
		} else {
			input.Family = sshobservation.FamilyIPv6
		}
	}
	return input
}

func cliSSHResult(
	outcome probe.Outcome,
	input sshobservation.Input,
	evidence *sshobservation.Evidence,
	failure *probe.Failure,
) sshobservation.Result {
	return sshobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindSSHObservation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    3,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         input,
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func cliTLSCompletedResult(dialIP string) tlsobservation.Result {
	notBefore := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	evidence := tlsobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(dialIP), tlsobservation.Port).String(),
		TCPConnectMS:   1,
		TLS: tlsobservation.TLS{
			Status:           tlsobservation.TLSCompleted,
			HandshakeMS:      1,
			Version:          "TLS1.3",
			CipherSuite:      "TLS_AES_128_GCM_SHA256",
			PeerCertificates: 1,
			Leaf: &tlsobservation.LeafCertificate{
				SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				NotBefore: notBefore,
				NotAfter:  notBefore.Add(24 * time.Hour),
			},
		},
	}
	return cliTLSResult(probe.OutcomeSucceeded, cliTLSInput(dialIP), &evidence, nil)
}

func cliTLSUnconfirmedResult(dialIP string) tlsobservation.Result {
	evidence := tlsobservation.Evidence{
		RemoteEndpoint: netip.AddrPortFrom(netip.MustParseAddr(dialIP), tlsobservation.Port).String(),
		TCPConnectMS:   1,
		TLS: tlsobservation.TLS{
			Status:            tlsobservation.TLSUnconfirmed,
			UnconfirmedReason: tlsobservation.UnconfirmedHandshakeTimeout,
			HandshakeMS:       1,
		},
	}
	return cliTLSResult(probe.OutcomeSucceeded, cliTLSInput(dialIP), &evidence, nil)
}

func cliTLSFailureResult(
	dialIP string,
	outcome probe.Outcome,
	code probe.FailureCode,
) tlsobservation.Result {
	return cliTLSResult(
		outcome,
		cliTLSInput(dialIP),
		nil,
		&probe.Failure{Code: code, Detail: "scripted failure"},
	)
}

func cliTLSInvalidInputResult(dialIP string) tlsobservation.Result {
	return cliTLSResult(
		probe.OutcomeFailed,
		cliTLSInput(dialIP),
		nil,
		&probe.Failure{Code: probe.FailureInvalidInput, Detail: "scripted invalid input"},
	)
}

func cliTLSInput(dialIP string) tlsobservation.Input {
	input := tlsobservation.Input{
		DialIP:               dialIP,
		Port:                 tlsobservation.Port,
		SNIMode:              tlsobservation.SNIOmittedNoHostname,
		IdentityVerification: tlsobservation.IdentityNotPerformedNoHostname,
	}
	if address, err := netip.ParseAddr(dialIP); err == nil {
		if address.Unmap().Is4() {
			input.Family = tlsobservation.FamilyIPv4
		} else {
			input.Family = tlsobservation.FamilyIPv6
		}
	}
	return input
}

func cliTLSResult(
	outcome probe.Outcome,
	input tlsobservation.Input,
	evidence *tlsobservation.Evidence,
	failure *probe.Failure,
) tlsobservation.Result {
	return tlsobservation.Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         probe.KindTLSObservation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    3,
		Platform:      cliPlatform(),
		Source:        cliSource(),
		Input:         input,
		Outcome:       outcome,
		Evidence:      evidence,
		Failure:       failure,
	}
}

func cliTLSRetryBatchCompletedResult(targets []string) tlsretrybatch.Result {
	result := cliTLSRetryBatchResult(targets, tlsretrybatch.StatusCompleted, "", "")
	for _, target := range targets[:min(len(targets), 4)] {
		result.Targets = append(result.Targets, tlsretrybatch.TargetResult{
			DialIP: target,
			Family: cliTLSInput(target).Family,
			Status: tlsretrybatch.TargetCompleted,
			Attempts: []tlsretrybatch.Attempt{{
				Number: 1,
				Observation: cliTLSFailureResult(
					target,
					probe.OutcomeFailed,
					tlsobservation.FailureTCPConnectionRefused,
				),
			}},
		})
	}
	result.TargetsOmitted = max(0, len(targets)-4)
	return result
}

func cliTLSRetryBatchStoppedResult(target string) tlsretrybatch.Result {
	result := cliTLSRetryBatchResult(
		[]string{target},
		tlsretrybatch.StatusStopped,
		tlsretrybatch.StopBatchTimeout,
		"context deadline exceeded",
	)
	result.Targets = append(result.Targets, tlsretrybatch.TargetResult{
		DialIP: target,
		Family: cliTLSInput(target).Family,
		Status: tlsretrybatch.TargetInterrupted,
		Attempts: []tlsretrybatch.Attempt{{
			Number: 1,
			Observation: cliTLSFailureResult(
				target,
				probe.OutcomeFailed,
				tlsobservation.FailureTCPTimeout,
			),
		}},
	})
	return result
}

func cliTLSRetryBatchCancelledResult(target string) tlsretrybatch.Result {
	result := cliTLSRetryBatchResult(
		[]string{target},
		tlsretrybatch.StatusCancelled,
		tlsretrybatch.StopCancelled,
		"context canceled",
	)
	result.Targets = append(result.Targets, tlsretrybatch.TargetResult{
		DialIP:   target,
		Family:   cliTLSInput(target).Family,
		Status:   tlsretrybatch.TargetNotStarted,
		Attempts: []tlsretrybatch.Attempt{},
	})
	return result
}

func cliTLSRetryBatchInvalidResult(target string) tlsretrybatch.Result {
	return cliTLSRetryBatchResult(
		[]string{target},
		tlsretrybatch.StatusStopped,
		tlsretrybatch.StopInvalidInput,
		"scripted invalid input",
	)
}

func cliTLSRetryBatchResult(
	targets []string,
	status tlsretrybatch.Status,
	reason tlsretrybatch.StopReason,
	detail string,
) tlsretrybatch.Result {
	return tlsretrybatch.Result{
		SchemaVersion: tlsretrybatch.SchemaVersion,
		Operation:     tlsretrybatch.Operation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    4,
		Platform:      cliPlatform(),
		Input: tlsretrybatch.Input{
			Targets:              append([]string(nil), targets...),
			TargetLimit:          4,
			ConcurrencyLimit:     2,
			AttemptLimit:         3,
			RetryLimit:           2,
			Port:                 tlsobservation.Port,
			SNIMode:              tlsobservation.SNIOmittedNoHostname,
			IdentityVerification: tlsobservation.IdentityNotPerformedNoHostname,
			PerAttemptTimeoutMS:  5000,
			BackoffMinMS:         100,
			BackoffMaxMS:         300,
		},
		Status:     status,
		StopReason: reason,
		Detail:     detail,
		Targets:    []tlsretrybatch.TargetResult{},
	}
}

const cliBrowserPlaceholderURL = "http://127.0.0.1:40000/"

func cliBrowserPlaceholderCompletedResult(withFallback bool) browserplaceholder.Result {
	result := cliBrowserPlaceholderResult(browserplaceholder.StatusCompleted, "", "")
	result.Completion = browserplaceholder.CompletionPageRequested
	result.PageRequest = &browserplaceholder.PageRequest{
		Method: "GET",
		Host:   "127.0.0.1:40000",
		Path:   "/",
	}
	if withFallback {
		attempt := cliBrowserPlaceholderFailedAttempt()
		result.OpenAttempt = &attempt
		result.FallbackNotified = true
	}
	return result
}

func cliBrowserPlaceholderStoppedResult() browserplaceholder.Result {
	return cliBrowserPlaceholderResult(
		browserplaceholder.StatusStopped,
		browserplaceholder.StopPlaceholderTimeout,
		"context deadline exceeded",
	)
}

func cliBrowserPlaceholderCancelledResult() browserplaceholder.Result {
	return cliBrowserPlaceholderResult(
		browserplaceholder.StatusCancelled,
		browserplaceholder.StopCancelled,
		"context canceled",
	)
}

func cliBrowserPlaceholderFallback() *browserplaceholder.Fallback {
	attempt := cliBrowserPlaceholderFailedAttempt()
	return &browserplaceholder.Fallback{
		URL:     cliBrowserPlaceholderURL,
		Failure: *attempt.Failure,
	}
}

func cliBrowserPlaceholderFailedAttempt() browseropener.Result {
	return browseropener.Result{
		Backend: "scripted-browser",
		URL:     cliBrowserPlaceholderURL,
		Status:  browseropener.StatusFailed,
		Failure: &browseropener.Failure{
			Code:   browseropener.FailureLaunchFailed,
			Detail: "scripted browser launch failure",
		},
	}
}

func cliBrowserPlaceholderResult(
	status browserplaceholder.Status,
	reason browserplaceholder.StopReason,
	detail string,
) browserplaceholder.Result {
	attempt := browseropener.Result{
		Backend: "scripted-browser",
		URL:     cliBrowserPlaceholderURL,
		Status:  browseropener.StatusOpened,
	}
	return browserplaceholder.Result{
		SchemaVersion: browserplaceholder.SchemaVersion,
		Operation:     browserplaceholder.Operation,
		ObservedAt:    cliObservedAt(),
		DurationMS:    4,
		Platform:      cliPlatform(),
		Input: browserplaceholder.Input{
			ListenNetwork: "tcp4",
			ListenAddress: "127.0.0.1:0",
			Path:          "/",
			OpenTimeoutMS: 5000,
			TimeoutMS:     phase0BrowserPlaceholderTimeout.Milliseconds(),
		},
		URL:         cliBrowserPlaceholderURL,
		OpenAttempt: &attempt,
		Status:      status,
		StopReason:  reason,
		Detail:      detail,
	}
}

func cliObservedAt() time.Time {
	return time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
}

func cliPlatform() probe.Platform {
	return probe.Platform{OS: "testos", Arch: "testarch"}
}

func cliSource() probe.Source {
	return probe.Source{Backend: "scripted", Capability: probe.CapabilityNative}
}
