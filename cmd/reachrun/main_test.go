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

	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/dnsobservation/dnsobservationtest"
	"github.com/wangjc683/reachrun/internal/platform/resolverinventory"
	"github.com/wangjc683/reachrun/internal/platform/resolverinventory/resolverinventorytest"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver/systemresolvertest"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/sshobservation"
	"github.com/wangjc683/reachrun/internal/sshobservation/sshobservationtest"
	"github.com/wangjc683/reachrun/internal/webobservation"
	"github.com/wangjc683/reachrun/internal/webobservation/webobservationtest"
	"github.com/wangjc683/reachrun/internal/webpath"
	"github.com/wangjc683/reachrun/internal/webpath/webpathtest"
)

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
		"empty":                        nil,
		"resolve missing hostname":     {"resolve"},
		"resolve extra argument":       {"resolve", "example.com", "extra"},
		"inventory extra argument":     {"resolver-inventory", "extra"},
		"DNS missing argument":         {"dns-observe", "udp", "cloudflare", "A"},
		"DNS extra argument":           {"dns-observe", "udp", "cloudflare", "A", "example.com", "extra"},
		"unknown command":              {"inspect"},
		"unknown transport":            {"dns-observe", "UDP", "cloudflare", "A", "example.com"},
		"unknown provider":             {"dns-observe", "udp", "quad9", "A", "example.com"},
		"lowercase query type":         {"dns-observe", "udp", "cloudflare", "a", "example.com"},
		"current does not support DoH": {"dns-observe", "doh", "current", "A", "example.com"},
		"Web missing argument":         {"web-observe", "https", "example.com"},
		"Web extra argument":           {"web-observe", "https", "example.com", "93.184.216.34", "extra"},
		"unknown Web scheme":           {"web-observe", "HTTPS", "example.com", "93.184.216.34"},
		"Web path missing hostname":    {"web-path"},
		"Web path extra argument":      {"web-path", "example.com", "extra"},
		"SSH missing IP":               {"ssh-observe"},
		"SSH extra argument":           {"ssh-observe", "93.184.216.34", "22", "extra"},
		"SSH nonnumeric port":          {"ssh-observe", "93.184.216.34", "ssh"},
		"SSH zero port":                {"ssh-observe", "93.184.216.34", "0"},
		"SSH oversized port":           {"ssh-observe", "93.184.216.34", "65536"},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolver := systemresolvertest.New()
			inventory := resolverinventorytest.New()
			factory := &scriptedDNSFactory{observer: dnsobservationtest.New()}
			webFactory := &scriptedWebFactory{observer: webobservationtest.New()}
			webPathFactory := &scriptedWebPathFactory{observer: webpathtest.New()}
			sshFactory := &scriptedSSHFactory{observer: sshobservationtest.New()}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				args,
				&stdout,
				&stderr,
				dependencies{
					systemResolver:     resolver,
					resolverInventory:  inventory,
					newDNSObserver:     factory.New,
					newWebObserver:     webFactory.New,
					newWebPathObserver: webPathFactory.New,
					newSSHObserver:     sshFactory.New,
				},
			)
			if code != 2 {
				t.Fatalf("run() = %d, want 2", code)
			}
			if stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty", stdout.String())
			}
			if !strings.Contains(stderr.String(), "Phase 0 diagnostic") ||
				!strings.Contains(stderr.String(), "reachrun resolver-inventory") ||
				!strings.Contains(stderr.String(), "reachrun dns-observe") ||
				!strings.Contains(stderr.String(), "reachrun web-observe") ||
				!strings.Contains(stderr.String(), "reachrun web-path") ||
				!strings.Contains(stderr.String(), "reachrun ssh-observe") {
				t.Fatalf("stderr = %q, want Phase 0 usage", stderr.String())
			}
			if len(resolver.Calls()) != 0 || len(inventory.Calls()) != 0 ||
				len(factory.calls) != 0 || len(webFactory.calls) != 0 ||
				len(webPathFactory.calls) != 0 || len(sshFactory.calls) != 0 {
				t.Fatalf(
					"dependency calls = resolver %#v, inventory %#v, DNS factory %#v, Web factory %#v, Web-path factory %#v, SSH factory %#v; want none",
					resolver.Calls(),
					inventory.Calls(),
					factory.calls,
					webFactory.calls,
					webPathFactory.calls,
					sshFactory.calls,
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
		"SSH observation": {
			args: []string{"ssh-observe", "93.184.216.34"},
			deps: dependencies{
				newSSHObserver: (&scriptedSSHFactory{
					observer: sshobservationtest.New(sshobservation.Result{}),
				}).New,
			},
			wantError: "invalid SSH observation result",
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

type scriptedDNSFactory struct {
	observer dnsobservation.Observer
	err      error
	calls    []dnsobservation.Config
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

type scriptedSSHFactory struct {
	observer sshobservation.Observer
	err      error
	calls    []sshobservation.Config
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

type sshObserverFunc func(context.Context, sshobservation.Request) sshobservation.Result

func (f sshObserverFunc) Observe(
	ctx context.Context,
	request sshobservation.Request,
) sshobservation.Result {
	return f(ctx, request)
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
	}
	remoteEndpoint := endpoint
	if transport == dnsobservation.TransportDoH {
		switch resolver {
		case resolverCloudflareDoH:
			remoteEndpoint = "1.1.1.1:443"
		case resolverGoogleDoH:
			remoteEndpoint = "8.8.8.8:443"
		default:
			remoteEndpoint = "192.0.2.53:443"
		}
	}
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

func cliObservedAt() time.Time {
	return time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
}

func cliPlatform() probe.Platform {
	return probe.Platform{OS: "testos", Arch: "testarch"}
}

func cliSource() probe.Source {
	return probe.Source{Backend: "scripted", Capability: probe.CapabilityNative}
}
