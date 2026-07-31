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
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			resolver := systemresolvertest.New()
			inventory := resolverinventorytest.New()
			factory := &scriptedDNSFactory{observer: dnsobservationtest.New()}
			var stdout bytes.Buffer
			var stderr bytes.Buffer

			code := run(
				context.Background(),
				args,
				&stdout,
				&stderr,
				dependencies{
					systemResolver:    resolver,
					resolverInventory: inventory,
					newDNSObserver:    factory.New,
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
				!strings.Contains(stderr.String(), "reachrun dns-observe") {
				t.Fatalf("stderr = %q, want Phase 0 usage", stderr.String())
			}
			if len(resolver.Calls()) != 0 || len(inventory.Calls()) != 0 || len(factory.calls) != 0 {
				t.Fatalf(
					"dependency calls = resolver %#v, inventory %#v, factory %#v; want none",
					resolver.Calls(),
					inventory.Calls(),
					factory.calls,
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

func cliObservedAt() time.Time {
	return time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC)
}

func cliPlatform() probe.Platform {
	return probe.Platform{OS: "testos", Arch: "testarch"}
}

func cliSource() probe.Source {
	return probe.Source{Backend: "scripted", Capability: probe.CapabilityNative}
}
