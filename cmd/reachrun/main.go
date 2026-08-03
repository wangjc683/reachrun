// Command reachrun contains the temporary Phase 0 diagnostic CLI. The V1 user
// entry point will become the local browser application in a later phase.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/wangjc683/reachrun/internal/dnshttpspath"
	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/platform/familycondition"
	"github.com/wangjc683/reachrun/internal/platform/resolverinventory"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/sshobservation"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
	"github.com/wangjc683/reachrun/internal/webobservation"
	"github.com/wangjc683/reachrun/internal/webpath"
	"github.com/wangjc683/reachrun/internal/webrecheck"
)

const (
	phase0ProbeTimeout        = 5 * time.Second
	phase0WebPathTimeout      = 15 * time.Second
	phase0DNSHTTPSPathTimeout = 30 * time.Second
	phase0WebRecheckTimeout   = 25 * time.Second
)

const (
	resolverCurrent        dnsobservation.ResolverID = "current"
	resolverCloudflareWire dnsobservation.ResolverID = "cloudflare-wire"
	resolverCloudflareDoH  dnsobservation.ResolverID = "cloudflare-doh"
	resolverGoogleWire     dnsobservation.ResolverID = "google-wire"
	resolverGoogleDoH      dnsobservation.ResolverID = "google-doh"
)

type dnsObserverFactory func(dnsobservation.Config) (dnsobservation.Observer, error)
type dnsHTTPSPathObserverFactory func(dnshttpspath.Config) (dnshttpspath.Observer, error)
type webObserverFactory func(webobservation.Config) (webobservation.Observer, error)
type webPathObserverFactory func(webpath.Config) (webpath.Observer, error)
type webRecheckObserverFactory func(webrecheck.Config) (webrecheck.Observer, error)
type sshObserverFactory func(sshobservation.Config) (sshobservation.Observer, error)
type tlsObserverFactory func(tlsobservation.Config) (tlsobservation.Observer, error)
type familyConditionObserverFactory func(familycondition.Config) (familycondition.Observer, error)

type dependencies struct {
	systemResolver             systemresolver.Resolver
	resolverInventory          resolverinventory.Observer
	newDNSObserver             dnsObserverFactory
	newDNSHTTPSPathObserver    dnsHTTPSPathObserverFactory
	newWebObserver             webObserverFactory
	newWebPathObserver         webPathObserverFactory
	newWebRecheckObserver      webRecheckObserverFactory
	newSSHObserver             sshObserverFactory
	newTLSObserver             tlsObserverFactory
	newFamilyConditionObserver familyConditionObserverFactory
}

func main() {
	os.Exit(mainExitCode())
}

func mainExitCode() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	return run(ctx, os.Args[1:], os.Stdout, os.Stderr, productionDependencies())
}

func productionDependencies() dependencies {
	return dependencies{
		systemResolver:             systemresolver.New(),
		resolverInventory:          resolverinventory.New(),
		newDNSObserver:             dnsobservation.New,
		newDNSHTTPSPathObserver:    dnshttpspath.New,
		newWebObserver:             webobservation.New,
		newWebPathObserver:         webpath.New,
		newWebRecheckObserver:      webrecheck.New,
		newSSHObserver:             sshobservation.New,
		newTLSObserver:             tlsobservation.New,
		newFamilyConditionObserver: familycondition.New,
	}
}

func run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	deps dependencies,
) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "family-conditions":
		if len(args) != 1 {
			printUsage(stderr)
			return 2
		}
		return runFamilyConditions(ctx, stdout, stderr, deps.newFamilyConditionObserver)
	case "resolve":
		if len(args) != 2 {
			printUsage(stderr)
			return 2
		}
		return runResolve(ctx, args[1], stdout, stderr, deps.systemResolver)
	case "resolver-inventory":
		if len(args) != 1 {
			printUsage(stderr)
			return 2
		}
		return runResolverInventory(ctx, stdout, stderr, deps.resolverInventory)
	case "dns-observe":
		request, provider, ok := parseDNSObservationArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runDNSObservation(ctx, request, provider, stdout, stderr, deps)
	case "dns-https-path":
		request, provider, ok := parseDNSHTTPSPathArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runDNSHTTPSPath(ctx, request, provider, stdout, stderr, deps)
	case "web-observe":
		request, ok := parseWebObservationArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runWebObservation(ctx, request, stdout, stderr, deps.newWebObserver)
	case "web-path":
		if len(args) != 2 {
			printUsage(stderr)
			return 2
		}
		return runWebPath(
			ctx,
			webpath.Request{Hostname: args[1]},
			stdout,
			stderr,
			deps.newWebPathObserver,
		)
	case "web-recheck":
		request, ok := parseWebRecheckArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runWebRecheck(ctx, request, stdout, stderr, deps.newWebRecheckObserver)
	case "ssh-observe":
		request, ok := parseSSHObservationArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runSSHObservation(ctx, request, stdout, stderr, deps.newSSHObserver)
	case "tls-observe":
		request, ok := parseTLSObservationArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runTLSObservation(ctx, request, stdout, stderr, deps.newTLSObserver)
	default:
		printUsage(stderr)
		return 2
	}
}

func runFamilyConditions(
	ctx context.Context,
	stdout io.Writer,
	stderr io.Writer,
	newObserver familyConditionObserverFactory,
) int {
	probeContext, cancel := context.WithTimeout(ctx, phase0ProbeTimeout)
	defer cancel()

	observer, err := newObserver(familycondition.Config{Timeout: phase0ProbeTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create address-family-condition observer: %v\n", err)
		return 1
	}
	result := observer.Observe(probeContext)
	if err := familycondition.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid address-family-condition result: %v\n", err)
		return 1
	}
	return emitResult(stdout, stderr, result, result.Outcome)
}

func runTLSObservation(
	ctx context.Context,
	request tlsobservation.Request,
	stdout io.Writer,
	stderr io.Writer,
	newObserver tlsObserverFactory,
) int {
	probeContext, cancel := context.WithTimeout(ctx, phase0ProbeTimeout)
	defer cancel()

	observer, err := newObserver(tlsobservation.Config{Timeout: phase0ProbeTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create TLS observer: %v\n", err)
		return 1
	}
	result := observer.Observe(probeContext, request)
	if err := tlsobservation.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid TLS observation result: %v\n", err)
		return 1
	}
	return emitResult(stdout, stderr, result, result.Outcome)
}

func runWebRecheck(
	ctx context.Context,
	request webrecheck.Request,
	stdout io.Writer,
	stderr io.Writer,
	newObserver webRecheckObserverFactory,
) int {
	recheckContext, cancel := context.WithTimeout(ctx, phase0WebRecheckTimeout)
	defer cancel()

	observer, err := newObserver(webrecheck.Config{Timeout: phase0WebRecheckTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create Web candidate recheck observer: %v\n", err)
		return 1
	}
	result := observer.Observe(recheckContext, request)
	if err := webrecheck.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid Web candidate recheck result: %v\n", err)
		return 1
	}
	outcome := probe.OutcomeFailed
	switch result.Status {
	case webrecheck.StatusCompleted:
		outcome = probe.OutcomeSucceeded
	case webrecheck.StatusCancelled:
		outcome = probe.OutcomeCancelled
	}
	return emitResult(stdout, stderr, result, outcome)
}

func runWebPath(
	ctx context.Context,
	request webpath.Request,
	stdout io.Writer,
	stderr io.Writer,
	newObserver webPathObserverFactory,
) int {
	pathContext, cancel := context.WithTimeout(ctx, phase0WebPathTimeout)
	defer cancel()

	observer, err := newObserver(webpath.Config{Timeout: phase0WebPathTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create Web-path observer: %v\n", err)
		return 1
	}
	result := observer.Observe(pathContext, request)
	if err := webpath.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid Web-path result: %v\n", err)
		return 1
	}
	outcome := probe.OutcomeFailed
	switch result.Status {
	case webpath.StatusCompleted:
		outcome = probe.OutcomeSucceeded
	case webpath.StatusCancelled:
		outcome = probe.OutcomeCancelled
	}
	return emitResult(stdout, stderr, result, outcome)
}

func runSSHObservation(
	ctx context.Context,
	request sshobservation.Request,
	stdout io.Writer,
	stderr io.Writer,
	newObserver sshObserverFactory,
) int {
	probeContext, cancel := context.WithTimeout(ctx, phase0ProbeTimeout)
	defer cancel()

	observer, err := newObserver(sshobservation.Config{Timeout: phase0ProbeTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create SSH observer: %v\n", err)
		return 1
	}
	result := observer.Observe(probeContext, request)
	if err := sshobservation.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid SSH observation result: %v\n", err)
		return 1
	}
	return emitResult(stdout, stderr, result, result.Outcome)
}

func runWebObservation(
	ctx context.Context,
	request webobservation.Request,
	stdout io.Writer,
	stderr io.Writer,
	newObserver webObserverFactory,
) int {
	probeContext, cancel := context.WithTimeout(ctx, phase0ProbeTimeout)
	defer cancel()

	observer, err := newObserver(webobservation.Config{Timeout: phase0ProbeTimeout})
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create Web observer: %v\n", err)
		return 1
	}
	result := observer.Observe(probeContext, request)
	if err := webobservation.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid Web observation result: %v\n", err)
		return 1
	}
	return emitResult(stdout, stderr, result, result.Outcome)
}

func runResolve(
	ctx context.Context,
	hostname string,
	stdout io.Writer,
	stderr io.Writer,
	resolver systemresolver.Resolver,
) int {
	probeContext, cancel := context.WithTimeout(ctx, phase0ProbeTimeout)
	defer cancel()

	result := resolver.Resolve(probeContext, hostname)
	if err := systemresolver.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid system resolver result: %v\n", err)
		return 1
	}
	return emitResult(stdout, stderr, result, result.Outcome)
}

func runResolverInventory(
	ctx context.Context,
	stdout io.Writer,
	stderr io.Writer,
	observer resolverinventory.Observer,
) int {
	probeContext, cancel := context.WithTimeout(ctx, phase0ProbeTimeout)
	defer cancel()

	result := observer.Observe(probeContext)
	if err := resolverinventory.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid resolver inventory result: %v\n", err)
		return 1
	}
	return emitResult(stdout, stderr, result, result.Outcome)
}

func runDNSObservation(
	ctx context.Context,
	request dnsobservation.Request,
	provider string,
	stdout io.Writer,
	stderr io.Writer,
	deps dependencies,
) int {
	probeContext, cancel := context.WithTimeout(ctx, phase0ProbeTimeout)
	defer cancel()

	config := resolverConfigForProvider(probeContext, cancel, provider, stderr, deps)

	observer, err := deps.newDNSObserver(config)
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create DNS observer: %v\n", err)
		return 1
	}
	result := observer.Observe(probeContext, request)
	if err := dnsobservation.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid DNS observation result: %v\n", err)
		return 1
	}
	return emitResult(stdout, stderr, result, result.Outcome)
}

func runDNSHTTPSPath(
	ctx context.Context,
	request dnshttpspath.Request,
	provider string,
	stdout io.Writer,
	stderr io.Writer,
	deps dependencies,
) int {
	pathContext, cancel := context.WithTimeout(ctx, phase0DNSHTTPSPathTimeout)
	defer cancel()

	dnsConfig := resolverConfigForProvider(pathContext, cancel, provider, stderr, deps)
	observer, err := deps.newDNSHTTPSPathObserver(dnshttpspath.Config{
		DNS:     dnsConfig,
		Timeout: phase0DNSHTTPSPathTimeout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "reachrun: create DNS HTTPS-path observer: %v\n", err)
		return 1
	}
	result := observer.Observe(pathContext, request)
	if err := dnshttpspath.Validate(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: invalid DNS HTTPS-path result: %v\n", err)
		return 1
	}
	outcome := probe.OutcomeFailed
	switch result.Status {
	case dnshttpspath.StatusCompleted:
		outcome = probe.OutcomeSucceeded
	case dnshttpspath.StatusCancelled:
		outcome = probe.OutcomeCancelled
	}
	return emitResult(stdout, stderr, result, outcome)
}

func resolverConfigForProvider(
	ctx context.Context,
	cancel context.CancelFunc,
	provider string,
	stderr io.Writer,
	deps dependencies,
) dnsobservation.Config {
	config := referenceResolverConfig()
	if provider != "current" {
		return config
	}

	inventory := deps.resolverInventory.Observe(ctx)
	if resolverinventory.Validate(inventory) == nil && inventory.Outcome == probe.OutcomeCancelled {
		// Inventory is part of the same command. Preserve explicit cancellation
		// so it dominates the expected "current resolver unavailable" setup path.
		cancel()
	}
	endpoint, err := currentResolverEndpoint(inventory)
	if err != nil {
		// Keep "current" unconfigured. The selected observer returns this
		// command's terminal evidence; inventory remains diagnostic input.
		if ctx.Err() != context.Canceled {
			fmt.Fprintf(stderr, "reachrun: current resolver unavailable: %v\n", err)
		}
		return config
	}
	config.Resolvers = append(config.Resolvers, endpoint)
	return config
}

func parseDNSObservationArgs(args []string) (dnsobservation.Request, string, bool) {
	if len(args) != 5 || args[0] != "dns-observe" {
		return dnsobservation.Request{}, "", false
	}

	transport, ok := parseDNSTransport(args[1])
	if !ok {
		return dnsobservation.Request{}, "", false
	}

	provider := args[2]
	resolver, ok := resolverFor(provider, transport)
	if !ok {
		return dnsobservation.Request{}, "", false
	}

	var queryType dnsobservation.QueryType
	switch args[3] {
	case string(dnsobservation.QueryTypeA):
		queryType = dnsobservation.QueryTypeA
	case string(dnsobservation.QueryTypeAAAA):
		queryType = dnsobservation.QueryTypeAAAA
	case string(dnsobservation.QueryTypeCNAME):
		queryType = dnsobservation.QueryTypeCNAME
	case string(dnsobservation.QueryTypeSVCB):
		queryType = dnsobservation.QueryTypeSVCB
	case string(dnsobservation.QueryTypeHTTPS):
		queryType = dnsobservation.QueryTypeHTTPS
	default:
		return dnsobservation.Request{}, "", false
	}

	return dnsobservation.Request{
		Hostname:  args[4],
		QueryType: queryType,
		Resolver:  resolver,
		Transport: transport,
	}, provider, true
}

func parseDNSHTTPSPathArgs(args []string) (dnshttpspath.Request, string, bool) {
	if len(args) != 4 || args[0] != "dns-https-path" {
		return dnshttpspath.Request{}, "", false
	}
	transport, ok := parseDNSTransport(args[1])
	if !ok {
		return dnshttpspath.Request{}, "", false
	}
	provider := args[2]
	resolver, ok := resolverFor(provider, transport)
	if !ok {
		return dnshttpspath.Request{}, "", false
	}
	return dnshttpspath.Request{
		Hostname: args[3], Resolver: resolver, Transport: transport,
	}, provider, true
}

func parseWebRecheckArgs(args []string) (webrecheck.Request, bool) {
	if len(args) != 4 || args[0] != "web-recheck" {
		return webrecheck.Request{}, false
	}
	return webrecheck.Request{
		Hostname:            args[1],
		LocalCandidates:     strings.Split(args[2], ","),
		ReferenceCandidates: strings.Split(args[3], ","),
	}, true
}

func parseDNSTransport(value string) (dnsobservation.Transport, bool) {
	switch value {
	case string(dnsobservation.TransportUDP):
		return dnsobservation.TransportUDP, true
	case string(dnsobservation.TransportTCP):
		return dnsobservation.TransportTCP, true
	case string(dnsobservation.TransportDoH):
		return dnsobservation.TransportDoH, true
	default:
		return "", false
	}
}

func parseWebObservationArgs(args []string) (webobservation.Request, bool) {
	if len(args) != 4 || args[0] != "web-observe" {
		return webobservation.Request{}, false
	}

	var scheme webobservation.Scheme
	switch args[1] {
	case string(webobservation.SchemeHTTP):
		scheme = webobservation.SchemeHTTP
	case string(webobservation.SchemeHTTPS):
		scheme = webobservation.SchemeHTTPS
	default:
		return webobservation.Request{}, false
	}

	return webobservation.Request{
		Scheme:   scheme,
		Hostname: args[2],
		DialIP:   args[3],
	}, true
}

func parseSSHObservationArgs(args []string) (sshobservation.Request, bool) {
	if len(args) < 2 || len(args) > 3 || args[0] != "ssh-observe" {
		return sshobservation.Request{}, false
	}

	port := sshobservation.DefaultPort
	if len(args) == 3 {
		parsed, err := strconv.ParseUint(args[2], 10, 16)
		if err != nil || parsed == 0 {
			return sshobservation.Request{}, false
		}
		port = uint16(parsed)
	}
	return sshobservation.Request{DialIP: args[1], Port: port}, true
}

func parseTLSObservationArgs(args []string) (tlsobservation.Request, bool) {
	if len(args) != 2 || args[0] != "tls-observe" {
		return tlsobservation.Request{}, false
	}
	return tlsobservation.Request{DialIP: args[1]}, true
}

func resolverFor(provider string, transport dnsobservation.Transport) (dnsobservation.ResolverID, bool) {
	switch provider {
	case "current":
		if transport == dnsobservation.TransportDoH {
			return "", false
		}
		return resolverCurrent, true
	case "cloudflare":
		if transport == dnsobservation.TransportDoH {
			return resolverCloudflareDoH, true
		}
		return resolverCloudflareWire, true
	case "google":
		if transport == dnsobservation.TransportDoH {
			return resolverGoogleDoH, true
		}
		return resolverGoogleWire, true
	default:
		return "", false
	}
}

func referenceResolverConfig() dnsobservation.Config {
	return dnsobservation.Config{
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
}

func currentResolverEndpoint(result resolverinventory.Result) (dnsobservation.ResolverEndpoint, error) {
	if err := resolverinventory.Validate(result); err != nil {
		return dnsobservation.ResolverEndpoint{}, fmt.Errorf("invalid inventory: %w", err)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		if result.Failure != nil {
			return dnsobservation.ResolverEndpoint{}, fmt.Errorf(
				"inventory ended with %s (%s)",
				result.Outcome,
				result.Failure.Code,
			)
		}
		return dnsobservation.ResolverEndpoint{}, fmt.Errorf("inventory ended with %s", result.Outcome)
	}

	var firstRejected error
	for _, group := range result.Evidence.Groups {
		for _, server := range group.Servers {
			if server.Port != 53 {
				continue
			}
			endpoint, err := currentResolverServerEndpoint(group, server)
			if err == nil {
				return endpoint, nil
			}
			if firstRejected == nil {
				firstRejected = err
			}
		}
	}
	if firstRejected != nil {
		return dnsobservation.ResolverEndpoint{}, fmt.Errorf(
			"inventory has no usable port 53 resolver: %w",
			firstRejected,
		)
	}
	return dnsobservation.ResolverEndpoint{}, fmt.Errorf(
		"inventory has no resolver on supported port 53",
	)
}

func currentResolverServerEndpoint(
	group resolverinventory.Group,
	server resolverinventory.Server,
) (dnsobservation.ResolverEndpoint, error) {
	address, err := netip.ParseAddr(server.Address)
	if err != nil {
		return dnsobservation.ResolverEndpoint{}, fmt.Errorf("parse resolver address %q: %w", server.Address, err)
	}
	address = address.WithZone("").Unmap()
	if address.IsUnspecified() ||
		address.IsMulticast() ||
		address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return dnsobservation.ResolverEndpoint{}, fmt.Errorf(
			"resolver address %q is not a unicast dial target",
			server.Address,
		)
	}
	if address.Is6() && address.IsLinkLocalUnicast() {
		zone := server.Zone
		if zone == "" {
			zone = group.Interface
		}
		if zone == "" && group.InterfaceIndex != 0 {
			zone = strconv.FormatUint(uint64(group.InterfaceIndex), 10)
		}
		if zone == "" {
			return dnsobservation.ResolverEndpoint{}, fmt.Errorf(
				"link-local resolver %q has no interface zone",
				server.Address,
			)
		}
		address = address.WithZone(zone)
	}

	return dnsobservation.ResolverEndpoint{ID: resolverCurrent, WireIP: address}, nil
}

func emitResult(
	stdout io.Writer,
	stderr io.Writer,
	result any,
	outcome probe.Outcome,
) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(stderr, "reachrun: encode result: %v\n", err)
		return 1
	}

	switch outcome {
	case probe.OutcomeSucceeded:
		return 0
	case probe.OutcomeCancelled:
		return 130
	default:
		return 1
	}
}

func printUsage(output io.Writer) {
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  reachrun family-conditions")
	fmt.Fprintln(output, "  reachrun resolve <hostname>")
	fmt.Fprintln(output, "  reachrun resolver-inventory")
	fmt.Fprintln(output, "  reachrun dns-observe <udp|tcp|doh> <current|cloudflare|google> <A|AAAA|CNAME|SVCB|HTTPS> <hostname>")
	fmt.Fprintln(output, "  reachrun dns-https-path <udp|tcp|doh> <current|cloudflare|google> <hostname>")
	fmt.Fprintln(output, "  reachrun web-path <hostname>")
	fmt.Fprintln(output, "  reachrun web-recheck <hostname> <local-ip[,local-ip]> <reference-ip[,reference-ip]>")
	fmt.Fprintln(output, "  reachrun web-observe <http|https> <hostname> <public-ip>")
	fmt.Fprintln(output, "  reachrun ssh-observe <public-ip> [port]")
	fmt.Fprintln(output, "  reachrun tls-observe <public-ip>")
	fmt.Fprintln(output, "Phase 0 diagnostic only: each valid command prints one terminal JSON evidence document.")
}
