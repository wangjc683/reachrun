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
	"time"

	"github.com/wangjc683/reachrun/internal/dnsobservation"
	"github.com/wangjc683/reachrun/internal/platform/resolverinventory"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/sshobservation"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

const phase0ProbeTimeout = 5 * time.Second

const (
	resolverCurrent        dnsobservation.ResolverID = "current"
	resolverCloudflareWire dnsobservation.ResolverID = "cloudflare-wire"
	resolverCloudflareDoH  dnsobservation.ResolverID = "cloudflare-doh"
	resolverGoogleWire     dnsobservation.ResolverID = "google-wire"
	resolverGoogleDoH      dnsobservation.ResolverID = "google-doh"
)

type dnsObserverFactory func(dnsobservation.Config) (dnsobservation.Observer, error)
type webObserverFactory func(webobservation.Config) (webobservation.Observer, error)
type sshObserverFactory func(sshobservation.Config) (sshobservation.Observer, error)

type dependencies struct {
	systemResolver    systemresolver.Resolver
	resolverInventory resolverinventory.Observer
	newDNSObserver    dnsObserverFactory
	newWebObserver    webObserverFactory
	newSSHObserver    sshObserverFactory
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
		systemResolver:    systemresolver.New(),
		resolverInventory: resolverinventory.New(),
		newDNSObserver:    dnsobservation.New,
		newWebObserver:    webobservation.New,
		newSSHObserver:    sshobservation.New,
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
	case "web-observe":
		request, ok := parseWebObservationArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runWebObservation(ctx, request, stdout, stderr, deps.newWebObserver)
	case "ssh-observe":
		request, ok := parseSSHObservationArgs(args)
		if !ok {
			printUsage(stderr)
			return 2
		}
		return runSSHObservation(ctx, request, stdout, stderr, deps.newSSHObserver)
	default:
		printUsage(stderr)
		return 2
	}
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

	config := referenceResolverConfig()
	if provider == "current" {
		inventory := deps.resolverInventory.Observe(probeContext)
		if resolverinventory.Validate(inventory) == nil && inventory.Outcome == probe.OutcomeCancelled {
			// Inventory is part of this one DNS command. Preserve explicit user
			// cancellation in the shared context so it dominates the otherwise
			// expected "current resolver is unavailable" setup failure.
			cancel()
		}
		endpoint, err := currentResolverEndpoint(inventory)
		if err != nil {
			// Keep "current" unconfigured. The DNS observer then returns this
			// command's one terminal DNS envelope; resolver inventory is diagnostic
			// input, not command output.
			if probeContext.Err() != context.Canceled {
				fmt.Fprintf(stderr, "reachrun: current resolver unavailable: %v\n", err)
			}
		} else {
			config.Resolvers = append(config.Resolvers, endpoint)
		}
	}

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

func parseDNSObservationArgs(args []string) (dnsobservation.Request, string, bool) {
	if len(args) != 5 || args[0] != "dns-observe" {
		return dnsobservation.Request{}, "", false
	}

	var transport dnsobservation.Transport
	switch args[1] {
	case string(dnsobservation.TransportUDP):
		transport = dnsobservation.TransportUDP
	case string(dnsobservation.TransportTCP):
		transport = dnsobservation.TransportTCP
	case string(dnsobservation.TransportDoH):
		transport = dnsobservation.TransportDoH
	default:
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
	fmt.Fprintln(output, "  reachrun resolve <hostname>")
	fmt.Fprintln(output, "  reachrun resolver-inventory")
	fmt.Fprintln(output, "  reachrun dns-observe <udp|tcp|doh> <current|cloudflare|google> <A|AAAA|CNAME> <hostname>")
	fmt.Fprintln(output, "  reachrun web-observe <http|https> <hostname> <public-ip>")
	fmt.Fprintln(output, "  reachrun ssh-observe <public-ip> [port]")
	fmt.Fprintln(output, "Phase 0 diagnostic only: each valid probe prints one terminal evidence envelope as JSON.")
}
