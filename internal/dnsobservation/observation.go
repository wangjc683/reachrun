// Package dnsobservation records one controlled DNS exchange against an
// explicitly configured resolver. It is deliberately separate from system
// hostname resolution and resolver configuration inventory.
package dnsobservation

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"runtime"
	"strings"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// ProbeKind identifies a controlled DNS observation in the shared Phase 0
	// evidence envelope.
	ProbeKind = probe.KindDNSObservation

	// FailureDNSTransport means no valid DNS response was obtained because the
	// selected network transport failed.
	FailureDNSTransport probe.FailureCode = "dns_transport_failure"
	// FailureDNSProtocol means bytes arrived but did not form the requested DNS
	// response.
	FailureDNSProtocol probe.FailureCode = "dns_protocol_failure"
	// FailureDoHRule means a DoH HTTP response violated the configured RFC 8484
	// exchange contract before a DNS response could be accepted.
	FailureDoHRule probe.FailureCode = "doh_rule_failure"
)

const (
	defaultTimeout     = 3 * time.Second
	maximumTimeout     = 30 * time.Second
	maxDNSMessageBytes = 65535
	maxResponseRecords = 128
	dnsPort            = 53
)

var ipv4LimitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// ResolverID selects one immutable endpoint from Config. A Request never
// carries an arbitrary network address or URL.
type ResolverID string

// Transport identifies the explicitly requested DNS transport. UDP
// truncation is returned as evidence; Observe never silently changes it to
// TCP.
type Transport string

const (
	TransportUDP Transport = "udp"
	TransportTCP Transport = "tcp"
	TransportDoH Transport = "doh"
)

// QueryType is the bounded record-type set supported by this Phase 0 slice.
type QueryType string

const (
	QueryTypeA     QueryType = "A"
	QueryTypeAAAA  QueryType = "AAAA"
	QueryTypeCNAME QueryType = "CNAME"
	QueryTypeSVCB  QueryType = "SVCB"
	QueryTypeHTTPS QueryType = "HTTPS"
)

// ResolverEndpoint defines exactly one named wire-DNS or DoH resolver. For a
// wire resolver, WireIP is set. For DoH, DoHURL and DoHBootstrap are set.
// Wire DNS always uses port 53 in production.
type ResolverEndpoint struct {
	ID           ResolverID
	WireIP       netip.Addr
	DoHURL       string
	DoHBootstrap netip.Addr
}

// Config is copied by New and remains immutable for the Observer lifetime.
type Config struct {
	Resolvers []ResolverEndpoint
	Timeout   time.Duration
}

// Request asks for one question over one explicit transport.
type Request struct {
	Hostname  string
	QueryType QueryType
	Resolver  ResolverID
	Transport Transport
}

// ResolverInput records which configured resolver and concrete endpoint were
// used for this observation.
type ResolverInput struct {
	ID       ResolverID `json:"id"`
	Endpoint string     `json:"endpoint"`
}

// Input is the normalized request captured in the evidence envelope.
type Input struct {
	Hostname  string        `json:"hostname"`
	QueryType QueryType     `json:"query_type"`
	Class     string        `json:"class"`
	Resolver  ResolverInput `json:"resolver"`
	Transport Transport     `json:"transport"`
}

// AnswerKind classifies the DNS response without turning DNS-negative or
// server RCODE responses into transport failures.
type AnswerKind string

const (
	AnswerKindAnswer     AnswerKind = "answer"
	AnswerKindNoData     AnswerKind = "no_data"
	AnswerKindNameError  AnswerKind = "name_error"
	AnswerKindReferral   AnswerKind = "referral"
	AnswerKindRCodeError AnswerKind = "rcode_error"
	AnswerKindIncomplete AnswerKind = "incomplete"
)

// ResponseCode preserves both the numeric DNS RCODE and a stable display
// name. Unknown codes remain representable.
type ResponseCode struct {
	Code uint16 `json:"code"`
	Name string `json:"name"`
}

// ResponseFlags records protocol facts exposed by the DNS header.
type ResponseFlags struct {
	Authoritative      bool `json:"authoritative"`
	Truncated          bool `json:"truncated"`
	RecursionDesired   bool `json:"recursion_desired"`
	RecursionAvailable bool `json:"recursion_available"`
	AuthenticatedData  bool `json:"authenticated_data"`
	CheckingDisabled   bool `json:"checking_disabled"`
}

// IPFamily identifies a canonical A or AAAA address.
type IPFamily string

const (
	IPFamilyIPv4 IPFamily = "ipv4"
	IPFamilyIPv6 IPFamily = "ipv6"
)

// ServiceBindingMode distinguishes AliasMode from ServiceMode without asking
// consumers to repeat the SvcPriority zero check.
type ServiceBindingMode string

const (
	ServiceBindingAlias   ServiceBindingMode = "alias"
	ServiceBindingService ServiceBindingMode = "service"
)

// ServiceParameter preserves one ordered SvcParam as a stable numeric key,
// registry name, and lowercase hexadecimal wire value. The wire value remains
// available even when the current version does not understand the parameter.
type ServiceParameter struct {
	Key      uint16 `json:"key"`
	Name     string `json:"name"`
	ValueHex string `json:"value_hex"`
}

// ServiceBinding is the typed RDATA shared by HTTPS and SVCB records.
// AliasMode parameters are retained as evidence even though RFC 9460 requires
// clients to ignore them while following the alias.
type ServiceBinding struct {
	Priority uint16             `json:"priority"`
	Target   string             `json:"target"`
	Mode     ServiceBindingMode `json:"mode"`
	Params   []ServiceParameter `json:"params"`
}

// Record is a tagged A, AAAA, CNAME, SVCB, or HTTPS answer. Records remain in
// DNS wire order. Address is populated only for A/AAAA, Target only for CNAME,
// and Service only for SVCB/HTTPS.
type Record struct {
	Name    string          `json:"name"`
	Type    QueryType       `json:"type"`
	TTL     uint32          `json:"ttl"`
	Address string          `json:"address,omitempty"`
	Family  IPFamily        `json:"family,omitempty"`
	Target  string          `json:"target,omitempty"`
	Service *ServiceBinding `json:"service,omitempty"`
}

// SOARecord captures the first authority SOA used to support a negative
// response. It is not treated as proof that the response was authoritative.
type SOARecord struct {
	Name    string `json:"name"`
	TTL     uint32 `json:"ttl"`
	NS      string `json:"ns"`
	Mailbox string `json:"mailbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
	MinTTL  uint32 `json:"min_ttl"`
}

// NSRecord captures an IN-class authority NS record. Keeping this evidence in
// wire order makes a referral distinguishable from an empty NOERROR response
// after serialization.
type NSRecord struct {
	Name   string `json:"name"`
	TTL    uint32 `json:"ttl"`
	Target string `json:"target"`
}

// Evidence is a valid DNS response. A truncated response is still valid
// evidence but is explicitly incomplete and never triggers hidden TCP work.
type Evidence struct {
	RCode          ResponseCode  `json:"rcode"`
	Flags          ResponseFlags `json:"flags"`
	AnswerKind     AnswerKind    `json:"answer_kind"`
	EffectiveName  string        `json:"effective_name"`
	Records        []Record      `json:"records"`
	NegativeSOA    *SOARecord    `json:"negative_soa,omitempty"`
	AuthorityNS    []NSRecord    `json:"authority_ns,omitempty"`
	ResponseBytes  int           `json:"response_bytes"`
	RemoteEndpoint string        `json:"remote_endpoint"`
	DoHStatus      int           `json:"doh_status,omitempty"`
}

// Result is the DNS-observation specialization of the Phase 0 envelope.
type Result = probe.Envelope[Input, Evidence]

// Observer returns one terminal evidence envelope for each explicit DNS
// exchange. Expected network and protocol failures live inside Result.
type Observer interface {
	Observe(ctx context.Context, request Request) Result
}

type endpointKind uint8

const (
	endpointWire endpointKind = iota + 1
	endpointDoH
)

type configuredEndpoint struct {
	id        ResolverID
	kind      endpointKind
	wireIP    netip.Addr
	dohURL    *url.URL
	bootstrap netip.Addr
}

type dependencies struct {
	now                 func() time.Time
	random              io.Reader
	wirePort            uint16
	rootCAs             *x509.CertPool
	beforeSuccessCommit func()
}

type observer struct {
	endpoints           map[ResolverID]configuredEndpoint
	timeout             time.Duration
	now                 func() time.Time
	random              io.Reader
	wirePort            uint16
	rootCAs             *x509.CertPool
	beforeSuccessCommit func()
	source              probe.Source
}

// New validates and copies config, then returns the production Observer.
func New(config Config) (Observer, error) {
	return newObserver(config, dependencies{
		now:      time.Now,
		random:   rand.Reader,
		wirePort: dnsPort,
	})
}

func newObserver(config Config, deps dependencies) (*observer, error) {
	timeout := config.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	if timeout < 0 || timeout > maximumTimeout {
		return nil, fmt.Errorf("timeout must be between zero and %s", maximumTimeout)
	}
	if len(config.Resolvers) == 0 {
		return nil, fmt.Errorf("at least one resolver endpoint is required")
	}
	if deps.now == nil {
		deps.now = time.Now
	}
	if deps.random == nil {
		deps.random = rand.Reader
	}
	if deps.wirePort == 0 {
		deps.wirePort = dnsPort
	}

	endpoints := make(map[ResolverID]configuredEndpoint, len(config.Resolvers))
	for index, candidate := range config.Resolvers {
		endpoint, err := normalizeEndpoint(candidate)
		if err != nil {
			return nil, fmt.Errorf("resolver %d: %w", index, err)
		}
		if _, exists := endpoints[endpoint.id]; exists {
			return nil, fmt.Errorf("resolver id %q is duplicated", endpoint.id)
		}
		endpoints[endpoint.id] = endpoint
	}

	return &observer{
		endpoints:           endpoints,
		timeout:             timeout,
		now:                 deps.now,
		random:              deps.random,
		wirePort:            deps.wirePort,
		rootCAs:             deps.rootCAs,
		beforeSuccessCommit: deps.beforeSuccessCommit,
		source: probe.Source{
			Backend:    "golang.org/x/net/dns/dnsmessage",
			Capability: probe.CapabilityNative,
		},
	}, nil
}

func normalizeEndpoint(candidate ResolverEndpoint) (configuredEndpoint, error) {
	id := ResolverID(strings.TrimSpace(string(candidate.ID)))
	if id == "" {
		return configuredEndpoint{}, fmt.Errorf("resolver id must not be empty")
	}

	hasWire := candidate.WireIP.IsValid()
	hasDoH := strings.TrimSpace(candidate.DoHURL) != "" || candidate.DoHBootstrap.IsValid()
	if hasWire == hasDoH {
		return configuredEndpoint{}, fmt.Errorf("resolver %q must define exactly one wire or DoH endpoint", id)
	}

	if hasWire {
		ip := candidate.WireIP.Unmap()
		if isUnsupportedResolverAddress(ip) {
			return configuredEndpoint{}, fmt.Errorf("wire resolver %q has unsupported IP %q", id, ip)
		}
		return configuredEndpoint{id: id, kind: endpointWire, wireIP: ip}, nil
	}

	if !candidate.DoHBootstrap.IsValid() {
		return configuredEndpoint{}, fmt.Errorf("DoH resolver %q requires a bootstrap IP", id)
	}
	bootstrap := candidate.DoHBootstrap.Unmap()
	if isUnsupportedResolverAddress(bootstrap) {
		return configuredEndpoint{}, fmt.Errorf("DoH resolver %q has unsupported bootstrap IP %q", id, bootstrap)
	}
	u, err := parseDoHEndpointURL(candidate.DoHURL)
	if err != nil {
		return configuredEndpoint{}, fmt.Errorf("DoH resolver %q: %w", id, err)
	}

	copyURL := *u
	return configuredEndpoint{
		id:        id,
		kind:      endpointDoH,
		dohURL:    &copyURL,
		bootstrap: bootstrap,
	}, nil
}

func isUnsupportedResolverAddress(address netip.Addr) bool {
	address = address.Unmap()
	return address.IsUnspecified() ||
		address.IsMulticast() ||
		address == ipv4LimitedBroadcast
}

func parseDoHEndpointURL(value string) (*url.URL, error) {
	u, err := url.Parse(value)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || u.Hostname() == "" {
		return nil, fmt.Errorf("requires an absolute HTTPS URL")
	}
	if u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return nil, fmt.Errorf("URL must not contain credentials, query, or fragment")
	}
	if _, err := dohPort(u); err != nil {
		return nil, err
	}
	return u, nil
}

func (e configuredEndpoint) input(transport Transport, wirePort uint16) ResolverInput {
	endpoint := ""
	if e.kind == endpointWire {
		endpoint = netip.AddrPortFrom(e.wireIP, wirePort).String()
	} else {
		endpoint = e.dohURL.String()
	}
	return ResolverInput{ID: e.id, Endpoint: endpoint}
}

func (o *observer) baseResult(startedAt time.Time, input Input) Result {
	finishedAt := o.now()
	duration := finishedAt.Sub(startedAt).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    finishedAt.UTC(),
		DurationMS:    duration,
		Platform: probe.Platform{
			OS:   runtime.GOOS,
			Arch: runtime.GOARCH,
		},
		Source: o.source,
		Input:  input,
	}
}
