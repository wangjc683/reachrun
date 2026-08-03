package dnsobservation

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestResultJSONContract(t *testing.T) {
	t.Parallel()

	result := validResult()
	result.Evidence.AnswerKind = AnswerKindReferral
	result.Evidence.Records = []Record{}
	result.Evidence.AuthorityNS = []NSRecord{{
		Name:   "example.com",
		TTL:    300,
		Target: "ns1.example.net",
	}}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}

	want := `{"schema_version":1,"probe":"dns_observation","observed_at":"2026-08-01T00:00:00Z","duration_ms":12,"platform":{"os":"testos","arch":"testarch"},"source":{"backend":"golang.org/x/net/dns/dnsmessage","capability":"native"},"input":{"hostname":"www.example.com","query_type":"A","class":"IN","resolver":{"id":"wire-test","endpoint":"192.0.2.53:53"},"transport":"udp"},"outcome":"succeeded","evidence":{"rcode":{"code":0,"name":"NOERROR"},"flags":{"authoritative":false,"truncated":false,"recursion_desired":true,"recursion_available":true,"authenticated_data":false,"checking_disabled":false},"answer_kind":"referral","effective_name":"www.example.com","records":[],"authority_ns":[{"name":"example.com","ttl":300,"target":"ns1.example.net"}],"response_bytes":72,"remote_endpoint":"192.0.2.53:53"}}`
	if string(encoded) != want {
		t.Fatalf("unexpected JSON contract\n got: %s\nwant: %s", encoded, want)
	}
	if strings.Contains(string(encoded), `"failure"`) ||
		strings.Contains(string(encoded), `"negative_soa"`) ||
		strings.Contains(string(encoded), `"doh_status"`) {
		t.Fatalf("success JSON includes an inapplicable optional field: %s", encoded)
	}
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestNewValidatesAndCopiesConfig(t *testing.T) {
	t.Parallel()

	resolvers := []ResolverEndpoint{
		{ID: " wire ", WireIP: netip.MustParseAddr("::ffff:192.0.2.53")},
		{
			ID:           "doh",
			DoHURL:       "https://dns.example/dns-query",
			DoHBootstrap: netip.MustParseAddr("2001:db8::53"),
		},
	}
	created, err := New(Config{Resolvers: resolvers, Timeout: time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	got := created.(*observer)

	resolvers[0].ID = "changed"
	resolvers[0].WireIP = netip.MustParseAddr("203.0.113.53")
	resolvers[1].DoHURL = "https://changed.example/dns-query"

	wire := got.endpoints["wire"]
	if wire.wireIP.String() != "192.0.2.53" || got.wirePort != 53 {
		t.Fatalf("wire endpoint = %s:%d, want immutable 192.0.2.53:53", wire.wireIP, got.wirePort)
	}
	doh := got.endpoints["doh"]
	if doh.dohURL.String() != "https://dns.example/dns-query" || doh.bootstrap.String() != "2001:db8::53" {
		t.Fatalf("DoH endpoint changed with caller config: %#v", doh)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	validWire := ResolverEndpoint{ID: "wire", WireIP: netip.MustParseAddr("192.0.2.53")}
	tests := map[string]Config{
		"no resolvers": {},
		"negative timeout": {
			Resolvers: []ResolverEndpoint{validWire},
			Timeout:   -time.Millisecond,
		},
		"timeout above maximum": {
			Resolvers: []ResolverEndpoint{validWire},
			Timeout:   maximumTimeout + time.Millisecond,
		},
		"duplicate id": {
			Resolvers: []ResolverEndpoint{validWire, validWire},
		},
		"empty endpoint": {
			Resolvers: []ResolverEndpoint{{ID: "empty"}},
		},
		"wire and doh": {
			Resolvers: []ResolverEndpoint{{
				ID:           "both",
				WireIP:       netip.MustParseAddr("192.0.2.53"),
				DoHURL:       "https://dns.example/dns-query",
				DoHBootstrap: netip.MustParseAddr("192.0.2.54"),
			}},
		},
		"unspecified wire ip": {
			Resolvers: []ResolverEndpoint{{ID: "wire", WireIP: netip.IPv4Unspecified()}},
		},
		"multicast wire ip": {
			Resolvers: []ResolverEndpoint{{ID: "wire", WireIP: netip.MustParseAddr("224.0.0.251")}},
		},
		"limited broadcast wire ip": {
			Resolvers: []ResolverEndpoint{{ID: "wire", WireIP: netip.MustParseAddr("255.255.255.255")}},
		},
		"doh without bootstrap": {
			Resolvers: []ResolverEndpoint{{ID: "doh", DoHURL: "https://dns.example/dns-query"}},
		},
		"doh multicast bootstrap": {
			Resolvers: []ResolverEndpoint{{
				ID:           "doh",
				DoHURL:       "https://dns.example/dns-query",
				DoHBootstrap: netip.MustParseAddr("ff02::fb"),
			}},
		},
		"doh limited broadcast bootstrap": {
			Resolvers: []ResolverEndpoint{{
				ID:           "doh",
				DoHURL:       "https://dns.example/dns-query",
				DoHBootstrap: netip.MustParseAddr("255.255.255.255"),
			}},
		},
		"doh not https": {
			Resolvers: []ResolverEndpoint{{
				ID:           "doh",
				DoHURL:       "http://dns.example/dns-query",
				DoHBootstrap: netip.MustParseAddr("192.0.2.53"),
			}},
		},
		"doh query parameters": {
			Resolvers: []ResolverEndpoint{{
				ID:           "doh",
				DoHURL:       "https://dns.example/dns-query?dns=value",
				DoHBootstrap: netip.MustParseAddr("192.0.2.53"),
			}},
		},
		"doh without hostname": {
			Resolvers: []ResolverEndpoint{{
				ID:           "doh",
				DoHURL:       "https://:443/dns-query",
				DoHBootstrap: netip.MustParseAddr("192.0.2.53"),
			}},
		},
		"doh non-canonical port": {
			Resolvers: []ResolverEndpoint{{
				ID:           "doh",
				DoHURL:       "https://dns.example:0443/dns-query",
				DoHBootstrap: netip.MustParseAddr("192.0.2.53"),
			}},
		},
	}

	for name, config := range tests {
		name, config := name, config
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := New(config); err == nil {
				t.Fatal("New() error = nil, want config rejection")
			}
		})
	}
}

func TestValidateRejectsInconsistentEvidence(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"wrong probe": func(result *Result) {
			result.Probe = "other"
		},
		"rcode name mismatch": func(result *Result) {
			result.Evidence.RCode.Name = "SERVFAIL"
		},
		"effective name ignores cname": func(result *Result) {
			result.Evidence.Records = []Record{
				{Name: "www.example.com", Type: QueryTypeCNAME, TTL: 60, Target: "edge.example.net"},
				{Name: "edge.example.net", Type: QueryTypeA, TTL: 60, Address: "192.0.2.10", Family: IPFamilyIPv4},
			}
			result.Evidence.EffectiveName = "www.example.com"
		},
		"answer lacks requested record": func(result *Result) {
			result.Evidence.Records = []Record{{
				Name: "www.example.com", Type: QueryTypeAAAA, TTL: 60,
				Address: "2001:db8::10", Family: IPFamilyIPv6,
			}}
		},
		"no data includes requested record": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindNoData
		},
		"referral lacks authority ns": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindReferral
			result.Evidence.Records = []Record{}
		},
		"referral includes negative soa": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindReferral
			result.Evidence.Records = []Record{}
			result.Evidence.AuthorityNS = []NSRecord{{Name: "example.com", Target: "ns.example.com"}}
			result.Evidence.NegativeSOA = testSOA()
		},
		"no data ns without soa is referral": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindNoData
			result.Evidence.Records = []Record{}
			result.Evidence.AuthorityNS = []NSRecord{{Name: "example.com", Target: "ns.example.com"}}
		},
		"incomplete without cause": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindIncomplete
		},
		"complete kind with cname cycle": func(result *Result) {
			result.Evidence.Records = []Record{
				{Name: "www.example.com", Type: QueryTypeCNAME, Target: "edge.example.net"},
				{Name: "edge.example.net", Type: QueryTypeCNAME, Target: "www.example.com"},
			}
		},
		"invalid authority ns": func(result *Result) {
			result.Evidence.AuthorityNS = []NSRecord{{Name: "example.com", Target: "NOT A NAME"}}
		},
		"wire evidence with doh status": func(result *Result) {
			result.Evidence.DoHStatus = 200
		},
		"wire endpoint is not an address and port": func(result *Result) {
			result.Input.Resolver.Endpoint = "https://dns.example/dns-query"
		},
		"wire remote differs from configured resolver": func(result *Result) {
			result.Evidence.RemoteEndpoint = "192.0.2.54:53"
		},
		"remote endpoint is not canonical": func(result *Result) {
			result.Evidence.RemoteEndpoint = "192.0.2.53:0053"
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validResult()
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatal("Validate() error = nil, want inconsistent evidence rejection")
			}
		})
	}
}

func TestValidateAcceptsDoHEndpointIdentity(t *testing.T) {
	t.Parallel()

	result := validResult()
	result.Input.Transport = TransportDoH
	result.Input.Resolver = ResolverInput{
		ID:       "doh-test",
		Endpoint: "https://dns.example:8443/dns-query",
	}
	result.Evidence.RemoteEndpoint = "192.0.2.53:8443"
	result.Evidence.DoHStatus = 200
	if err := Validate(result); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	result.Evidence.RemoteEndpoint = "192.0.2.53:443"
	if err := Validate(result); err == nil {
		t.Fatal("Validate() error = nil, want DoH remote-port mismatch rejection")
	}
}

func TestValidateChecksServiceBindingContract(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"missing service binding": func(result *Result) {
			result.Evidence.Records[0].Service = nil
		},
		"alias priority marked service": func(result *Result) {
			result.Evidence.Records[0].Service.Mode = ServiceBindingService
		},
		"noncanonical target": func(result *Result) {
			result.Evidence.Records[0].Service.Target = "Target.Example"
		},
		"parameter keys out of order": func(result *Result) {
			result.Evidence.Records[0].Service.Params = []ServiceParameter{
				{Key: 3, Name: "port", ValueHex: "01bb"},
				{Key: 1, Name: "alpn", ValueHex: "026832"},
			}
		},
		"nil parameter array": func(result *Result) {
			result.Evidence.Records[0].Service.Params = nil
		},
		"parameter name mismatch": func(result *Result) {
			result.Evidence.Records[0].Service.Params[0].Name = "key1"
		},
		"parameter value not canonical hex": func(result *Result) {
			result.Evidence.Records[0].Service.Params[0].ValueHex = "0A"
		},
		"service mixed with cname target": func(result *Result) {
			result.Evidence.Records[0].Target = "other.example"
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validHTTPSResult()
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatal("Validate() error = nil, want service binding rejection")
			}
		})
	}

	result := validHTTPSResult()
	if err := Validate(result); err != nil {
		t.Fatalf("valid HTTPS result rejected: %v", err)
	}
}

func TestValidateChecksFailureInputContract(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"transport failure requires endpoint": func(result *Result) {
			result.Failure.Code = FailureDNSTransport
			result.Input.Resolver.Endpoint = ""
		},
		"timeout requires supported query": func(result *Result) {
			result.Failure.Code = probe.FailureTimeout
			result.Input.QueryType = "TXT"
		},
		"cancellation requires normalized resolver id": func(result *Result) {
			result.Outcome = probe.OutcomeCancelled
			result.Failure.Code = probe.FailureCancelled
			result.Input.Resolver.ID = " resolver-with-spaces "
		},
		"protocol failure validates endpoint shape": func(result *Result) {
			result.Failure.Code = FailureDNSProtocol
			result.Input.Resolver.Endpoint = "not-an-address"
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validResult()
			result.Outcome = probe.OutcomeFailed
			result.Evidence = nil
			result.Failure = &probe.Failure{Code: FailureDNSTransport}
			mutate(&result)
			if err := Validate(result); err == nil {
				t.Fatal("Validate() error = nil, want failure-input contract rejection")
			}
		})
	}
}

func TestValidateAllowsPreLookupTerminalInputs(t *testing.T) {
	t.Parallel()

	tests := map[string]Result{
		"invalid input": func() Result {
			result := validResult()
			result.Outcome = probe.OutcomeFailed
			result.Evidence = nil
			result.Failure = &probe.Failure{Code: probe.FailureInvalidInput}
			result.Input = Input{
				Hostname:  "bad/name",
				QueryType: "TXT",
				Class:     dnsClassIN,
				Transport: "invalid",
			}
			return result
		}(),
		"timeout before resolver lookup": func() Result {
			result := validResult()
			result.Outcome = probe.OutcomeFailed
			result.Evidence = nil
			result.Failure = &probe.Failure{Code: probe.FailureTimeout}
			result.Input.Resolver.Endpoint = ""
			return result
		}(),
		"cancellation before resolver lookup": func() Result {
			result := validResult()
			result.Outcome = probe.OutcomeCancelled
			result.Evidence = nil
			result.Failure = &probe.Failure{Code: probe.FailureCancelled}
			result.Input.Resolver.Endpoint = ""
			return result
		}(),
	}

	for name, result := range tests {
		name, result := name, result
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestValidateAcceptsDNSOutcomes(t *testing.T) {
	t.Parallel()

	tests := map[string]func(*Result){
		"answer through cname": func(result *Result) {
			result.Evidence.Records = []Record{
				{Name: "www.example.com", Type: QueryTypeCNAME, TTL: 60, Target: "edge.example.net"},
				{Name: "edge.example.net", Type: QueryTypeA, TTL: 60, Address: "192.0.2.10", Family: IPFamilyIPv4},
			}
			result.Evidence.EffectiveName = "edge.example.net"
		},
		"no data with soa and ns": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindNoData
			result.Evidence.Records = []Record{}
			result.Evidence.NegativeSOA = testSOA()
			result.Evidence.AuthorityNS = []NSRecord{{Name: "example.com", TTL: 300, Target: "ns.example.com"}}
		},
		"name error": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindNameError
			result.Evidence.RCode = ResponseCode{Code: 3, Name: "NXDOMAIN"}
			result.Evidence.Records = []Record{}
			result.Evidence.NegativeSOA = testSOA()
		},
		"rcode error": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindRCodeError
			result.Evidence.RCode = ResponseCode{Code: 2, Name: "SERVFAIL"}
			result.Evidence.Records = []Record{}
		},
		"truncated": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindIncomplete
			result.Evidence.Flags.Truncated = true
			result.Evidence.Records = []Record{}
		},
		"referral": func(result *Result) {
			result.Evidence.AnswerKind = AnswerKindReferral
			result.Evidence.Records = []Record{}
			result.Evidence.AuthorityNS = []NSRecord{{Name: "example.com", TTL: 300, Target: "ns.example.com"}}
		},
	}

	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			result := validResult()
			mutate(&result)
			if err := Validate(result); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestValidateRejectsFailureCodeOutsideContract(t *testing.T) {
	t.Parallel()

	result := validResult()
	result.Outcome = probe.OutcomeFailed
	result.Evidence = nil
	result.Failure = &probe.Failure{Code: "other_probe_failure"}
	if err := Validate(result); err == nil {
		t.Fatal("Validate() error = nil, want unsupported failure code")
	}
}

func validResult() Result {
	evidence := Evidence{
		RCode: ResponseCode{Code: 0, Name: "NOERROR"},
		Flags: ResponseFlags{
			RecursionDesired:   true,
			RecursionAvailable: true,
		},
		AnswerKind:    AnswerKindAnswer,
		EffectiveName: "www.example.com",
		Records: []Record{{
			Name:    "www.example.com",
			Type:    QueryTypeA,
			TTL:     60,
			Address: "192.0.2.10",
			Family:  IPFamilyIPv4,
		}},
		ResponseBytes:  72,
		RemoteEndpoint: "192.0.2.53:53",
	}
	return Result{
		SchemaVersion: probe.SchemaVersion,
		Probe:         ProbeKind,
		ObservedAt:    time.Date(2026, time.August, 1, 0, 0, 0, 0, time.UTC),
		DurationMS:    12,
		Platform:      probe.Platform{OS: "testos", Arch: "testarch"},
		Source: probe.Source{
			Backend:    "golang.org/x/net/dns/dnsmessage",
			Capability: probe.CapabilityNative,
		},
		Input: Input{
			Hostname:  "www.example.com",
			QueryType: QueryTypeA,
			Class:     dnsClassIN,
			Resolver:  ResolverInput{ID: "wire-test", Endpoint: "192.0.2.53:53"},
			Transport: TransportUDP,
		},
		Outcome:  probe.OutcomeSucceeded,
		Evidence: &evidence,
	}
}

func validHTTPSResult() Result {
	result := validResult()
	result.Input.QueryType = QueryTypeHTTPS
	result.Evidence.Records = []Record{{
		Name: "www.example.com",
		Type: QueryTypeHTTPS,
		TTL:  60,
		Service: &ServiceBinding{
			Priority: 0,
			Target:   "svc.example.net",
			Mode:     ServiceBindingAlias,
			Params: []ServiceParameter{{
				Key: 1, Name: "alpn", ValueHex: "026832",
			}},
		},
	}}
	return result
}

func testSOA() *SOARecord {
	return &SOARecord{
		Name:    "example.com",
		TTL:     300,
		NS:      "ns.example.com",
		Mailbox: "hostmaster.example.com",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		MinTTL:  300,
	}
}
