package dnsobservation

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/wangjc683/reachrun/internal/probe"
	"golang.org/x/net/dns/dnsmessage"
)

// Validate checks both the shared envelope rules and the DNS-observation
// evidence contract.
func Validate(result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe envelope: %w", err)
	}
	if result.Probe != ProbeKind {
		return fmt.Errorf("probe must be %q", ProbeKind)
	}
	if result.Failure != nil && !validFailureCode(result.Failure.Code) {
		return fmt.Errorf("unsupported DNS observation failure code %q", result.Failure.Code)
	}
	if err := validateInputContract(result.Input, result.Outcome, result.Failure); err != nil {
		return fmt.Errorf("invalid DNS observation input: %w", err)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		return nil
	}

	evidence := result.Evidence
	if !evidence.AnswerKind.valid() {
		return fmt.Errorf("unsupported answer kind %q", evidence.AnswerKind)
	}
	if evidence.RCode.Name != responseCodeName(dnsmessage.RCode(evidence.RCode.Code)) {
		return fmt.Errorf("rcode name %q does not match code %d", evidence.RCode.Name, evidence.RCode.Code)
	}
	if evidence.ResponseBytes <= 0 || evidence.ResponseBytes > maxDNSMessageBytes {
		return fmt.Errorf("response_bytes must be between 1 and %d", maxDNSMessageBytes)
	}
	if evidence.RemoteEndpoint == "" {
		return fmt.Errorf("remote_endpoint must not be empty")
	}
	if err := validateRemoteEndpoint(result.Input, evidence.RemoteEndpoint); err != nil {
		return err
	}
	if result.Input.Transport == TransportDoH {
		if evidence.DoHStatus < 200 || evidence.DoHStatus >= 300 {
			return fmt.Errorf("successful DoH evidence must include a 2xx status")
		}
	} else if evidence.DoHStatus != 0 {
		return fmt.Errorf("wire DNS evidence must not include a DoH status")
	}
	if evidence.Flags.Truncated && evidence.AnswerKind != AnswerKindIncomplete {
		return fmt.Errorf("truncated response must be incomplete")
	}
	if len(evidence.Records) > maxResponseRecords {
		return fmt.Errorf("records exceed limit %d", maxResponseRecords)
	}
	for index, record := range evidence.Records {
		if err := validateRecord(record); err != nil {
			return fmt.Errorf("record %d: %w", index, err)
		}
	}
	if len(evidence.Records)+len(evidence.AuthorityNS) > maxResponseRecords {
		return fmt.Errorf("typed records exceed limit %d", maxResponseRecords)
	}
	for index, record := range evidence.AuthorityNS {
		if err := validateNSRecord(record); err != nil {
			return fmt.Errorf("authority NS %d: %w", index, err)
		}
	}
	if evidence.NegativeSOA != nil {
		if evidence.AnswerKind != AnswerKindNoData && evidence.AnswerKind != AnswerKindNameError {
			return fmt.Errorf("negative SOA requires no_data or name_error")
		}
		if err := validateSOA(*evidence.NegativeSOA); err != nil {
			return fmt.Errorf("negative SOA: %w", err)
		}
	}
	if err := validateEvidenceClassification(result.Input, *evidence); err != nil {
		return err
	}
	return nil
}

func validateInputContract(input Input, outcome probe.Outcome, failure *probe.Failure) error {
	normalized, _, hostnameErr := normalizeHostname(input.Hostname)
	if normalized != input.Hostname {
		return fmt.Errorf("hostname must use its normalized representation")
	}
	if input.Class != dnsClassIN {
		return fmt.Errorf("class must be %q", dnsClassIN)
	}
	resolverID := string(input.Resolver.ID)
	if strings.TrimSpace(resolverID) != resolverID {
		return fmt.Errorf("resolver id must be trimmed")
	}

	failureCode := probe.FailureCode("")
	if failure != nil {
		failureCode = failure.Code
	}
	strictRequest := outcome == probe.OutcomeSucceeded || failureCode != probe.FailureInvalidInput
	if strictRequest {
		if hostnameErr != nil {
			return fmt.Errorf("hostname is invalid: %w", hostnameErr)
		}
		if !input.QueryType.valid() {
			return fmt.Errorf("unsupported query type %q", input.QueryType)
		}
		if !input.Transport.valid() {
			return fmt.Errorf("unsupported transport %q", input.Transport)
		}
		if input.Resolver.ID == "" {
			return fmt.Errorf("resolver id must not be empty")
		}
	}

	if failureCode == probe.FailureInvalidInput {
		// Invalid input may be rejected before a resolver is selected, or because
		// an otherwise valid endpoint does not support the requested transport.
		return nil
	}

	requiresEndpoint := outcome == probe.OutcomeSucceeded ||
		failureCode == FailureDNSTransport ||
		failureCode == FailureDNSProtocol ||
		failureCode == FailureDoHRule
	if input.Resolver.Endpoint == "" {
		if requiresEndpoint {
			return fmt.Errorf("resolver endpoint must not be empty")
		}
		// Timeout or cancellation can win before endpoint lookup.
		return nil
	}
	_, _, err := validateResolverEndpoint(input)
	return err
}

func validateResolverEndpoint(input Input) (netip.AddrPort, uint16, error) {
	switch input.Transport {
	case TransportUDP, TransportTCP:
		endpoint, err := parseCanonicalAddrPort(input.Resolver.Endpoint)
		if err != nil {
			return netip.AddrPort{}, 0, fmt.Errorf("wire resolver endpoint: %w", err)
		}
		return endpoint, endpoint.Port(), nil
	case TransportDoH:
		u, err := parseDoHEndpointURL(input.Resolver.Endpoint)
		if err != nil {
			return netip.AddrPort{}, 0, fmt.Errorf("DoH resolver endpoint: %w", err)
		}
		if u.String() != input.Resolver.Endpoint {
			return netip.AddrPort{}, 0, fmt.Errorf("DoH resolver endpoint must be canonical")
		}
		port, err := dohPort(u)
		if err != nil {
			return netip.AddrPort{}, 0, err
		}
		parsedPort, err := strconv.ParseUint(port, 10, 16)
		if err != nil || parsedPort == 0 {
			return netip.AddrPort{}, 0, fmt.Errorf("DoH resolver endpoint has invalid port %q", port)
		}
		return netip.AddrPort{}, uint16(parsedPort), nil
	default:
		return netip.AddrPort{}, 0, fmt.Errorf("unsupported transport %q", input.Transport)
	}
}

func validateRemoteEndpoint(input Input, value string) error {
	remote, err := parseCanonicalAddrPort(value)
	if err != nil {
		return fmt.Errorf("remote_endpoint: %w", err)
	}
	configuredWire, expectedPort, err := validateResolverEndpoint(input)
	if err != nil {
		return err
	}
	if remote.Port() != expectedPort {
		return fmt.Errorf(
			"remote_endpoint port %d does not match resolver port %d",
			remote.Port(),
			expectedPort,
		)
	}
	if input.Transport != TransportDoH && remote != configuredWire {
		return fmt.Errorf(
			"remote_endpoint %q does not match wire resolver endpoint %q",
			value,
			input.Resolver.Endpoint,
		)
	}
	return nil
}

func parseCanonicalAddrPort(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not an address and port: %w", value, err)
	}
	if endpoint.String() != value {
		return netip.AddrPort{}, fmt.Errorf("%q is not canonical", value)
	}
	if isUnsupportedResolverAddress(endpoint.Addr()) {
		return netip.AddrPort{}, fmt.Errorf("%q uses an unsupported address", value)
	}
	return endpoint, nil
}

func validFailureCode(code probe.FailureCode) bool {
	switch code {
	case probe.FailureInvalidInput,
		probe.FailureTimeout,
		probe.FailureCancelled,
		FailureDNSTransport,
		FailureDNSProtocol,
		FailureDoHRule:
		return true
	default:
		return false
	}
}

func validateAnswerKind(kind AnswerKind, code uint16) error {
	switch kind {
	case AnswerKindAnswer, AnswerKindNoData, AnswerKindReferral:
		if code != uint16(dnsmessage.RCodeSuccess) {
			return fmt.Errorf("answer kind %q requires NOERROR", kind)
		}
	case AnswerKindNameError:
		if code != uint16(dnsmessage.RCodeNameError) {
			return fmt.Errorf("name_error requires NXDOMAIN")
		}
	case AnswerKindRCodeError:
		if code == uint16(dnsmessage.RCodeSuccess) || code == uint16(dnsmessage.RCodeNameError) {
			return fmt.Errorf("rcode_error requires a non-NOERROR, non-NXDOMAIN code")
		}
	case AnswerKindIncomplete:
		return nil
	}
	return nil
}

func validateEvidenceClassification(input Input, evidence Evidence) error {
	if evidence.EffectiveName == "" || !isCanonicalDNSName(evidence.EffectiveName) {
		return fmt.Errorf("effective_name %q is not canonical", evidence.EffectiveName)
	}
	effectiveName, chainComplete := followCNAMEs(input.Hostname, evidence.Records)
	if evidence.EffectiveName != effectiveName {
		return fmt.Errorf(
			"effective_name %q does not match the CNAME chain result %q",
			evidence.EffectiveName,
			effectiveName,
		)
	}

	if err := validateAnswerKind(evidence.AnswerKind, evidence.RCode.Code); err != nil {
		return err
	}
	if evidence.AnswerKind == AnswerKindIncomplete {
		if !evidence.Flags.Truncated && chainComplete {
			return fmt.Errorf("incomplete answer requires truncation or an incomplete CNAME chain")
		}
		if evidence.NegativeSOA != nil {
			return fmt.Errorf("incomplete answer must not include a negative SOA")
		}
		return nil
	}
	if evidence.Flags.Truncated || !chainComplete {
		return fmt.Errorf("complete answer kind %q has incomplete response evidence", evidence.AnswerKind)
	}

	hasRequestedAnswer := false
	wantedName := effectiveName
	if input.QueryType == QueryTypeCNAME {
		wantedName = input.Hostname
	}
	for _, record := range evidence.Records {
		if record.Type == input.QueryType && record.Name == wantedName {
			hasRequestedAnswer = true
			break
		}
	}

	switch evidence.AnswerKind {
	case AnswerKindAnswer:
		if !hasRequestedAnswer {
			return fmt.Errorf("answer evidence has no %s record for %q", input.QueryType, wantedName)
		}
	case AnswerKindNoData:
		if hasRequestedAnswer {
			return fmt.Errorf("no_data evidence includes a requested answer")
		}
		if len(evidence.AuthorityNS) > 0 && evidence.NegativeSOA == nil {
			return fmt.Errorf("no_data authority NS evidence without a negative SOA is a referral")
		}
	case AnswerKindReferral:
		if hasRequestedAnswer {
			return fmt.Errorf("referral evidence includes a requested answer")
		}
		if len(evidence.AuthorityNS) == 0 {
			return fmt.Errorf("referral evidence requires an authority NS record")
		}
		if evidence.NegativeSOA != nil {
			return fmt.Errorf("referral evidence must not include a negative SOA")
		}
	case AnswerKindRCodeError:
		if evidence.NegativeSOA != nil {
			return fmt.Errorf("rcode_error evidence must not include a negative SOA")
		}
	}
	return nil
}

func validateRecord(record Record) error {
	if !isCanonicalDNSName(record.Name) {
		return fmt.Errorf("name %q is not canonical", record.Name)
	}
	switch record.Type {
	case QueryTypeA:
		address, err := netip.ParseAddr(record.Address)
		if err != nil || !address.Is4() || address.String() != record.Address {
			return fmt.Errorf("A address %q is not canonical IPv4", record.Address)
		}
		if record.Family != IPFamilyIPv4 || record.Target != "" || record.Service != nil {
			return fmt.Errorf("A record has inconsistent family, target, or service binding")
		}
	case QueryTypeAAAA:
		address, err := netip.ParseAddr(record.Address)
		if err != nil || !address.Is6() || address.Is4() || address.String() != record.Address {
			return fmt.Errorf("AAAA address %q is not canonical IPv6", record.Address)
		}
		if record.Family != IPFamilyIPv6 || record.Target != "" || record.Service != nil {
			return fmt.Errorf("AAAA record has inconsistent family, target, or service binding")
		}
	case QueryTypeCNAME:
		if record.Address != "" || record.Family != "" || record.Service != nil ||
			!isCanonicalDNSName(record.Target) {
			return fmt.Errorf("CNAME record has inconsistent address, family, target, or service binding")
		}
	case QueryTypeSVCB, QueryTypeHTTPS:
		if record.Address != "" || record.Family != "" || record.Target != "" || record.Service == nil {
			return fmt.Errorf("%s record has inconsistent address, family, target, or service binding", record.Type)
		}
		if err := validateServiceBinding(*record.Service); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported record type %q", record.Type)
	}
	return nil
}

func validateServiceBinding(binding ServiceBinding) error {
	if !isCanonicalDNSName(binding.Target) {
		return fmt.Errorf("service target %q is not canonical", binding.Target)
	}
	if binding.Params == nil {
		return fmt.Errorf("service parameters must encode as an array")
	}
	wantMode := ServiceBindingService
	if binding.Priority == 0 {
		wantMode = ServiceBindingAlias
	}
	if binding.Mode != wantMode {
		return fmt.Errorf("service binding priority %d requires mode %q", binding.Priority, wantMode)
	}
	var previous uint16
	for index, param := range binding.Params {
		if index > 0 && param.Key <= previous {
			return fmt.Errorf("service parameters must use strictly increasing keys")
		}
		if param.Name != serviceParameterName(param.Key) {
			return fmt.Errorf("service parameter %d name %q does not match key", index, param.Name)
		}
		value, err := hex.DecodeString(param.ValueHex)
		if err != nil || hex.EncodeToString(value) != param.ValueHex {
			return fmt.Errorf("service parameter %d value_hex is not canonical lowercase hexadecimal", index)
		}
		previous = param.Key
	}
	return nil
}

func validateSOA(record SOARecord) error {
	if !isCanonicalDNSName(record.Name) ||
		!isCanonicalDNSName(record.NS) ||
		!isCanonicalDNSName(record.Mailbox) {
		return fmt.Errorf("name, ns, and mailbox must be canonical DNS names")
	}
	return nil
}

func validateNSRecord(record NSRecord) error {
	if !isCanonicalDNSName(record.Name) || !isCanonicalDNSName(record.Target) {
		return fmt.Errorf("name and target must be canonical DNS names")
	}
	return nil
}

func isCanonicalDNSName(value string) bool {
	if value == "." {
		return true
	}
	normalized, _, err := normalizeHostname(value)
	return err == nil && normalized == value
}

// NormalizeHostname exposes the DNS Observation hostname contract to bounded
// orchestration modules without exposing the dnsmessage codec type.
func NormalizeHostname(value string) (string, error) {
	normalized, _, err := normalizeHostname(value)
	return normalized, err
}
