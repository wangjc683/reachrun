package dnsobservation

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode"

	"golang.org/x/net/dns/dnsmessage"
)

const dnsClassIN = "IN"

type expectedResponse struct {
	id       uint16
	name     dnsmessage.Name
	nameText string
	qtype    dnsmessage.Type
}

type parsedResponse struct {
	header       dnsmessage.Header
	answers      []dnsmessage.Resource
	authorities  []dnsmessage.Resource
	additionals  []dnsmessage.Resource
	bodyComplete bool
}

func normalizeRequest(request Request) (Input, dnsmessage.Name, dnsmessage.Type, error) {
	hostname, name, err := normalizeHostname(request.Hostname)
	input := Input{
		Hostname:  hostname,
		QueryType: request.QueryType,
		Class:     dnsClassIN,
		Resolver:  ResolverInput{ID: ResolverID(strings.TrimSpace(string(request.Resolver)))},
		Transport: request.Transport,
	}
	if err != nil {
		return input, dnsmessage.Name{}, 0, err
	}

	qtype, err := wireQueryType(request.QueryType)
	if err != nil {
		return input, dnsmessage.Name{}, 0, err
	}
	if !request.Transport.valid() {
		return input, dnsmessage.Name{}, 0, fmt.Errorf("unsupported DNS transport %q", request.Transport)
	}
	if input.Resolver.ID == "" {
		return input, dnsmessage.Name{}, 0, fmt.Errorf("resolver id must not be empty")
	}

	return input, name, qtype, nil
}

func normalizeHostname(value string) (string, dnsmessage.Name, error) {
	hostname := strings.ToLower(strings.TrimSpace(value))
	hostname = strings.TrimSuffix(hostname, ".")
	if hostname == "" {
		return hostname, dnsmessage.Name{}, errors.New("hostname must not be empty")
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return hostname, dnsmessage.Name{}, errors.New("IP literals are not DNS observation hostnames")
	}
	if strings.ContainsAny(hostname, "/\\:@?#[]*") ||
		strings.IndexFunc(hostname, unicode.IsSpace) >= 0 {
		return hostname, dnsmessage.Name{}, errors.New("hostname must not include a scheme, port, path, or whitespace")
	}
	for _, r := range hostname {
		if r > unicode.MaxASCII || r < 0x21 {
			return hostname, dnsmessage.Name{}, errors.New("hostname must be normalized ASCII")
		}
	}

	name, err := dnsmessage.NewName(hostname + ".")
	if err != nil {
		return hostname, dnsmessage.Name{}, fmt.Errorf("create DNS name: %w", err)
	}
	// NewName only copies bytes. Packing one minimal question applies the DNS
	// label-length and canonical-name validation used by the wire codec.
	probeMessage := dnsmessage.Message{
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	if _, err := probeMessage.Pack(); err != nil {
		return hostname, dnsmessage.Name{}, fmt.Errorf("invalid DNS hostname: %w", err)
	}
	return hostname, name, nil
}

func buildQuery(id uint16, name dnsmessage.Name, qtype dnsmessage.Type) ([]byte, error) {
	message := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               id,
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{{
			Name:  name,
			Type:  qtype,
			Class: dnsmessage.ClassINET,
		}},
	}
	return message.Pack()
}

func decodeResponse(raw []byte, expected expectedResponse) (parsedResponse, error) {
	if len(raw) == 0 || len(raw) > maxDNSMessageBytes {
		return parsedResponse{}, fmt.Errorf("DNS response size %d is outside the allowed range", len(raw))
	}

	var parser dnsmessage.Parser
	header, err := parser.Start(raw)
	if err != nil {
		return parsedResponse{}, fmt.Errorf("parse DNS header: %w", err)
	}
	parsed := parsedResponse{header: header, bodyComplete: true}

	questions := make([]dnsmessage.Question, 0, 1)
	for {
		question, questionErr := parser.Question()
		if errors.Is(questionErr, dnsmessage.ErrSectionDone) {
			break
		}
		if questionErr != nil {
			return parsedResponse{}, fmt.Errorf("parse DNS question: %w", questionErr)
		}
		questions = append(questions, question)
		if len(questions) > 1 {
			return parsedResponse{}, errors.New("DNS response must contain exactly one question")
		}
	}
	if err := validateResponseIdentity(header, questions, expected); err != nil {
		return parsedResponse{}, err
	}

	records := 0
	parsed.answers, parsed.bodyComplete, err = parseSection(
		parser.Answer,
		header.Truncated,
		&records,
	)
	if err != nil || !parsed.bodyComplete {
		return parsed, err
	}
	parsed.authorities, parsed.bodyComplete, err = parseSection(
		parser.Authority,
		header.Truncated,
		&records,
	)
	if err != nil || !parsed.bodyComplete {
		return parsed, err
	}
	parsed.additionals, parsed.bodyComplete, err = parseSection(
		parser.Additional,
		header.Truncated,
		&records,
	)
	if err != nil {
		return parsed, err
	}

	return parsed, nil
}

func parseSection(
	next func() (dnsmessage.Resource, error),
	allowTruncated bool,
	records *int,
) ([]dnsmessage.Resource, bool, error) {
	result := make([]dnsmessage.Resource, 0)
	for {
		record, err := next()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			return result, true, nil
		}
		if err != nil {
			if allowTruncated {
				return result, false, nil
			}
			return nil, false, fmt.Errorf("parse DNS resource: %w", err)
		}
		*records++
		if *records > maxResponseRecords {
			return nil, false, fmt.Errorf("DNS response exceeds %d records", maxResponseRecords)
		}
		result = append(result, record)
	}
}

func validateResponseIdentity(
	header dnsmessage.Header,
	questions []dnsmessage.Question,
	expected expectedResponse,
) error {
	if !header.Response {
		return errors.New("DNS message is not a response")
	}
	if header.OpCode != 0 {
		return fmt.Errorf("DNS response opcode is %d, want QUERY", header.OpCode)
	}
	if header.ID != expected.id {
		return fmt.Errorf("DNS response id is %d, want %d", header.ID, expected.id)
	}
	if len(questions) != 1 {
		return fmt.Errorf("DNS response has %d questions, want 1", len(questions))
	}
	question := questions[0]
	if !strings.EqualFold(question.Name.String(), expected.name.String()) ||
		question.Type != expected.qtype ||
		question.Class != dnsmessage.ClassINET {
		return errors.New("DNS response question does not match the request")
	}
	return nil
}

func evidenceFromResponse(
	parsed parsedResponse,
	input Input,
	responseBytes int,
	remoteEndpoint string,
	dohStatus int,
) (Evidence, error) {
	header := parsed.header
	rcode := header.RCode
	for _, additional := range parsed.additionals {
		if additional.Header.Type == dnsmessage.TypeOPT {
			rcode = additional.Header.ExtendedRCode(rcode)
			break
		}
	}

	records := make([]Record, 0, len(parsed.answers))
	for _, answer := range parsed.answers {
		if answer.Header.Class != dnsmessage.ClassINET {
			continue
		}
		name := canonicalName(answer.Header.Name.String())
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			address := netip.AddrFrom4(body.A)
			records = append(records, Record{
				Name:    name,
				Type:    QueryTypeA,
				TTL:     answer.Header.TTL,
				Address: address.String(),
				Family:  IPFamilyIPv4,
			})
		case *dnsmessage.AAAAResource:
			address := netip.AddrFrom16(body.AAAA)
			records = append(records, Record{
				Name:    name,
				Type:    QueryTypeAAAA,
				TTL:     answer.Header.TTL,
				Address: address.String(),
				Family:  IPFamilyIPv6,
			})
		case *dnsmessage.CNAMEResource:
			records = append(records, Record{
				Name:   name,
				Type:   QueryTypeCNAME,
				TTL:    answer.Header.TTL,
				Target: canonicalName(body.CNAME.String()),
			})
		}
	}

	var negativeSOA *SOARecord
	authorityNS := make([]NSRecord, 0)
	for _, authority := range parsed.authorities {
		if authority.Header.Class != dnsmessage.ClassINET {
			continue
		}
		switch body := authority.Body.(type) {
		case *dnsmessage.SOAResource:
			if negativeSOA == nil {
				negativeSOA = &SOARecord{
					Name:    canonicalName(authority.Header.Name.String()),
					TTL:     authority.Header.TTL,
					NS:      canonicalName(body.NS.String()),
					Mailbox: canonicalName(body.MBox.String()),
					Serial:  body.Serial,
					Refresh: body.Refresh,
					Retry:   body.Retry,
					Expire:  body.Expire,
					MinTTL:  body.MinTTL,
				}
			}
		case *dnsmessage.NSResource:
			authorityNS = append(authorityNS, NSRecord{
				Name:   canonicalName(authority.Header.Name.String()),
				TTL:    authority.Header.TTL,
				Target: canonicalName(body.NS.String()),
			})
		}
	}

	effectiveName, chainComplete := followCNAMEs(input.Hostname, records)
	kind := classifyAnswer(
		header,
		rcode,
		input.QueryType,
		input.Hostname,
		effectiveName,
		chainComplete && parsed.bodyComplete,
		records,
		negativeSOA != nil,
		len(authorityNS) > 0,
	)
	if kind != AnswerKindNoData && kind != AnswerKindNameError {
		negativeSOA = nil
	}

	return Evidence{
		RCode: ResponseCode{
			Code: uint16(rcode),
			Name: responseCodeName(rcode),
		},
		Flags: ResponseFlags{
			Authoritative:      header.Authoritative,
			Truncated:          header.Truncated,
			RecursionDesired:   header.RecursionDesired,
			RecursionAvailable: header.RecursionAvailable,
			AuthenticatedData:  header.AuthenticData,
			CheckingDisabled:   header.CheckingDisabled,
		},
		AnswerKind:     kind,
		EffectiveName:  effectiveName,
		Records:        records,
		NegativeSOA:    negativeSOA,
		AuthorityNS:    authorityNS,
		ResponseBytes:  responseBytes,
		RemoteEndpoint: remoteEndpoint,
		DoHStatus:      dohStatus,
	}, nil
}

func followCNAMEs(hostname string, records []Record) (string, bool) {
	targets := make(map[string]string)
	complete := true
	for _, record := range records {
		if record.Type != QueryTypeCNAME {
			continue
		}
		if existing, ok := targets[record.Name]; ok && existing != record.Target {
			complete = false
			continue
		}
		targets[record.Name] = record.Target
	}

	effective := hostname
	seen := map[string]struct{}{effective: {}}
	for range records {
		target, ok := targets[effective]
		if !ok {
			return effective, complete
		}
		if _, ok := seen[target]; ok {
			return effective, false
		}
		seen[target] = struct{}{}
		effective = target
	}
	if _, ok := targets[effective]; ok {
		return effective, false
	}
	return effective, complete
}

func classifyAnswer(
	header dnsmessage.Header,
	rcode dnsmessage.RCode,
	queryType QueryType,
	hostname string,
	effectiveName string,
	complete bool,
	records []Record,
	hasSOA bool,
	hasAuthorityNS bool,
) AnswerKind {
	if header.Truncated || !complete {
		return AnswerKindIncomplete
	}
	if rcode == dnsmessage.RCodeNameError {
		return AnswerKindNameError
	}
	if rcode != dnsmessage.RCodeSuccess {
		return AnswerKindRCodeError
	}

	wantedName := effectiveName
	if queryType == QueryTypeCNAME {
		wantedName = hostname
	}
	for _, record := range records {
		if record.Type == queryType && record.Name == wantedName {
			return AnswerKindAnswer
		}
	}
	if !hasSOA && hasAuthorityNS {
		return AnswerKindReferral
	}
	return AnswerKindNoData
}

func canonicalName(value string) string {
	value = strings.ToLower(value)
	if value == "." {
		return value
	}
	return strings.TrimSuffix(value, ".")
}

func wireQueryType(value QueryType) (dnsmessage.Type, error) {
	switch value {
	case QueryTypeA:
		return dnsmessage.TypeA, nil
	case QueryTypeAAAA:
		return dnsmessage.TypeAAAA, nil
	case QueryTypeCNAME:
		return dnsmessage.TypeCNAME, nil
	default:
		return 0, fmt.Errorf("unsupported DNS query type %q", value)
	}
}

func responseCodeName(rcode dnsmessage.RCode) string {
	switch rcode {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	default:
		return fmt.Sprintf("RCODE%d", rcode)
	}
}

func (t Transport) valid() bool {
	return t == TransportUDP || t == TransportTCP || t == TransportDoH
}

func (q QueryType) valid() bool {
	return q == QueryTypeA || q == QueryTypeAAAA || q == QueryTypeCNAME
}

func (k AnswerKind) valid() bool {
	switch k {
	case AnswerKindAnswer,
		AnswerKindNoData,
		AnswerKindNameError,
		AnswerKindReferral,
		AnswerKindRCodeError,
		AnswerKindIncomplete:
		return true
	default:
		return false
	}
}
