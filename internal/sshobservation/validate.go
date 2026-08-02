package sshobservation

import (
	"fmt"
	"net/netip"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/probe"
)

// Validate checks the shared envelope and complete SSH-observation evidence
// contract. Scripted adapters should validate fixtures through this function.
func Validate(result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe envelope: %w", err)
	}
	if result.Probe != ProbeKind {
		return fmt.Errorf("probe must be %q", ProbeKind)
	}
	if result.Input.Port == 0 {
		return fmt.Errorf("input port must not be zero")
	}
	if result.Input.ClientIdentification != ClientIdentification {
		return fmt.Errorf("input client identification must be the fixed module value")
	}
	if result.Failure != nil && !validFailureCode(result.Failure.Code) {
		return fmt.Errorf("unsupported SSH observation failure code %q", result.Failure.Code)
	}
	if result.Failure != nil && result.Failure.Code == probe.FailureInvalidInput {
		normalized, _, normalizeErr := normalizeRequest(Request{
			DialIP: result.Input.DialIP,
			Port:   result.Input.Port,
		})
		if normalizeErr == nil {
			return fmt.Errorf("invalid_input failure requires an invalid target")
		}
		if normalized != result.Input {
			return fmt.Errorf("invalid_input must preserve the normalized and derived representation")
		}
		return nil
	}

	text, address, err := nettarget.NormalizePublicIP(result.Input.DialIP)
	if err != nil {
		return fmt.Errorf("input dial_ip is not an allowed public address: %w", err)
	}
	if text != result.Input.DialIP {
		return fmt.Errorf("input dial_ip must be canonical")
	}
	wantFamily := FamilyIPv6
	if address.Is4() {
		wantFamily = FamilyIPv4
	}
	if result.Input.Family != wantFamily {
		return fmt.Errorf("input family must be %q", wantFamily)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		return nil
	}

	evidence := result.Evidence
	wantRemote := netip.AddrPortFrom(address, result.Input.Port).String()
	if evidence.RemoteEndpoint != wantRemote {
		return fmt.Errorf("remote endpoint must be %q", wantRemote)
	}
	if evidence.TCPConnectMS < 0 {
		return fmt.Errorf("tcp_connect_ms must not be negative")
	}
	identification := evidence.Identification
	if identification.ExchangeMS < 0 {
		return fmt.Errorf("exchange_ms must not be negative")
	}
	if evidence.TCPConnectMS+identification.ExchangeMS > result.DurationMS {
		return fmt.Errorf("stage timings must fit within total duration")
	}
	if identification.PreambleLines < 0 || identification.PreambleLines > maxPreambleLines {
		return fmt.Errorf("preamble_lines must be between zero and %d", maxPreambleLines)
	}

	switch identification.Status {
	case IdentificationReceived:
		if identification.UnconfirmedReason != "" {
			return fmt.Errorf("received identification must not include an unconfirmed reason")
		}
		if !identification.ClientIdentificationSent {
			return fmt.Errorf("received identification requires the client line to be sent")
		}
		parsed, err := parseIdentificationLine([]byte(identification.ServerIdentification + "\n"))
		if err != nil {
			return fmt.Errorf("server identification is invalid: %w", err)
		}
		if parsed.protocolVersion != identification.ProtocolVersion ||
			parsed.softwareVersion != identification.SoftwareVersion ||
			parsed.comments != identification.Comments {
			return fmt.Errorf("structured identification fields do not match the server line")
		}
	case IdentificationUnconfirmed:
		if !validUnconfirmedReason(identification.UnconfirmedReason) {
			return fmt.Errorf("unsupported unconfirmed reason %q", identification.UnconfirmedReason)
		}
		if identification.ServerIdentification != "" ||
			identification.ProtocolVersion != "" ||
			identification.SoftwareVersion != "" ||
			identification.Comments != "" {
			return fmt.Errorf("unconfirmed identification must not include parsed server fields")
		}
	case "":
		return fmt.Errorf("identification status must not be empty")
	default:
		return fmt.Errorf("unsupported identification status %q", identification.Status)
	}
	return nil
}

func validFailureCode(code probe.FailureCode) bool {
	switch code {
	case probe.FailureInvalidInput,
		probe.FailureCancelled,
		FailureTCPConnectionRefused,
		FailureTCPNoRoute,
		FailureTCPTimeout,
		FailureTCPConnectionReset,
		FailureTCP:
		return true
	default:
		return false
	}
}

func validUnconfirmedReason(reason UnconfirmedReason) bool {
	switch reason {
	case UnconfirmedInvalidIdentification,
		UnconfirmedTimeout,
		UnconfirmedConnectionClosed,
		UnconfirmedConnectionReset,
		UnconfirmedPreambleLimit,
		UnconfirmedExchangeFailure:
		return true
	default:
		return false
	}
}
