package tlsobservation

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"unicode/utf8"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/probe"
)

// Validate checks the shared envelope and complete hostname-free TLS evidence
// contract. Scripted adapters should validate fixtures through this function.
func Validate(result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe envelope: %w", err)
	}
	if result.Probe != ProbeKind {
		return fmt.Errorf("probe must be %q", ProbeKind)
	}
	if result.Input.Port != Port {
		return fmt.Errorf("input port must be %d", Port)
	}
	if result.Input.SNIMode != SNIOmittedNoHostname {
		return fmt.Errorf("input SNI mode must be %q", SNIOmittedNoHostname)
	}
	if result.Input.IdentityVerification != IdentityNotPerformedNoHostname {
		return fmt.Errorf("input identity verification must be %q", IdentityNotPerformedNoHostname)
	}
	if result.Failure != nil && !validFailureCode(result.Failure.Code) {
		return fmt.Errorf("unsupported TLS observation failure code %q", result.Failure.Code)
	}
	if result.Failure != nil && result.Failure.Code == probe.FailureInvalidInput {
		normalized, _, normalizeErr := normalizeRequest(Request{DialIP: result.Input.DialIP})
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
	wantRemote := netip.AddrPortFrom(address, Port).String()
	if evidence.RemoteEndpoint != wantRemote {
		return fmt.Errorf("remote endpoint must be %q", wantRemote)
	}
	if evidence.TCPConnectMS < 0 || evidence.TLS.HandshakeMS < 0 {
		return fmt.Errorf("stage timings must not be negative")
	}
	if evidence.TCPConnectMS+evidence.TLS.HandshakeMS > result.DurationMS {
		return fmt.Errorf("stage timings must fit within total duration")
	}

	switch evidence.TLS.Status {
	case TLSCompleted:
		if evidence.TLS.UnconfirmedReason != "" {
			return fmt.Errorf("completed TLS must not include an unconfirmed reason")
		}
		if evidence.TLS.Version == "" || evidence.TLS.CipherSuite == "" {
			return fmt.Errorf("completed TLS requires version and cipher suite")
		}
		if !utf8.ValidString(evidence.TLS.ALPN) || len(evidence.TLS.ALPN) > 255 {
			return fmt.Errorf("TLS ALPN must be bounded valid UTF-8")
		}
		if evidence.TLS.PeerCertificates < 1 || evidence.TLS.Leaf == nil {
			return fmt.Errorf("completed TLS requires peer and leaf certificate evidence")
		}
		if err := validateLeaf(*evidence.TLS.Leaf); err != nil {
			return err
		}
	case TLSUnconfirmed:
		if !validUnconfirmedReason(evidence.TLS.UnconfirmedReason) {
			return fmt.Errorf("unsupported unconfirmed reason %q", evidence.TLS.UnconfirmedReason)
		}
		if evidence.TLS.Version != "" || evidence.TLS.CipherSuite != "" ||
			evidence.TLS.ALPN != "" || evidence.TLS.PeerCertificates != 0 ||
			evidence.TLS.Leaf != nil {
			return fmt.Errorf("unconfirmed TLS must not include completed-handshake fields")
		}
	case "":
		return fmt.Errorf("TLS status must not be empty")
	default:
		return fmt.Errorf("unsupported TLS status %q", evidence.TLS.Status)
	}
	return nil
}

func validateLeaf(leaf LeafCertificate) error {
	decoded, err := hex.DecodeString(leaf.SHA256)
	if err != nil || len(decoded) != 32 {
		return fmt.Errorf("leaf sha256 must contain 32 lowercase hexadecimal bytes")
	}
	if leaf.SHA256 != fmt.Sprintf("%x", decoded) {
		return fmt.Errorf("leaf sha256 must use lowercase hexadecimal")
	}
	if leaf.NotBefore.IsZero() || leaf.NotAfter.IsZero() {
		return fmt.Errorf("leaf validity times must not be zero")
	}
	if _, offset := leaf.NotBefore.Zone(); offset != 0 {
		return fmt.Errorf("leaf not_before must use UTC")
	}
	if _, offset := leaf.NotAfter.Zone(); offset != 0 {
		return fmt.Errorf("leaf not_after must use UTC")
	}
	if !leaf.NotAfter.After(leaf.NotBefore) {
		return fmt.Errorf("leaf not_after must be after not_before")
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
	case UnconfirmedHandshakeTimeout,
		UnconfirmedConnectionClosed,
		UnconfirmedConnectionReset,
		UnconfirmedHandshakeFailure,
		UnconfirmedExchangeFailure:
		return true
	default:
		return false
	}
}
