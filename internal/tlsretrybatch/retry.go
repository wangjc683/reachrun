package tlsretrybatch

import (
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

// shouldRetry is deliberately TLS-specific. The aggregate never retries a
// completed handshake, cancellation, connection refusal, no-route result, or
// an unclassified/deterministic TLS failure.
func shouldRetry(result tlsobservation.Result) bool {
	switch result.Outcome {
	case probe.OutcomeFailed:
		if result.Failure == nil {
			return false
		}
		return result.Failure.Code == tlsobservation.FailureTCPTimeout ||
			result.Failure.Code == tlsobservation.FailureTCPConnectionReset
	case probe.OutcomeSucceeded:
		if result.Evidence == nil || result.Evidence.TLS.Status != tlsobservation.TLSUnconfirmed {
			return false
		}
		return result.Evidence.TLS.UnconfirmedReason == tlsobservation.UnconfirmedHandshakeTimeout ||
			result.Evidence.TLS.UnconfirmedReason == tlsobservation.UnconfirmedConnectionReset
	default:
		return false
	}
}
