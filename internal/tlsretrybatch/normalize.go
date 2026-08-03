package tlsretrybatch

import (
	"fmt"
	"net/netip"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/tlsobservation"
)

func normalizeRequest(request Request) (Input, error) {
	targets := make([]string, 0, len(request.Targets))
	seen := make(map[string]struct{}, len(request.Targets))
	var firstErr error
	for index, value := range request.Targets {
		text, _, err := nettarget.NormalizePublicIP(value)
		if _, duplicate := seen[text]; !duplicate {
			seen[text] = struct{}{}
			targets = append(targets, text)
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("target %d: %w", index, err)
		}
	}

	input := Input{
		Targets:              targets,
		TargetLimit:          targetLimit,
		ConcurrencyLimit:     concurrencyLimit,
		AttemptLimit:         attemptLimit,
		RetryLimit:           retryLimit,
		Port:                 tlsobservation.Port,
		SNIMode:              tlsobservation.SNIOmittedNoHostname,
		IdentityVerification: tlsobservation.IdentityNotPerformedNoHostname,
		PerAttemptTimeoutMS:  perAttemptTimeout.Milliseconds(),
		BackoffMinMS:         backoffMin.Milliseconds(),
		BackoffMaxMS:         backoffMax.Milliseconds(),
	}
	if len(request.Targets) == 0 {
		return input, fmt.Errorf("targets must not be empty")
	}
	if firstErr != nil {
		return input, firstErr
	}
	if len(targets) > requestTargetLimit {
		return input, fmt.Errorf("targets must contain at most %d unique addresses", requestTargetLimit)
	}
	return input, nil
}

func boundedTargets(input Input) []string {
	return input.Targets[:min(len(input.Targets), targetLimit)]
}

func omittedTargets(input Input) int {
	return max(0, len(input.Targets)-targetLimit)
}

func targetFamily(value string) tlsobservation.Family {
	address := netip.MustParseAddr(value)
	if address.Is4() {
		return tlsobservation.FamilyIPv4
	}
	return tlsobservation.FamilyIPv6
}

func expectedTLSInput(target string) tlsobservation.Input {
	return tlsobservation.Input{
		DialIP:               target,
		Family:               targetFamily(target),
		Port:                 tlsobservation.Port,
		SNIMode:              tlsobservation.SNIOmittedNoHostname,
		IdentityVerification: tlsobservation.IdentityNotPerformedNoHostname,
	}
}
