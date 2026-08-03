package webrecheck

import (
	"fmt"
	"net/netip"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

type scheduledCandidate struct {
	source CandidateSource
	ip     string
}

func normalizeRequest(request Request) (Input, error) {
	hostname, hostnameErr := nettarget.NormalizeWebHostname(request.Hostname)
	local, localFamily, localErr := normalizeCandidates("local", request.LocalCandidates)
	reference, referenceFamily, referenceErr := normalizeCandidates(
		"reference",
		request.ReferenceCandidates,
	)

	family := localFamily
	if family == "" {
		family = referenceFamily
	}
	input := Input{
		Hostname:                hostname,
		URL:                     "https://" + hostname + "/",
		Scheme:                  webobservation.SchemeHTTPS,
		Family:                  family,
		Port:                    httpsPort,
		Method:                  httpMethod,
		Path:                    httpPath,
		CandidateLimitPerSource: candidateLimitPerSource,
		RetryLimit:              retryLimit,
		RedirectLimit:           redirectLimit,
		LocalCandidates:         local,
		ReferenceCandidates:     reference,
	}

	switch {
	case hostnameErr != nil:
		return input, hostnameErr
	case localErr != nil:
		return input, localErr
	case referenceErr != nil:
		return input, referenceErr
	case localFamily != referenceFamily:
		return input, fmt.Errorf(
			"local family %q does not match reference family %q",
			localFamily,
			referenceFamily,
		)
	default:
		return input, nil
	}
}

func normalizeCandidates(
	label string,
	values []string,
) ([]string, webobservation.Family, error) {
	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	family := webobservation.Family("")
	var firstErr error

	for index, value := range values {
		text, address, err := nettarget.NormalizePublicIP(value)
		if _, duplicate := seen[text]; !duplicate {
			seen[text] = struct{}{}
			normalized = append(normalized, text)
		}
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s candidate %d: %w", label, index, err)
			}
			continue
		}
		candidateFamily := familyFor(address)
		if family == "" {
			family = candidateFamily
		} else if family != candidateFamily && firstErr == nil {
			firstErr = fmt.Errorf("%s candidates must use one address family", label)
		}
	}

	if len(values) == 0 {
		return normalized, family, fmt.Errorf("%s candidates must not be empty", label)
	}
	return normalized, family, firstErr
}

func familyFor(address netip.Addr) webobservation.Family {
	if address.Is4() {
		return webobservation.FamilyIPv4
	}
	return webobservation.FamilyIPv6
}

func schedule(input Input) []scheduledCandidate {
	local := boundedCandidates(input.LocalCandidates)
	reference := boundedCandidates(input.ReferenceCandidates)
	maximum := max(len(local), len(reference))
	result := make([]scheduledCandidate, 0, len(local)+len(reference))
	for index := range maximum {
		if index < len(local) {
			result = append(result, scheduledCandidate{source: CandidateLocal, ip: local[index]})
		}
		if index < len(reference) {
			result = append(result, scheduledCandidate{source: CandidateReference, ip: reference[index]})
		}
	}
	return result
}

func boundedCandidates(values []string) []string {
	return values[:min(len(values), candidateLimitPerSource)]
}

func omittedCandidates(values []string) int {
	return max(0, len(values)-candidateLimitPerSource)
}
