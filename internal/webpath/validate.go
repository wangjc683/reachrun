package webpath

import (
	"fmt"
	"net/netip"
	"net/url"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/platform/systemresolver"
	"github.com/wangjc683/reachrun/internal/probe"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

// Validate checks the complete aggregate contract, including every nested
// probe envelope and the safety-preserving relationship between redirects,
// resolutions, candidate IPs, and actual Web attempts.
func Validate(result Result) error {
	if result.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version must be %d", SchemaVersion)
	}
	if result.Operation != Operation {
		return fmt.Errorf("operation must be %q", Operation)
	}
	if result.ObservedAt.IsZero() {
		return fmt.Errorf("observed_at must not be zero")
	}
	if _, offset := result.ObservedAt.Zone(); offset != 0 {
		return fmt.Errorf("observed_at must use UTC")
	}
	if result.DurationMS < 0 {
		return fmt.Errorf("duration_ms must not be negative")
	}
	if result.Platform.OS == "" || result.Platform.Arch == "" {
		return fmt.Errorf("platform os and arch must not be empty")
	}
	if result.Hops == nil {
		return fmt.Errorf("hops must be an explicit array")
	}
	if result.RedirectsFollowed < 0 || result.RedirectsFollowed > redirectLimit {
		return fmt.Errorf("redirects_followed must be between zero and %d", redirectLimit)
	}

	normalizedInput, _, inputErr := normalizeInput(Request{Hostname: result.Input.Hostname})
	if normalizedInput != result.Input {
		return fmt.Errorf("input must use its normalized and fixed representation")
	}
	if inputErr != nil {
		if result.Status != StatusStopped || result.StopReason != StopInvalidInput ||
			len(result.Hops) != 0 || result.RedirectsFollowed != 0 || result.HTTPFallbackUsed {
			return fmt.Errorf("invalid hostname requires stopped/invalid_input with no hops")
		}
		return nil
	}
	if result.Status == StatusStopped && result.StopReason == StopInvalidInput {
		return fmt.Errorf("valid hostname must not stop as invalid_input")
	}
	if err := validateTerminalPair(result.Status, result.StopReason); err != nil {
		return err
	}
	if result.Status == StatusCompleted && result.Detail != "" {
		return fmt.Errorf("completed path must not include stop detail")
	}

	maximumHops := redirectLimit + 1
	if result.HTTPFallbackUsed {
		maximumHops++
	}
	if len(result.Hops) > maximumHops {
		return fmt.Errorf("hops exceed bounded maximum %d", maximumHops)
	}
	if len(result.Hops) > 0 && result.Hops[0].URL != result.Input.InitialURL {
		return fmt.Errorf("first hop URL must be %q", result.Input.InitialURL)
	}

	parsedURLs := make([]*url.URL, len(result.Hops))
	for index := range result.Hops {
		parsed, err := validateHop(result.Platform, result.Hops[index])
		if err != nil {
			return fmt.Errorf("invalid hop %d: %w", index, err)
		}
		parsedURLs[index] = parsed
	}
	if result.HTTPFallbackUsed &&
		(len(result.Hops) == 0 || !exhaustedPublicCandidates(result.Hops[0])) {
		return fmt.Errorf("HTTP fallback requires exhausted initial HTTPS candidates")
	}

	computedRedirects := 0
	for index := 1; index < len(result.Hops); index++ {
		if result.HTTPFallbackUsed && index == 1 {
			want := "http://" + result.Input.Hostname + "/"
			if result.Hops[index].URL != want || !exhaustedPublicCandidates(result.Hops[index-1]) {
				return fmt.Errorf("HTTP fallback must follow a failed initial HTTPS hop at %q", want)
			}
			continue
		}

		previous := result.Hops[index-1]
		success := successfulAttempt(previous)
		if success == nil || !isRedirectStatus(success.Evidence.HTTP.StatusCode) {
			return fmt.Errorf("hop %d is not reached from a successful redirect", index)
		}
		next, _, err := redirectTarget(parsedURLs[index-1], success.Evidence.HTTP)
		if err != nil {
			return fmt.Errorf("hop %d follows unusable redirect: %w", index, err)
		}
		if next.String() != result.Hops[index].URL {
			return fmt.Errorf("hop %d URL %q does not match redirect target %q", index, result.Hops[index].URL, next)
		}
		computedRedirects++
	}
	if computedRedirects != result.RedirectsFollowed {
		return fmt.Errorf("redirects_followed = %d, want %d from hop transitions", result.RedirectsFollowed, computedRedirects)
	}
	if result.HTTPFallbackUsed && len(result.Hops) < 2 &&
		result.Status != StatusCancelled &&
		result.StopReason != StopPathTimeout &&
		result.StopReason != StopInvalidProbeEvidence {
		return fmt.Errorf("HTTP fallback requires an HTTP hop unless interrupted")
	}

	if err := validateTerminalEvidence(result, parsedURLs); err != nil {
		return err
	}
	return nil
}

func validateTerminalPair(status Status, reason StopReason) error {
	switch status {
	case StatusCompleted:
		if reason != StopFinalResponse {
			return fmt.Errorf("completed status requires final_response")
		}
	case StatusCancelled:
		if reason != StopCancelled {
			return fmt.Errorf("cancelled status requires cancelled reason")
		}
	case StatusStopped:
		if reason == "" || reason == StopFinalResponse || reason == StopCancelled || !validStoppedReason(reason) {
			return fmt.Errorf("stopped status has unsupported reason %q", reason)
		}
	default:
		return fmt.Errorf("unsupported status %q", status)
	}
	return nil
}

func validStoppedReason(reason StopReason) bool {
	switch reason {
	case StopInvalidInput,
		StopResolutionFailed,
		StopNoPublicCandidates,
		StopAllCandidatesFailed,
		StopRedirectLocationUnavailable,
		StopRedirectTargetInvalid,
		StopRedirectTargetUnsafe,
		StopRedirectLoop,
		StopRedirectLimit,
		StopPathTimeout,
		StopInvalidProbeEvidence:
		return true
	default:
		return false
	}
}

func validateHop(platform probe.Platform, hop Hop) (*url.URL, error) {
	parsed, err := url.Parse(hop.URL)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.String() != hop.URL || parsed.User != nil || parsed.Fragment != "" || parsed.Opaque != "" {
		return nil, fmt.Errorf("URL must be canonical HTTP(S) without credentials or fragment")
	}
	scheme := webobservation.Scheme(parsed.Scheme)
	if scheme != webobservation.SchemeHTTP && scheme != webobservation.SchemeHTTPS {
		return nil, fmt.Errorf("unsupported scheme %q", parsed.Scheme)
	}
	if parsed.Port() != "" {
		return nil, fmt.Errorf("canonical hop URL must not include an explicit default port")
	}
	hostname, err := nettarget.NormalizeWebHostname(parsed.Hostname())
	if err != nil || hostname != parsed.Hostname() {
		return nil, fmt.Errorf("URL hostname is not normalized: %v", err)
	}
	if parsed.EscapedPath() == "" {
		return nil, fmt.Errorf("URL must include an explicit path")
	}
	if err := systemresolver.Validate(hop.Resolution); err != nil {
		return nil, fmt.Errorf("resolution: %w", err)
	}
	if hop.Resolution.Platform != platform {
		return nil, fmt.Errorf("resolution platform does not match path platform")
	}
	if hop.Resolution.Input.Hostname != hostname {
		return nil, fmt.Errorf("resolution hostname %q does not match URL hostname %q", hop.Resolution.Input.Hostname, hostname)
	}
	if hop.Attempts == nil {
		return nil, fmt.Errorf("attempts must be an explicit array")
	}
	if hop.Resolution.Outcome != probe.OutcomeSucceeded && len(hop.Attempts) != 0 {
		return nil, fmt.Errorf("failed resolution must not have Web attempts")
	}

	resolvedAddresses := addressSet(hop.Resolution)
	selectedCandidates := []string(nil)
	if hop.Resolution.Outcome == probe.OutcomeSucceeded {
		selectedCandidates = selectPublicCandidates(hop.Resolution.Evidence.Addresses)
	}
	familyCounts := map[webobservation.Family]int{}
	attempted := make(map[netip.Addr]struct{}, len(hop.Attempts))
	successes := 0
	for index, attempt := range hop.Attempts {
		if err := webobservation.Validate(attempt); err != nil {
			return nil, fmt.Errorf("attempt %d: %w", index, err)
		}
		if attempt.Platform != platform {
			return nil, fmt.Errorf("attempt %d platform does not match path platform", index)
		}
		if attempt.Input.Scheme != scheme ||
			attempt.Input.Hostname != hostname ||
			attempt.Input.Path != parsed.EscapedPath() ||
			attempt.Input.RawQuery != parsed.RawQuery {
			return nil, fmt.Errorf("attempt %d request does not match hop URL", index)
		}
		address, err := netip.ParseAddr(attempt.Input.DialIP)
		if err != nil {
			return nil, fmt.Errorf("attempt %d dial IP is invalid: %w", index, err)
		}
		address = address.Unmap()
		if index >= len(selectedCandidates) || attempt.Input.DialIP != selectedCandidates[index] {
			return nil, fmt.Errorf("attempt %d does not follow bounded resolver order", index)
		}
		if _, ok := resolvedAddresses[address]; !ok {
			return nil, fmt.Errorf("attempt %d dial IP was not returned by this resolution", index)
		}
		if _, _, err := nettarget.NormalizePublicIP(address.String()); err != nil {
			return nil, fmt.Errorf("attempt %d dial IP is not an allowed public address: %w", index, err)
		}
		if _, duplicate := attempted[address]; duplicate {
			return nil, fmt.Errorf("attempt %d repeats dial IP %q", index, address)
		}
		attempted[address] = struct{}{}
		familyCounts[attempt.Input.Family]++
		if familyCounts[attempt.Input.Family] > candidateLimitPerFamily {
			return nil, fmt.Errorf("attempts exceed per-family candidate limit")
		}
		if attempt.Outcome == probe.OutcomeSucceeded {
			successes++
			if index != len(hop.Attempts)-1 {
				return nil, fmt.Errorf("successful attempt must be terminal for its hop")
			}
		}
		if attempt.Outcome == probe.OutcomeCancelled && index != len(hop.Attempts)-1 {
			return nil, fmt.Errorf("cancelled attempt must be terminal for its hop")
		}
	}
	if successes > 1 {
		return nil, fmt.Errorf("hop must not include more than one successful attempt")
	}
	return parsed, nil
}

func addressSet(resolution systemresolver.Result) map[netip.Addr]struct{} {
	result := make(map[netip.Addr]struct{})
	if resolution.Outcome != probe.OutcomeSucceeded {
		return result
	}
	for _, address := range resolution.Evidence.Addresses {
		parsed, err := netip.ParseAddr(address.IP)
		if err == nil {
			result[parsed.Unmap()] = struct{}{}
		}
	}
	return result
}

func successfulAttempt(hop Hop) *webobservation.Result {
	if len(hop.Attempts) == 0 {
		return nil
	}
	last := &hop.Attempts[len(hop.Attempts)-1]
	if last.Outcome != probe.OutcomeSucceeded {
		return nil
	}
	return last
}

func exhaustedPublicCandidates(hop Hop) bool {
	if hop.Resolution.Outcome != probe.OutcomeSucceeded || successfulAttempt(hop) != nil {
		return false
	}
	candidates := selectPublicCandidates(hop.Resolution.Evidence.Addresses)
	if len(candidates) == 0 || len(hop.Attempts) != len(candidates) {
		return false
	}
	for _, attempt := range hop.Attempts {
		if attempt.Outcome != probe.OutcomeFailed {
			return false
		}
	}
	return true
}

func validateTerminalEvidence(result Result, parsedURLs []*url.URL) error {
	if result.StopReason == StopInvalidProbeEvidence ||
		result.StopReason == StopPathTimeout ||
		result.Status == StatusCancelled {
		return nil
	}
	if len(result.Hops) == 0 {
		return fmt.Errorf("terminal reason %q requires at least one hop", result.StopReason)
	}
	last := result.Hops[len(result.Hops)-1]
	success := successfulAttempt(last)

	switch result.StopReason {
	case StopFinalResponse:
		if success == nil || isRedirectStatus(success.Evidence.HTTP.StatusCode) {
			return fmt.Errorf("final_response requires a successful non-redirect response")
		}
	case StopResolutionFailed:
		if last.Resolution.Outcome != probe.OutcomeFailed || len(last.Attempts) != 0 {
			return fmt.Errorf("resolution_failed requires a failed resolution and no attempts")
		}
	case StopNoPublicCandidates:
		if last.Resolution.Outcome != probe.OutcomeSucceeded ||
			len(selectPublicCandidates(last.Resolution.Evidence.Addresses)) != 0 ||
			len(last.Attempts) != 0 {
			return fmt.Errorf("no_public_candidates does not match last-hop evidence")
		}
	case StopAllCandidatesFailed:
		if !exhaustedPublicCandidates(last) {
			return fmt.Errorf("all_candidates_failed requires only failed attempts")
		}
	case StopRedirectLocationUnavailable:
		if success == nil || !isRedirectStatus(success.Evidence.HTTP.StatusCode) ||
			(!success.Evidence.HTTP.LocationOmitted && success.Evidence.HTTP.Location != "") {
			return fmt.Errorf("redirect_location_unavailable does not match last response")
		}
	case StopRedirectTargetInvalid, StopRedirectTargetUnsafe:
		if success == nil || !isRedirectStatus(success.Evidence.HTTP.StatusCode) {
			return fmt.Errorf("redirect target stop requires a successful redirect response")
		}
		_, reason, err := redirectTarget(parsedURLs[len(parsedURLs)-1], success.Evidence.HTTP)
		if err == nil || reason != result.StopReason {
			return fmt.Errorf("redirect target stop reason does not match Location")
		}
	case StopRedirectLoop:
		if success == nil || !isRedirectStatus(success.Evidence.HTTP.StatusCode) {
			return fmt.Errorf("redirect_loop requires a successful redirect response")
		}
		next, _, err := redirectTarget(parsedURLs[len(parsedURLs)-1], success.Evidence.HTTP)
		if err != nil {
			return fmt.Errorf("redirect_loop Location is unusable: %w", err)
		}
		found := false
		for _, prior := range parsedURLs {
			if prior.String() == next.String() {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("redirect_loop target does not repeat an observed URL")
		}
	case StopRedirectLimit:
		if result.RedirectsFollowed != redirectLimit || success == nil ||
			!isRedirectStatus(success.Evidence.HTTP.StatusCode) {
			return fmt.Errorf("redirect_limit does not match last response or count")
		}
	}
	return nil
}
