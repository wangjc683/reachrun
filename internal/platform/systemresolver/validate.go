package systemresolver

import (
	"fmt"
	"net/netip"

	"github.com/wangjc683/reachrun/internal/probe"
)

// Validate checks both the shared envelope rules and the system-resolution
// evidence contract.
func Validate(result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe envelope: %w", err)
	}
	if result.Probe != probe.KindSystemResolution {
		return fmt.Errorf("probe must be %q", probe.KindSystemResolution)
	}
	if result.Failure != nil && !validFailureCode(result.Failure.Code) {
		return fmt.Errorf("unsupported system resolver failure code %q", result.Failure.Code)
	}
	normalizedHostname, inputErr := normalizeHostname(result.Input.Hostname)
	if normalizedHostname != result.Input.Hostname {
		return fmt.Errorf("input hostname must be normalized")
	}
	if inputErr != nil {
		if result.Outcome != probe.OutcomeFailed ||
			result.Failure == nil ||
			result.Failure.Code != probe.FailureInvalidInput {
			return fmt.Errorf("invalid hostname must produce failed/invalid_input")
		}
		return nil
	}
	if result.Failure != nil && result.Failure.Code == probe.FailureInvalidInput {
		return fmt.Errorf("valid hostname must not produce invalid_input")
	}
	if result.Outcome != probe.OutcomeSucceeded {
		return nil
	}
	if len(result.Evidence.Addresses) == 0 {
		return fmt.Errorf("successful system resolution must include at least one address")
	}

	seen := make(map[netip.Addr]struct{}, len(result.Evidence.Addresses))
	for index, address := range result.Evidence.Addresses {
		parsed, err := netip.ParseAddr(address.IP)
		if err != nil {
			return fmt.Errorf("address %d has invalid ip %q: %w", index, address.IP, err)
		}
		parsed = parsed.Unmap()
		if address.IP != parsed.String() {
			return fmt.Errorf("address %d ip %q is not canonical", index, address.IP)
		}

		expectedFamily := FamilyIPv6
		if parsed.Is4() {
			expectedFamily = FamilyIPv4
		}
		if address.Family != expectedFamily {
			return fmt.Errorf(
				"address %d family %q does not match %q",
				index,
				address.Family,
				address.IP,
			)
		}
		if _, ok := seen[parsed]; ok {
			return fmt.Errorf("address %d duplicates %q", index, address.IP)
		}
		seen[parsed] = struct{}{}
	}

	return nil
}

func validFailureCode(code probe.FailureCode) bool {
	switch code {
	case probe.FailureInvalidInput,
		probe.FailureNameUnresolved,
		probe.FailureTimeout,
		probe.FailureResolutionFailure,
		probe.FailureCancelled:
		return true
	default:
		return false
	}
}
