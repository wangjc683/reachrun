package resolverinventory

import (
	"fmt"
	"reflect"

	"github.com/wangjc683/reachrun/internal/probe"
)

// Validate checks the shared envelope rules and resolver-inventory-specific
// evidence, source, and failure invariants.
func Validate(result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe envelope: %w", err)
	}
	if result.Probe != probe.KindResolverInventory {
		return fmt.Errorf("probe must be %q", probe.KindResolverInventory)
	}
	if !reflect.DeepEqual(result.Input, Input{}) {
		return fmt.Errorf("resolver inventory input must be empty")
	}
	if result.Failure != nil && !validFailureCode(result.Failure.Code) {
		return fmt.Errorf("unsupported resolver inventory failure code %q", result.Failure.Code)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		return nil
	}

	normalized, err := normalizeEvidence(*result.Evidence)
	if err != nil {
		return fmt.Errorf("invalid resolver inventory evidence: %w", err)
	}
	if !reflect.DeepEqual(normalized, *result.Evidence) {
		return fmt.Errorf("resolver inventory evidence must be canonical and deduplicated")
	}
	return nil
}

func validFailureCode(code probe.FailureCode) bool {
	switch code {
	case FailureUnavailable,
		FailureInvalid,
		probe.FailureTimeout,
		probe.FailureCancelled:
		return true
	default:
		return false
	}
}
