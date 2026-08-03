package familycondition

import (
	"fmt"
	"net/netip"
	"reflect"
	"unicode/utf8"

	"github.com/wangjc683/reachrun/internal/probe"
)

// Validate checks the shared envelope and complete address-family-condition
// evidence contract. Scripted adapters should validate fixtures through it.
func Validate(result Result) error {
	if err := result.Validate(); err != nil {
		return fmt.Errorf("invalid probe envelope: %w", err)
	}
	if result.Probe != ProbeKind {
		return fmt.Errorf("probe must be %q", ProbeKind)
	}
	if !reflect.DeepEqual(result.Input, Input{}) {
		return fmt.Errorf("address-family-condition input must be empty")
	}
	if result.Failure != nil && !validFailureCode(result.Failure.Code) {
		return fmt.Errorf("unsupported address-family-condition failure code %q", result.Failure.Code)
	}
	if result.Outcome != probe.OutcomeSucceeded {
		return nil
	}
	if len(result.Evidence.Conditions) != len(routeSpecs) {
		return fmt.Errorf("evidence must contain exactly %d conditions", len(routeSpecs))
	}
	for index, spec := range routeSpecs {
		if err := validateCondition(index, result.Evidence.Conditions[index], spec); err != nil {
			return err
		}
	}
	return nil
}

func validateCondition(index int, condition Condition, spec routeSpec) error {
	prefix := fmt.Sprintf("condition %d", index)
	if condition.Family != spec.family {
		return fmt.Errorf("%s family must be %q", prefix, spec.family)
	}
	if condition.Network != spec.network {
		return fmt.Errorf("%s network must be %q", prefix, spec.network)
	}
	if condition.RouteTarget != spec.endpoint {
		return fmt.Errorf("%s route target must be %q", prefix, spec.endpoint)
	}
	if condition.PayloadBytesSent != 0 {
		return fmt.Errorf("%s must report zero payload bytes sent", prefix)
	}

	switch condition.Status {
	case StatusRouteSelected:
		if condition.Reason != ReasonKernelRouteSelected {
			return fmt.Errorf("%s selected route must use reason %q", prefix, ReasonKernelRouteSelected)
		}
		if err := validateLocalSource(condition, spec.family); err != nil {
			return fmt.Errorf("%s: %w", prefix, err)
		}
	case StatusUnavailable:
		if !validUnavailableReason(condition.Reason) {
			return fmt.Errorf("%s has unsupported unavailable reason %q", prefix, condition.Reason)
		}
		if condition.LocalAddress != "" || condition.LocalZone != "" {
			return fmt.Errorf("%s unavailable condition must not include a local source", prefix)
		}
	default:
		return fmt.Errorf("%s has unsupported status %q", prefix, condition.Status)
	}
	return nil
}

func validateLocalSource(condition Condition, family Family) error {
	address, err := netip.ParseAddr(condition.LocalAddress)
	if err != nil {
		return fmt.Errorf("local address %q is invalid: %w", condition.LocalAddress, err)
	}
	if address.Zone() != "" {
		return fmt.Errorf("local address must preserve its zone separately")
	}
	address = address.Unmap()
	if condition.LocalAddress != address.String() {
		return fmt.Errorf("local address must be canonical")
	}
	if address.IsUnspecified() || address.IsMulticast() {
		return fmt.Errorf("local address must be a selected unicast address")
	}
	if (family == FamilyIPv4) != address.Is4() {
		return fmt.Errorf("local address does not match %s", family)
	}
	if address.Is4() && condition.LocalZone != "" {
		return fmt.Errorf("IPv4 local address must not include a zone")
	}
	if !utf8.ValidString(condition.LocalZone) || len(condition.LocalZone) > 255 {
		return fmt.Errorf("local zone must be bounded valid UTF-8")
	}
	return nil
}

func validUnavailableReason(reason Reason) bool {
	switch reason {
	case ReasonNoRoute,
		ReasonAddressFamilyUnsupported,
		ReasonSourceAddressUnavailable,
		ReasonNetworkDown:
		return true
	default:
		return false
	}
}

func validFailureCode(code probe.FailureCode) bool {
	switch code {
	case FailureRouteCheck, probe.FailureTimeout, probe.FailureCancelled:
		return true
	default:
		return false
	}
}
