// Package familycondition observes whether the local kernel can select a
// public route and source address for IPv4 and IPv6 without sending payload.
// It records local detection conditions; it does not probe target reachability,
// send packets, retry, or assess an asset.
package familycondition

import (
	"context"
	"time"

	"github.com/wangjc683/reachrun/internal/probe"
)

const (
	// ProbeKind identifies local address-family condition evidence in the
	// shared Phase 0 envelope.
	ProbeKind = probe.KindAddressFamilyConditions

	// IPv4RouteTarget and IPv6RouteTarget are fixed public literals used only
	// for kernel route selection. The observer never writes to either endpoint.
	IPv4RouteTarget = "1.1.1.1:53"
	IPv6RouteTarget = "[2606:4700:4700::1111]:53"

	// FailureRouteCheck means route selection failed without an explicit,
	// stable local-unavailability classification.
	FailureRouteCheck probe.FailureCode = "route_check_failure"
)

// Family identifies the local address family whose condition was observed.
type Family string

const (
	FamilyIPv4 Family = "ipv4"
	FamilyIPv6 Family = "ipv6"
)

// Status distinguishes a selected route from an explicitly unavailable local
// condition. Unavailable is evidence, not a target failure.
type Status string

const (
	StatusRouteSelected Status = "route_selected"
	StatusUnavailable   Status = "unavailable"
)

// Reason records the stable fact behind one address-family status.
type Reason string

const (
	ReasonKernelRouteSelected      Reason = "kernel_route_selected"
	ReasonNoRoute                  Reason = "no_route"
	ReasonAddressFamilyUnsupported Reason = "address_family_unsupported"
	ReasonSourceAddressUnavailable Reason = "source_address_unavailable"
	ReasonNetworkDown              Reason = "network_down"
)

// Config bounds one observation of both address families. Networks, targets,
// ordering, and the no-write policy are fixed by the module contract.
type Config struct {
	Timeout time.Duration
}

// Input is empty because the observer checks the current environment under a
// fixed policy rather than a user-selected target.
type Input struct{}

// Condition is the kernel route-selection result for one address family.
// LocalAddress omits an IPv6 zone; LocalZone preserves it separately.
type Condition struct {
	Family           Family `json:"family"`
	Network          string `json:"network"`
	RouteTarget      string `json:"route_target"`
	Status           Status `json:"status"`
	Reason           Reason `json:"reason"`
	LocalAddress     string `json:"local_address,omitempty"`
	LocalZone        string `json:"local_zone,omitempty"`
	PayloadBytesSent int    `json:"payload_bytes_sent"`
}

// Evidence contains exactly one IPv4 condition followed by one IPv6
// condition. It proves route selection only, not packet delivery or replies.
type Evidence struct {
	Conditions []Condition `json:"conditions"`
}

// Result is the address-family-condition specialization of the Phase 0
// evidence envelope.
type Result = probe.Envelope[Input, Evidence]

// Observer returns one terminal envelope for the current local address-family
// conditions. Expected local unavailability is represented as evidence.
type Observer interface {
	Observe(ctx context.Context) Result
}
