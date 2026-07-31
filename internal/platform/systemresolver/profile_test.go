package systemresolver

import (
	"testing"

	"github.com/wangjc683/reachrun/internal/probe"
)

func TestNetDNSMode(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		godebug string
		want    string
	}{
		"empty":                 {godebug: "", want: ""},
		"go":                    {godebug: "netdns=go", want: "go"},
		"cgo debug":             {godebug: "netdns=cgo+2", want: "cgo"},
		"debug before go":       {godebug: "netdns=1+go", want: "go"},
		"bisect is conditional": {godebug: "netdns=cgo+1#example", want: "conditional"},
		"numeric only":          {godebug: "netdns=1", want: ""},
		"right most wins":       {godebug: "netdns=cgo,other=1,netdns=go+1", want: "go"},
		"whitespace is exact":   {godebug: "netdns=go, netdns=cgo", want: "go"},
		"right most invalid":    {godebug: "netdns=cgo,netdns=invalid", want: ""},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := netDNSMode(test.godebug); got != test.want {
				t.Fatalf("netDNSMode(%q) = %q, want %q", test.godebug, got, test.want)
			}
		})
	}
}

func TestSourceForGODEBUGIsConservative(t *testing.T) {
	t.Parallel()

	profile := resolverBuildProfile{
		nativeAvailable: true,
		nativeByDefault: false,
		nativeBackend:   "native-test",
		fallbackBackend: "unverified-test",
		fallbackReason:  "backend_selection_unverified",
	}

	tests := map[string]struct {
		godebug    string
		backend    string
		capability probe.Capability
		reason     string
	}{
		"dynamic default is degraded": {
			backend:    "unverified-test",
			capability: probe.CapabilityDegraded,
			reason:     "backend_selection_unverified",
		},
		"forced go is degraded": {
			godebug:    "netdns=go",
			backend:    "go-dns-resolver",
			capability: probe.CapabilityDegraded,
			reason:     "go_resolver_forced",
		},
		"forced native is native": {
			godebug:    "netdns=cgo",
			backend:    "native-test",
			capability: probe.CapabilityNative,
		},
		"bisect selection is degraded": {
			godebug:    "netdns=cgo#example",
			backend:    "resolver-selection-conditional",
			capability: probe.CapabilityDegraded,
			reason:     "godebug_bisect_selection_unverified",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := sourceForGODEBUG(profile, test.godebug)
			if got.Backend != test.backend ||
				got.Capability != test.capability ||
				got.Reason != test.reason {
				t.Fatalf(
					"source = %#v, want backend %q capability %q reason %q",
					got,
					test.backend,
					test.capability,
					test.reason,
				)
			}
			if got.Capability == probe.CapabilityDegraded && got.Reason == "" {
				t.Fatal("degraded source has no reason")
			}
		})
	}
}
