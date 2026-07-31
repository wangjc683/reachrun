package systemresolver

import (
	"os"
	"strings"

	"github.com/wangjc683/reachrun/internal/probe"
)

type resolverBuildProfile struct {
	nativeAvailable bool
	nativeByDefault bool
	nativeBackend   string
	fallbackBackend string
	fallbackReason  string
}

func currentSource() probe.Source {
	return sourceForGODEBUG(compiledResolverProfile(), os.Getenv("GODEBUG"))
}

func sourceForGODEBUG(profile resolverBuildProfile, godebug string) probe.Source {
	switch netDNSMode(godebug) {
	case "go":
		return probe.Source{
			Backend:    "go-dns-resolver",
			Capability: probe.CapabilityDegraded,
			Reason:     "go_resolver_forced",
		}
	case "cgo":
		if profile.nativeAvailable {
			return probe.Source{
				Backend:    profile.nativeBackend,
				Capability: probe.CapabilityNative,
			}
		}
		return probe.Source{
			Backend:    profile.fallbackBackend,
			Capability: probe.CapabilityDegraded,
			Reason:     "native_backend_unavailable",
		}
	case "conditional":
		return probe.Source{
			Backend:    "resolver-selection-conditional",
			Capability: probe.CapabilityDegraded,
			Reason:     "godebug_bisect_selection_unverified",
		}
	default:
		if profile.nativeByDefault {
			return probe.Source{
				Backend:    profile.nativeBackend,
				Capability: probe.CapabilityNative,
			}
		}
		return probe.Source{
			Backend:    profile.fallbackBackend,
			Capability: probe.CapabilityDegraded,
			Reason:     profile.fallbackReason,
		}
	}
}

// netDNSMode follows Go's right-most-wins GODEBUG convention, recognizes the
// optional +debug-level suffix, and keeps bisect-conditioned settings
// unverified because their value depends on the eventual call stack.
func netDNSMode(godebug string) string {
	settings := strings.Split(godebug, ",")
	for i := len(settings) - 1; i >= 0; i-- {
		name, value, ok := strings.Cut(settings[i], "=")
		if !ok || name != "netdns" {
			continue
		}

		if _, _, conditional := strings.Cut(value, "#"); conditional {
			return "conditional"
		}
		mode := ""
		parsePart := func(part string) {
			if part == "" || (part[0] >= '0' && part[0] <= '9') {
				return
			}
			mode = part
		}
		if first, second, found := strings.Cut(value, "+"); found {
			parsePart(first)
			parsePart(second)
		} else {
			parsePart(value)
		}
		if mode == "go" || mode == "cgo" {
			return mode
		}
		return ""
	}

	return ""
}
