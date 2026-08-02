// Package nettarget centralizes the product safety policy for literal network
// targets. It does not resolve names or decide which target should be probed.
package nettarget

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// deniedPublicPrefixes complements netip's broad GlobalUnicast classification
// with product-forbidden special-purpose ranges. Review it against the IANA
// IPv4/IPv6 Special-Purpose Address Registries when those registries change.
var deniedPublicPrefixes = mustPrefixes(
	// IPv4 special-purpose, private, shared, documentation, benchmarking,
	// multicast, and reserved ranges.
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	// IPv6 translation, discard, IETF special-use, documentation, 6to4,
	// unique-local, link-local, and multicast ranges.
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"100::/64",
	"2001::/23",
	"2001:db8::/32",
	"2002::/16",
	"3ffe::/16",
	"3fff::/20",
	"5f00::/16",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
)

var allocatedIPv6GlobalUnicast = netip.MustParsePrefix("2000::/3")

// NormalizePublicIP parses one literal public address, removes an IPv4-mapped
// IPv6 wrapper, and returns its canonical text. Names, zones, and all
// product-forbidden special-purpose addresses are rejected.
func NormalizePublicIP(value string) (string, netip.Addr, error) {
	text := strings.TrimSpace(value)
	ip, err := netip.ParseAddr(text)
	if err != nil {
		return text, netip.Addr{}, fmt.Errorf("target must be one IP literal: %w", err)
	}
	if ip.Zone() != "" {
		return ip.String(), netip.Addr{}, errors.New("target must not include an IPv6 zone")
	}
	ip = ip.Unmap()
	text = ip.String()
	if !isAllowedPublicIP(ip) {
		return text, ip, fmt.Errorf("target %q is not an allowed public address", text)
	}
	return text, ip, nil
}

func isAllowedPublicIP(ip netip.Addr) bool {
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() ||
		ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() ||
		ip.IsUnspecified() {
		return false
	}
	// netip reports reserved unicast space such as 4000::/3 as globally
	// unicast. ReachRun only connects to the IPv6 range currently allocated
	// for global unicast, then subtracts product-forbidden special ranges.
	if ip.Is6() && !allocatedIPv6GlobalUnicast.Contains(ip) {
		return false
	}
	for _, prefix := range deniedPublicPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
