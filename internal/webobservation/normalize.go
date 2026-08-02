package webobservation

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

const (
	httpPort   = 80
	httpsPort  = 443
	httpMethod = "GET"
	httpPath   = "/"
)

// deniedTargetPrefixes complements netip's broad GlobalUnicast classification
// with product-forbidden special-purpose ranges. Review it against the IANA
// IPv4/IPv6 Special-Purpose Address Registries when those registries change.
var deniedTargetPrefixes = mustPrefixes(
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

type configuredTarget struct {
	hostname string
	ip       netip.Addr
	family   Family
	port     uint16
	network  string
	endpoint string
}

func normalizeRequest(request Request) (Input, configuredTarget, error) {
	scheme, port, schemeErr := normalizeScheme(request.Scheme)
	hostname, hostnameErr := normalizeHostname(request.Hostname)
	ipText, ip, family, ipErr := normalizePublicIP(request.DialIP)

	input := Input{
		Scheme:   scheme,
		Hostname: hostname,
		DialIP:   ipText,
		Family:   family,
		Port:     port,
		Method:   httpMethod,
		Path:     httpPath,
	}

	if schemeErr != nil {
		return input, configuredTarget{}, schemeErr
	}
	if hostnameErr != nil {
		return input, configuredTarget{}, hostnameErr
	}
	if ipErr != nil {
		return input, configuredTarget{}, ipErr
	}

	network := "tcp6"
	if family == FamilyIPv4 {
		network = "tcp4"
	}
	target := configuredTarget{
		hostname: hostname,
		ip:       ip,
		family:   family,
		port:     port,
		network:  network,
		endpoint: netip.AddrPortFrom(ip, port).String(),
	}
	return input, target, nil
}

func normalizeScheme(value Scheme) (Scheme, uint16, error) {
	scheme := Scheme(strings.ToLower(strings.TrimSpace(string(value))))
	switch scheme {
	case SchemeHTTP:
		return scheme, httpPort, nil
	case SchemeHTTPS:
		return scheme, httpsPort, nil
	default:
		return scheme, 0, fmt.Errorf("unsupported Web scheme %q", scheme)
	}
}

func normalizeHostname(value string) (string, error) {
	hostname := strings.ToLower(strings.TrimSpace(value))
	hostname = strings.TrimSuffix(hostname, ".")
	if hostname == "" {
		return hostname, errors.New("hostname must not be empty")
	}
	if len(hostname) > 253 {
		return hostname, errors.New("hostname exceeds 253 bytes")
	}
	if !strings.Contains(hostname, ".") {
		return hostname, errors.New("hostname must not be a single-label local name")
	}
	if _, err := netip.ParseAddr(hostname); err == nil {
		return hostname, errors.New("IP literals are not Web observation hostnames")
	}
	if strings.ContainsAny(hostname, "/\\:@?#[]*") ||
		strings.IndexFunc(hostname, unicode.IsSpace) >= 0 {
		return hostname, errors.New("hostname must not include a scheme, port, path, or whitespace")
	}

	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 {
			return hostname, errors.New("hostname labels must contain 1 to 63 bytes")
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return hostname, errors.New("hostname labels must not begin or end with a hyphen")
		}
		for _, r := range label {
			if r > unicode.MaxASCII ||
				!((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-') {
				return hostname, errors.New("hostname must be normalized ASCII letters, digits, dots, and hyphens")
			}
		}
	}
	return hostname, nil
}

func normalizePublicIP(value string) (string, netip.Addr, Family, error) {
	text := strings.TrimSpace(value)
	ip, err := netip.ParseAddr(text)
	if err != nil {
		return text, netip.Addr{}, "", fmt.Errorf("dial_ip must be one IP literal: %w", err)
	}
	if ip.Zone() != "" {
		return ip.String(), netip.Addr{}, "", errors.New("dial_ip must not include an IPv6 zone")
	}
	ip = ip.Unmap()
	text = ip.String()

	family := FamilyIPv6
	if ip.Is4() {
		family = FamilyIPv4
	}
	if !isPublicTarget(ip) {
		return text, ip, family, fmt.Errorf("dial_ip %q is not an allowed public address", text)
	}
	return text, ip, family, nil
}

func isPublicTarget(ip netip.Addr) bool {
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
	for _, prefix := range deniedTargetPrefixes {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func logicalEndpoint(target configuredTarget) string {
	return net.JoinHostPort(target.hostname, strconv.Itoa(int(target.port)))
}

func mustPrefixes(values ...string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefixes = append(prefixes, netip.MustParsePrefix(value))
	}
	return prefixes
}
