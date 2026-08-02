package webobservation

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"github.com/wangjc683/reachrun/internal/nettarget"
)

const (
	httpPort   = 80
	httpsPort  = 443
	httpMethod = "GET"
	httpPath   = "/"
)

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
	text, ip, err := nettarget.NormalizePublicIP(value)
	family := Family("")
	if ip.IsValid() {
		family = FamilyIPv6
		if ip.Is4() {
			family = FamilyIPv4
		}
	}
	return text, ip, family, err
}

func logicalEndpoint(target configuredTarget) string {
	return net.JoinHostPort(target.hostname, strconv.Itoa(int(target.port)))
}
