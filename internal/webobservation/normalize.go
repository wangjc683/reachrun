package webobservation

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

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
	path     string
	rawPath  string
	rawQuery string
}

func normalizeRequest(request Request) (Input, configuredTarget, error) {
	scheme, port, schemeErr := normalizeScheme(request.Scheme)
	hostname, hostnameErr := normalizeHostname(request.Hostname)
	ipText, ip, family, ipErr := normalizePublicIP(request.DialIP)
	requestTarget, targetErr := nettarget.NormalizeWebRequestTarget(request.Path, request.RawQuery)

	input := Input{
		Scheme:   scheme,
		Hostname: hostname,
		DialIP:   ipText,
		Family:   family,
		Port:     port,
		Method:   httpMethod,
		Path:     requestTarget.EscapedPath,
		RawQuery: requestTarget.RawQuery,
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
	if targetErr != nil {
		return input, configuredTarget{}, targetErr
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
		path:     requestTarget.Path,
		rawPath:  requestTarget.RawPath,
		rawQuery: requestTarget.RawQuery,
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
	return nettarget.NormalizeWebHostname(value)
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
