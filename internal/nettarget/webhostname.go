package nettarget

import (
	"errors"
	"net/netip"
	"strings"
	"unicode"
)

// NormalizeWebHostname applies the shared logical-hostname policy used before
// Web resolution and connection. It accepts normalized ASCII DNS names only;
// local single-label names and IP literals are deliberately outside the Web
// asset contract.
func NormalizeWebHostname(value string) (string, error) {
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
		for _, character := range label {
			if character > unicode.MaxASCII ||
				!((character >= 'a' && character <= 'z') ||
					(character >= '0' && character <= '9') || character == '-') {
				return hostname, errors.New("hostname must be normalized ASCII letters, digits, dots, and hyphens")
			}
		}
	}
	return hostname, nil
}
