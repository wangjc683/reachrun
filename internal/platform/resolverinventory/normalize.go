package resolverinventory

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

const defaultDNSPort uint16 = 53

func normalizeEvidence(evidence Evidence) (Evidence, error) {
	result := Evidence{Groups: make([]Group, 0, len(evidence.Groups))}
	seenGroups := make(map[string]struct{}, len(evidence.Groups))

	for index, group := range evidence.Groups {
		normalized, err := normalizeGroup(group)
		if err != nil {
			return Evidence{}, fmt.Errorf("resolver group %d: %w", index, err)
		}
		if len(normalized.Servers) == 0 {
			continue
		}

		key := groupKey(normalized)
		if _, exists := seenGroups[key]; exists {
			continue
		}
		seenGroups[key] = struct{}{}
		result.Groups = append(result.Groups, normalized)
	}

	if len(result.Groups) == 0 {
		return Evidence{}, fmt.Errorf("resolver inventory contains no configured servers")
	}
	return result, nil
}

func normalizeGroup(group Group) (Group, error) {
	if group.Scope == "" {
		group.Scope = ScopeGlobal
	}
	if group.Scope != ScopeGlobal && group.Scope != ScopeScoped {
		return Group{}, fmt.Errorf("unsupported scope %q", group.Scope)
	}

	group.Interface = strings.TrimSpace(group.Interface)
	servers := make([]Server, 0, len(group.Servers))
	seenServers := make(map[Server]struct{}, len(group.Servers))
	for index, server := range group.Servers {
		normalized, err := normalizeServer(server)
		if err != nil {
			return Group{}, fmt.Errorf("server %d: %w", index, err)
		}
		if _, exists := seenServers[normalized]; exists {
			continue
		}
		seenServers[normalized] = struct{}{}
		servers = append(servers, normalized)
	}
	group.Servers = servers

	var err error
	group.SearchDomains, err = normalizeDomains(group.SearchDomains)
	if err != nil {
		return Group{}, fmt.Errorf("search domains: %w", err)
	}
	group.MatchDomains, err = normalizeDomains(group.MatchDomains)
	if err != nil {
		return Group{}, fmt.Errorf("match domains: %w", err)
	}
	return group, nil
}

func normalizeServer(server Server) (Server, error) {
	value := strings.TrimSpace(server.Address)
	address, err := netip.ParseAddr(value)
	if err != nil {
		return Server{}, fmt.Errorf("invalid address %q: %w", value, err)
	}
	addressZone := address.Zone()
	server.Zone = strings.TrimSpace(server.Zone)
	if addressZone != "" && server.Zone != "" && addressZone != server.Zone {
		return Server{}, fmt.Errorf(
			"address zone %q conflicts with explicit zone %q",
			addressZone,
			server.Zone,
		)
	}
	if server.Zone == "" {
		server.Zone = addressZone
	}
	if addressZone != "" {
		address = address.WithZone("")
	}
	address = address.Unmap()
	if server.Zone != "" && (!address.Is6() || strings.IndexFunc(server.Zone, unicode.IsSpace) >= 0) {
		return Server{}, fmt.Errorf("invalid zone %q for address %q", server.Zone, value)
	}
	if address.IsUnspecified() {
		return Server{}, fmt.Errorf("unspecified address %q is not a resolver endpoint", value)
	}
	if server.Port == 0 {
		server.Port = defaultDNSPort
	}
	server.Address = address.String()
	return server, nil
}

func parseCanonicalAddress(value string) (netip.Addr, error) {
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid canonical resolver address %q: %w", value, err)
	}
	return address, nil
}

func normalizeDomains(domains []string) ([]string, error) {
	if len(domains) == 0 {
		return nil, nil
	}

	result := make([]string, 0, len(domains))
	seen := make(map[string]struct{}, len(domains))
	for index, domain := range domains {
		normalized, err := normalizeDomain(domain)
		if err != nil {
			return nil, fmt.Errorf("domain %d: %w", index, err)
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	return result, nil
}

func normalizeDomain(domain string) (string, error) {
	domain = strings.TrimSpace(domain)
	if domain == "." {
		return domain, nil
	}
	domain = strings.TrimSuffix(domain, ".")
	domain = strings.ToLower(domain)
	if domain == "" || strings.HasPrefix(domain, ".") || strings.Contains(domain, "..") {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	if strings.ContainsAny(domain, "/\\:@?#[]*") || strings.IndexFunc(domain, unicode.IsSpace) >= 0 {
		return "", fmt.Errorf("invalid domain %q", domain)
	}
	return domain, nil
}

func groupKey(group Group) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "%s\x00%s\x00%d", group.Scope, group.Interface, group.InterfaceIndex)
	for _, server := range group.Servers {
		fmt.Fprintf(&builder, "\x00%s:%d%%%s", server.Address, server.Port, server.Zone)
	}
	for _, domain := range group.SearchDomains {
		builder.WriteString("\x00s:")
		builder.WriteString(domain)
	}
	for _, domain := range group.MatchDomains {
		builder.WriteString("\x00m:")
		builder.WriteString(domain)
	}
	return builder.String()
}
