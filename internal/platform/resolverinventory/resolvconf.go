package resolverinventory

import (
	"bufio"
	"fmt"
	"strings"
)

func parseResolvConf(contents string) (Evidence, bool, error) {
	scanner := bufio.NewScanner(strings.NewReader(contents))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	group := Group{Scope: ScopeGlobal, Servers: make([]Server, 0)}
	searchDomains := make([]string, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "nameserver":
			if len(fields) < 2 {
				return Evidence{}, false, fmt.Errorf("nameserver directive has no address")
			}
			group.Servers = append(group.Servers, Server{Address: fields[1], Port: defaultDNSPort})
		case "search":
			searchDomains = append(searchDomains[:0], fields[1:]...)
		case "domain":
			if len(fields) < 2 {
				return Evidence{}, false, fmt.Errorf("domain directive has no value")
			}
			searchDomains = append(searchDomains[:0], fields[1])
		}
	}
	if err := scanner.Err(); err != nil {
		return Evidence{}, false, fmt.Errorf("scan resolv.conf: %w", err)
	}
	group.SearchDomains = searchDomains

	evidence, err := normalizeEvidence(Evidence{Groups: []Group{group}})
	if err != nil {
		return Evidence{}, false, err
	}
	stub := false
	for _, server := range evidence.Groups[0].Servers {
		address, parseErr := parseCanonicalAddress(server.Address)
		if parseErr != nil {
			return Evidence{}, false, parseErr
		}
		if address.IsLoopback() || address.IsLinkLocalUnicast() {
			stub = true
		}
	}
	return evidence, stub, nil
}
