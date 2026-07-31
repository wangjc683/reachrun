package resolverinventory

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

func parseScutilDNS(output string) (Evidence, error) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	scope := ScopeGlobal
	var current *scutilGroup
	groups := make([]Group, 0)
	flush := func() error {
		if current == nil {
			return nil
		}
		group, err := current.group()
		if err != nil {
			return err
		}
		if len(group.Servers) > 0 {
			groups = append(groups, group)
		}
		current = nil
		return nil
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch line {
		case "DNS configuration":
			if err := flush(); err != nil {
				return Evidence{}, err
			}
			scope = ScopeGlobal
			continue
		case "DNS configuration (for scoped queries)":
			if err := flush(); err != nil {
				return Evidence{}, err
			}
			scope = ScopeScoped
			continue
		}

		if strings.HasPrefix(line, "resolver #") {
			if err := flush(); err != nil {
				return Evidence{}, err
			}
			current = &scutilGroup{scope: scope, port: defaultDNSPort}
			continue
		}
		if current == nil || line == "" {
			continue
		}

		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch {
		case strings.HasPrefix(key, "nameserver["):
			if value == "" {
				return Evidence{}, fmt.Errorf("scutil nameserver is empty")
			}
			current.servers = append(current.servers, value)
		case key == "port":
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil || port == 0 {
				return Evidence{}, fmt.Errorf("invalid scutil resolver port %q", value)
			}
			current.port = uint16(port)
		case key == "if_index":
			index, name, err := parseScutilInterface(value)
			if err != nil {
				return Evidence{}, err
			}
			current.interfaceIndex = index
			current.interfaceName = name
		case strings.HasPrefix(key, "search domain["):
			current.searchDomains = append(current.searchDomains, value)
		case key == "domain":
			current.matchDomains = append(current.matchDomains, value)
		}
	}
	if err := scanner.Err(); err != nil {
		return Evidence{}, fmt.Errorf("scan scutil DNS output: %w", err)
	}
	if err := flush(); err != nil {
		return Evidence{}, err
	}
	return normalizeEvidence(Evidence{Groups: groups})
}

type scutilGroup struct {
	scope          Scope
	servers        []string
	port           uint16
	interfaceName  string
	interfaceIndex uint32
	searchDomains  []string
	matchDomains   []string
}

func (g scutilGroup) group() (Group, error) {
	group := Group{
		Scope:          g.scope,
		Servers:        make([]Server, 0, len(g.servers)),
		Interface:      g.interfaceName,
		InterfaceIndex: g.interfaceIndex,
		SearchDomains:  g.searchDomains,
		MatchDomains:   g.matchDomains,
	}
	for _, address := range g.servers {
		group.Servers = append(group.Servers, Server{Address: address, Port: g.port})
	}
	return normalizeGroup(group)
}

func parseScutilInterface(value string) (uint32, string, error) {
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return 0, "", fmt.Errorf("scutil if_index is empty")
	}
	index, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || index == 0 {
		return 0, "", fmt.Errorf("invalid scutil if_index %q", value)
	}

	name := ""
	open := strings.Index(value, "(")
	close := strings.LastIndex(value, ")")
	if open >= 0 || close >= 0 {
		if open < 0 || close <= open+1 || close != len(value)-1 {
			return 0, "", fmt.Errorf("invalid scutil interface %q", value)
		}
		name = strings.TrimSpace(value[open+1 : close])
	}
	return uint32(index), name, nil
}
