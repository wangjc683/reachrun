package resolverinventory

import (
	"reflect"
	"testing"
)

func TestParseScutilDNSPreservesGlobalAndScopedGroups(t *testing.T) {
	t.Parallel()

	const fixture = `DNS configuration

resolver #1
  search domain[0] : Example.COM.
  nameserver[0] : 192.0.2.1
  nameserver[1] : 192.0.2.1
  if_index : 14 (en0)

resolver #2
  domain   : Corp.Example.
  nameserver[0] : 2001:db8::53
  port     : 5353

resolver #3
  domain   : local
  options  : mdns

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 192.0.2.1
  if_index : 14 (en0)
`

	got, err := parseScutilDNS(fixture)
	if err != nil {
		t.Fatalf("parseScutilDNS() error = %v", err)
	}
	want := Evidence{Groups: []Group{
		{
			Scope:          ScopeGlobal,
			Servers:        []Server{{Address: "192.0.2.1", Port: 53}},
			Interface:      "en0",
			InterfaceIndex: 14,
			SearchDomains:  []string{"example.com"},
		},
		{
			Scope:        ScopeGlobal,
			Servers:      []Server{{Address: "2001:db8::53", Port: 5353}},
			MatchDomains: []string{"corp.example"},
		},
		{
			Scope:          ScopeScoped,
			Servers:        []Server{{Address: "192.0.2.1", Port: 53}},
			Interface:      "en0",
			InterfaceIndex: 14,
		},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestParseScutilDNSRejectsMalformedOrEmptyConfiguration(t *testing.T) {
	t.Parallel()

	for name, fixture := range map[string]string{
		"empty":          "No DNS configuration available\n",
		"invalid server": "DNS configuration\nresolver #1\n nameserver[0] : invalid\n",
		"invalid port":   "DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.1\n port : zero\n",
		"invalid index":  "DNS configuration\nresolver #1\n nameserver[0] : 192.0.2.1\n if_index : nope\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseScutilDNS(fixture); err == nil {
				t.Fatal("parseScutilDNS() error = nil, want parse error")
			}
		})
	}
}
