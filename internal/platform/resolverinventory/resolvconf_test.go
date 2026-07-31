package resolverinventory

import (
	"reflect"
	"testing"
)

func TestParseResolvConfPreservesServersAndLastSearchDirective(t *testing.T) {
	t.Parallel()

	const fixture = `# generated fixture
nameserver 192.0.2.53
nameserver ::ffff:192.0.2.53
nameserver 2001:db8::53
domain ignored.example
search Example.COM. Corp.Example example.com
options ndots:5
`

	got, stub, err := parseResolvConf(fixture)
	if err != nil {
		t.Fatalf("parseResolvConf() error = %v", err)
	}
	if stub {
		t.Fatal("stub = true, want false")
	}
	want := Evidence{Groups: []Group{{
		Scope: ScopeGlobal,
		Servers: []Server{
			{Address: "192.0.2.53", Port: 53},
			{Address: "2001:db8::53", Port: 53},
		},
		SearchDomains: []string{"example.com", "corp.example"},
	}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("evidence = %#v, want %#v", got, want)
	}
}

func TestParseResolvConfDetectsLocalStub(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"127.0.0.53", "::1", "fe80::53"} {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			_, stub, err := parseResolvConf("nameserver " + address + "\n")
			if err != nil {
				t.Fatalf("parseResolvConf() error = %v", err)
			}
			if !stub {
				t.Fatal("stub = false, want true")
			}
		})
	}
}

func TestParseResolvConfPreservesIPv6ResolverZone(t *testing.T) {
	t.Parallel()

	evidence, stub, err := parseResolvConf("nameserver fe80::53%eth0\n")
	if err != nil {
		t.Fatalf("parseResolvConf() error = %v", err)
	}
	if !stub {
		t.Fatal("stub = false, want link-local stub")
	}
	server := evidence.Groups[0].Servers[0]
	if server.Address != "fe80::53" || server.Zone != "eth0" {
		t.Fatalf("server = %#v, want canonical address plus eth0 zone", server)
	}
}

func TestParseResolvConfRejectsMissingOrInvalidServers(t *testing.T) {
	t.Parallel()

	for name, fixture := range map[string]string{
		"no server":       "search example.com\n",
		"missing address": "nameserver\n",
		"invalid address": "nameserver resolver.example\n",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, _, err := parseResolvConf(fixture); err == nil {
				t.Fatal("parseResolvConf() error = nil, want parse error")
			}
		})
	}
}
