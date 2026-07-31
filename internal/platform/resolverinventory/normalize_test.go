package resolverinventory

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNormalizeEvidencePreservesOrderAndDeduplicates(t *testing.T) {
	t.Parallel()

	evidence, err := normalizeEvidence(Evidence{Groups: []Group{
		{
			Scope: ScopeGlobal,
			Servers: []Server{
				{Address: "::ffff:192.0.2.1"},
				{Address: "192.0.2.1", Port: 53},
				{Address: "2001:db8::1", Port: 5353},
			},
			Interface:      " en0 ",
			InterfaceIndex: 4,
			SearchDomains:  []string{"Example.COM.", "example.com"},
			MatchDomains:   []string{"Corp.Example.", "corp.example"},
		},
	}})
	if err != nil {
		t.Fatalf("normalizeEvidence() error = %v", err)
	}

	want := Evidence{Groups: []Group{
		{
			Scope: ScopeGlobal,
			Servers: []Server{
				{Address: "192.0.2.1", Port: 53},
				{Address: "2001:db8::1", Port: 5353},
			},
			Interface:      "en0",
			InterfaceIndex: 4,
			SearchDomains:  []string{"example.com"},
			MatchDomains:   []string{"corp.example"},
		},
	}}
	if !reflect.DeepEqual(evidence, want) {
		t.Fatalf("evidence = %#v, want %#v", evidence, want)
	}
}

func TestNormalizeEvidenceRejectsEmptyOrInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := map[string]Evidence{
		"empty": {},
		"empty group": {
			Groups: []Group{{Scope: ScopeGlobal}},
		},
		"invalid address": {
			Groups: []Group{{Servers: []Server{{Address: "not-an-ip"}}}},
		},
		"unspecified address": {
			Groups: []Group{{Servers: []Server{{Address: "0.0.0.0"}}}},
		},
		"invalid domain": {
			Groups: []Group{{
				Servers:       []Server{{Address: "192.0.2.1"}},
				SearchDomains: []string{"bad domain"},
			}},
		},
		"conflicting zones": {
			Groups: []Group{{
				Servers: []Server{{Address: "fe80::53%en0", Zone: "en1"}},
			}},
		},
		"ipv4 zone": {
			Groups: []Group{{
				Servers: []Server{{Address: "192.0.2.53", Zone: "en0"}},
			}},
		},
	}

	for name, evidence := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := normalizeEvidence(evidence); err == nil {
				t.Fatal("normalizeEvidence() error = nil, want invalid configuration error")
			}
		})
	}
}

func TestNormalizeEvidenceKeepsInterfaceForLinkLocalServer(t *testing.T) {
	t.Parallel()

	evidence, err := normalizeEvidence(Evidence{Groups: []Group{{
		Scope:          ScopeScoped,
		Servers:        []Server{{Address: "fe80::53%12", Port: 53}},
		Interface:      "Ethernet",
		InterfaceIndex: 12,
	}}})
	if err != nil {
		t.Fatalf("normalizeEvidence() error = %v", err)
	}
	group := evidence.Groups[0]
	if group.Servers[0].Address != "fe80::53" {
		t.Fatalf("address = %q, want canonical address without zone", group.Servers[0].Address)
	}
	if group.Servers[0].Zone != "12" {
		t.Fatalf("zone = %q, want 12", group.Servers[0].Zone)
	}
	if group.Interface != "Ethernet" || group.InterfaceIndex != 12 {
		t.Fatalf("interface = %q/%d, want Ethernet/12", group.Interface, group.InterfaceIndex)
	}
}

func TestServerZoneJSONContract(t *testing.T) {
	t.Parallel()

	encoded, err := json.Marshal(Server{Address: "fe80::53", Port: 53, Zone: "en0"})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if got, want := string(encoded), `{"address":"fe80::53","port":53,"zone":"en0"}`; got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}
