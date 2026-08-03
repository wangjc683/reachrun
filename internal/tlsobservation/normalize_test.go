package tlsobservation

import "testing"

const (
	testPublicIPv4 = "93.184.216.34"
	testPublicIPv6 = "2606:4700:4700::1111"
)

func TestNormalizeRequestDerivesFixedPolicyAndAddressFamily(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		dialIP       string
		wantInput    Input
		wantNetwork  string
		wantEndpoint string
	}{
		"IPv4 mapped": {
			dialIP: "::ffff:" + testPublicIPv4,
			wantInput: Input{
				DialIP:               testPublicIPv4,
				Family:               FamilyIPv4,
				Port:                 Port,
				SNIMode:              SNIOmittedNoHostname,
				IdentityVerification: IdentityNotPerformedNoHostname,
			},
			wantNetwork:  "tcp4",
			wantEndpoint: testPublicIPv4 + ":443",
		},
		"IPv6": {
			dialIP: testPublicIPv6,
			wantInput: Input{
				DialIP:               testPublicIPv6,
				Family:               FamilyIPv6,
				Port:                 Port,
				SNIMode:              SNIOmittedNoHostname,
				IdentityVerification: IdentityNotPerformedNoHostname,
			},
			wantNetwork:  "tcp6",
			wantEndpoint: "[" + testPublicIPv6 + "]:443",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input, target, err := normalizeRequest(Request{DialIP: test.dialIP})
			if err != nil {
				t.Fatalf("normalizeRequest() error = %v", err)
			}
			if input != test.wantInput || target.network != test.wantNetwork || target.endpoint != test.wantEndpoint {
				t.Fatalf("normalizeRequest() = %#v/%#v, want %#v and %s/%s", input, target, test.wantInput, test.wantNetwork, test.wantEndpoint)
			}
		})
	}
}

func TestNormalizeRequestRejectsNonPublicTargetAndKeepsFixedPolicy(t *testing.T) {
	t.Parallel()

	input, _, err := normalizeRequest(Request{DialIP: "127.0.0.1"})
	if err == nil {
		t.Fatalf("normalizeRequest() error = nil; input = %#v", input)
	}
	if input.Port != Port || input.SNIMode != SNIOmittedNoHostname ||
		input.IdentityVerification != IdentityNotPerformedNoHostname {
		t.Fatalf("invalid input lost fixed policy fields: %#v", input)
	}
}

func TestNewValidatesTimeout(t *testing.T) {
	t.Parallel()

	created, err := New(Config{})
	if err != nil {
		t.Fatalf("New(default) error = %v", err)
	}
	if got := created.(*observer).timeout; got != defaultTimeout {
		t.Fatalf("default timeout = %s, want %s", got, defaultTimeout)
	}
	if _, err := New(Config{Timeout: -1}); err == nil {
		t.Fatal("New(negative timeout) error = nil")
	}
	if _, err := New(Config{Timeout: maximumTimeout + 1}); err == nil {
		t.Fatal("New(too-large timeout) error = nil")
	}
}
