package sshobservation

import "testing"

const (
	testPublicIPv4 = "93.184.216.34"
	testPublicIPv6 = "2606:4700:4700::1111"
)

func TestNormalizeRequestDerivesDefaultAndAddressFamily(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		request      Request
		wantInput    Input
		wantNetwork  string
		wantEndpoint string
	}{
		"default IPv4 port": {
			request: Request{DialIP: "::ffff:" + testPublicIPv4},
			wantInput: Input{
				DialIP: testPublicIPv4, Family: FamilyIPv4, Port: DefaultPort,
				ClientIdentification: ClientIdentification,
			},
			wantNetwork:  "tcp4",
			wantEndpoint: testPublicIPv4 + ":22",
		},
		"custom IPv6 port": {
			request: Request{DialIP: testPublicIPv6, Port: 2222},
			wantInput: Input{
				DialIP: testPublicIPv6, Family: FamilyIPv6, Port: 2222,
				ClientIdentification: ClientIdentification,
			},
			wantNetwork:  "tcp6",
			wantEndpoint: "[" + testPublicIPv6 + "]:2222",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input, target, err := normalizeRequest(test.request)
			if err != nil {
				t.Fatalf("normalizeRequest() error = %v", err)
			}
			if input != test.wantInput || target.network != test.wantNetwork || target.endpoint != test.wantEndpoint {
				t.Fatalf("normalizeRequest() = %#v/%#v, want %#v and %s/%s", input, target, test.wantInput, test.wantNetwork, test.wantEndpoint)
			}
		})
	}
}

func TestNormalizeRequestRejectsNonPublicTarget(t *testing.T) {
	t.Parallel()

	input, _, err := normalizeRequest(Request{DialIP: "127.0.0.1"})
	if err == nil {
		t.Fatalf("normalizeRequest() error = nil; input = %#v", input)
	}
	if input.Port != DefaultPort || input.ClientIdentification != ClientIdentification {
		t.Fatalf("invalid input lost fixed fields: %#v", input)
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
