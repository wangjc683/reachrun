package nettarget

import "testing"

func TestNormalizePublicIPCanonicalizesAllowedAddresses(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string
		want  string
	}{
		"IPv4":        {input: " 8.8.8.8 ", want: "8.8.8.8"},
		"mapped IPv4": {input: "::ffff:8.8.8.8", want: "8.8.8.8"},
		"IPv6":        {input: "2606:4700:4700::1111", want: "2606:4700:4700::1111"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			text, address, err := NormalizePublicIP(test.input)
			if err != nil {
				t.Fatalf("NormalizePublicIP() error = %v", err)
			}
			if text != test.want || address.String() != test.want {
				t.Fatalf("NormalizePublicIP() = %q/%q, want %q", text, address, test.want)
			}
		})
	}
}

func TestNormalizePublicIPRejectsUnsafeOrMalformedTargets(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"hostname":              "example.com",
		"unspecified":           "0.0.0.0",
		"loopback":              "127.0.0.1",
		"private":               "10.0.0.1",
		"shared":                "100.64.0.1",
		"link local":            "169.254.1.1",
		"documentation IPv4":    "192.0.2.1",
		"benchmark":             "198.18.0.1",
		"multicast":             "224.0.0.1",
		"reserved":              "240.0.0.1",
		"documentation IPv6":    "2001:db8::1",
		"SRv6 SID":              "5f00::1",
		"reserved IPv6 unicast": "4000::1",
		"former 6bone":          "3ffe::1",
		"unique local":          "fd00::1",
		"IPv6 zone":             "fe80::1%en0",
		"NAT64 well known":      "64:ff9b::808:808",
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if text, address, err := NormalizePublicIP(input); err == nil {
				t.Fatalf("NormalizePublicIP(%q) = %q/%q, nil; want error", input, text, address)
			}
		})
	}
}
