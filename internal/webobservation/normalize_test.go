package webobservation

import (
	"strings"
	"testing"

	"github.com/wangjc683/reachrun/internal/nettarget"
)

func TestNormalizeRequestDerivesFixedProtocolFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		request    Request
		wantInput  Input
		wantTarget string
		wantNet    string
	}{
		{
			name: "https ipv4 mapped canonicalized",
			request: Request{
				Scheme:   " HTTPS ",
				Hostname: "WWW.Example.COM.",
				DialIP:   "::ffff:8.8.8.8",
			},
			wantInput: Input{
				Scheme:   SchemeHTTPS,
				Hostname: "www.example.com",
				DialIP:   "8.8.8.8",
				Family:   FamilyIPv4,
				Port:     443,
				Method:   "GET",
				Path:     "/",
			},
			wantTarget: "8.8.8.8:443",
			wantNet:    "tcp4",
		},
		{
			name: "http ipv6",
			request: Request{
				Scheme:   SchemeHTTP,
				Hostname: "edge.example",
				DialIP:   testPublicIPv6,
				Path:     "/redirected/%2Fpath",
				RawQuery: "source=reachrun",
			},
			wantInput: Input{
				Scheme:   SchemeHTTP,
				Hostname: "edge.example",
				DialIP:   testPublicIPv6,
				Family:   FamilyIPv6,
				Port:     80,
				Method:   "GET",
				Path:     "/redirected/%2Fpath",
				RawQuery: "source=reachrun",
			},
			wantTarget: "[" + testPublicIPv6 + "]:80",
			wantNet:    "tcp6",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			input, target, err := normalizeRequest(test.request)
			if err != nil {
				t.Fatalf("normalizeRequest() error = %v", err)
			}
			if input != test.wantInput {
				t.Fatalf("input = %#v, want %#v", input, test.wantInput)
			}
			if target.endpoint != test.wantTarget || target.network != test.wantNet {
				t.Fatalf("target = %#v, want endpoint/network %s/%s", target, test.wantTarget, test.wantNet)
			}
		})
	}
}

func TestNormalizeRequestRejectsUnsafeOrMalformedInput(t *testing.T) {
	t.Parallel()

	tests := map[string]Request{
		"unsupported scheme": {
			Scheme: "ftp", Hostname: "example.com", DialIP: "8.8.8.8",
		},
		"hostname is ip": {
			Scheme: SchemeHTTPS, Hostname: "8.8.8.8", DialIP: "8.8.8.8",
		},
		"single-label local hostname": {
			Scheme: SchemeHTTPS, Hostname: "localhost", DialIP: "8.8.8.8",
		},
		"hostname has path": {
			Scheme: SchemeHTTPS, Hostname: "example.com/path", DialIP: "8.8.8.8",
		},
		"hostname has empty label": {
			Scheme: SchemeHTTPS, Hostname: "example..com", DialIP: "8.8.8.8",
		},
		"hostname unicode": {
			Scheme: SchemeHTTPS, Hostname: "例子.example", DialIP: "8.8.8.8",
		},
		"malformed ip": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "not-an-ip",
		},
		"unspecified": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "0.0.0.0",
		},
		"loopback": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "127.0.0.1",
		},
		"private": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "10.0.0.1",
		},
		"shared": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "100.64.0.1",
		},
		"link local": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "169.254.1.1",
		},
		"documentation ipv4": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "192.0.2.1",
		},
		"benchmark": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "198.18.0.1",
		},
		"multicast": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "224.0.0.1",
		},
		"reserved": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "240.0.0.1",
		},
		"documentation ipv6": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "2001:db8::1",
		},
		"srv6 sid": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "5f00::1",
		},
		"reserved ipv6 unicast": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "4000::1",
		},
		"former 6bone": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "3ffe::1",
		},
		"unique local": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "fd00::1",
		},
		"ipv6 link local zone": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "fe80::1%en0",
		},
		"nat64 well known": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "64:ff9b::808:808",
		},
		"absolute request target": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "8.8.8.8",
			Path: "https://other.example/path",
		},
		"query embedded in path": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "8.8.8.8",
			Path: "/path?query=must-be-separate",
		},
		"fragment in query": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "8.8.8.8",
			Path: "/path", RawQuery: "query=value#fragment",
		},
		"oversized request target": {
			Scheme: SchemeHTTPS, Hostname: "example.com", DialIP: "8.8.8.8",
			Path: "/" + strings.Repeat("x", nettarget.MaxWebRequestTargetBytes),
		},
	}

	for name, request := range tests {
		name, request := name, request
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			input, _, err := normalizeRequest(request)
			if err == nil {
				t.Fatalf("normalizeRequest(%#v) error = nil; input = %#v", request, input)
			}
			if input.Method != httpMethod || input.Path == "" {
				t.Fatalf("invalid input lost derived method/path: %#v", input)
			}
		})
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
