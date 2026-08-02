package sshobservation

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseIdentificationLineAcceptsBoundedSSHFormats(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		line     string
		protocol string
		software string
		comments string
	}{
		"SSH 2 CRLF": {
			line:     "SSH-2.0-OpenSSH_9.9\r\n",
			protocol: "2.0",
			software: "OpenSSH_9.9",
		},
		"legacy compatibility LF": {
			line:     "SSH-1.99-legacy_1.0\n",
			protocol: "1.99",
			software: "legacy_1.0",
		},
		"printable ASCII comments": {
			line:     "SSH-2.0-server_1 edge-node\r\n",
			protocol: "2.0",
			software: "server_1",
			comments: "edge-node",
		},
		"maximum CRLF length": {
			line:     "SSH-2.0-" + strings.Repeat("x", maxIdentificationBytes-len("SSH-2.0-")-2) + "\r\n",
			protocol: "2.0",
			software: strings.Repeat("x", maxIdentificationBytes-len("SSH-2.0-")-2),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			parsed, err := parseIdentificationLine([]byte(test.line))
			if err != nil {
				t.Fatalf("parseIdentificationLine() error = %v", err)
			}
			if parsed.protocolVersion != test.protocol ||
				parsed.softwareVersion != test.software ||
				parsed.comments != test.comments {
				t.Fatalf("parsed = %#v, want protocol/software/comments %q/%q/%q", parsed, test.protocol, test.software, test.comments)
			}
		})
	}
}

func TestParseIdentificationLineRejectsMalformedOrUnboundedLines(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing newline":              "SSH-2.0-OpenSSH_9.9",
		"SSH 2 LF only":                "SSH-2.0-OpenSSH_9.9\n",
		"too long":                     "SSH-2.0-" + strings.Repeat("x", maxIdentificationBytes) + "\r\n",
		"wrong prefix":                 "HTTP/1.1 200 OK\r\n",
		"missing software":             "SSH-2.0-\r\n",
		"malformed protocol":           "SSH-two-OpenSSH_9.9\r\n",
		"unsupported numeric protocol": "SSH-9.9-server\r\n",
		"hyphen in software":           "SSH-2.0-bad-software\r\n",
		"empty comments":               "SSH-2.0-server \r\n",
		"control in comments":          "SSH-2.0-server bad\tcomment\r\n",
		"non-ASCII bytes in comments":  "SSH-2.0-server 东京\r\n",
	}

	for name, line := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseIdentificationLine([]byte(line)); !errors.Is(err, errInvalidIdentification) {
				t.Fatalf("parseIdentificationLine() error = %v, want invalid identification", err)
			}
		})
	}
}

func TestReadServerLineStopsAtSSHIdentificationLimit(t *testing.T) {
	t.Parallel()

	payload := []byte("SSH-" + strings.Repeat("x", maxIdentificationBytes) + "\r\nKEX")
	reader := bytes.NewReader(payload)
	line, err := readServerLine(reader, maxPreambleBytes)
	if !errors.Is(err, errLineLimit) {
		t.Fatalf("readServerLine() error = %v, want line limit", err)
	}
	if len(line) != maxIdentificationBytes {
		t.Fatalf("read bytes = %d, want exactly %d", len(line), maxIdentificationBytes)
	}
	if got, want := reader.Len(), len(payload)-maxIdentificationBytes; got != want {
		t.Fatalf("remaining bytes = %d, want %d; reader consumed beyond the limit", got, want)
	}
}

func TestReadServerLineAllowsSSHAtExactPreambleByteBoundary(t *testing.T) {
	t.Parallel()

	want := "SSH-2.0-server\r\n"
	line, err := readServerLine(strings.NewReader(want), 0)
	if err != nil {
		t.Fatalf("readServerLine() error = %v", err)
	}
	if string(line) != want {
		t.Fatalf("line = %q, want %q", line, want)
	}
}
