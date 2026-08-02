package sshobservation

import (
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
		"UTF-8 comments": {
			line:     "SSH-2.0-server_1 东京节点\r\n",
			protocol: "2.0",
			software: "server_1",
			comments: "东京节点",
		},
		"maximum LF length": {
			line:     "SSH-2.0-" + strings.Repeat("x", maxIdentificationBytes-len("SSH-2.0-")-1) + "\n",
			protocol: "2.0",
			software: strings.Repeat("x", maxIdentificationBytes-len("SSH-2.0-")-1),
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
		"missing newline":     "SSH-2.0-OpenSSH_9.9",
		"too long":            "SSH-2.0-" + strings.Repeat("x", maxIdentificationBytes) + "\n",
		"wrong prefix":        "HTTP/1.1 200 OK\r\n",
		"missing software":    "SSH-2.0-\r\n",
		"malformed protocol":  "SSH-two-OpenSSH_9.9\r\n",
		"hyphen in software":  "SSH-2.0-bad-software\r\n",
		"empty comments":      "SSH-2.0-server \r\n",
		"control in comments": "SSH-2.0-server bad\tcomment\r\n",
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
