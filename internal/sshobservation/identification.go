package sshobservation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maxIdentificationBytes = 255
	maxPreambleLines       = 16
	maxPreambleBytes       = 4 << 10
	maxObservedLineBytes   = maxPreambleBytes + 1
)

var (
	errInvalidIdentification = errors.New("invalid SSH identification")
	errPreambleLimit         = errors.New("SSH preamble limit exceeded")
	errLineLimit             = errors.New("SSH line limit exceeded")
)

type parsedIdentification struct {
	raw             string
	protocolVersion string
	softwareVersion string
	comments        string
	preambleLines   int
	clientLineSent  bool
}

func exchangeIdentification(conn net.Conn) (parsedIdentification, error) {
	clientLine := []byte(ClientIdentification + "\r\n")
	written, err := writeAll(conn, clientLine)
	clientSent := written == len(clientLine)
	if err != nil {
		return parsedIdentification{clientLineSent: clientSent}, err
	}

	preambleLines := 0
	preambleBytes := 0
	for {
		line, readErr := readBoundedLine(conn, maxObservedLineBytes)
		startsSSH := bytes.HasPrefix(line, []byte("SSH-"))
		if readErr != nil {
			if startsSSH {
				return parsedIdentification{
					preambleLines:  preambleLines,
					clientLineSent: clientSent,
				}, fmt.Errorf("%w: version line was not bounded and terminated: %v", errInvalidIdentification, readErr)
			}
			if errors.Is(readErr, errLineLimit) {
				return parsedIdentification{
					preambleLines:  preambleLines,
					clientLineSent: clientSent,
				}, errPreambleLimit
			}
			return parsedIdentification{
				preambleLines:  preambleLines,
				clientLineSent: clientSent,
			}, readErr
		}

		if startsSSH {
			parsed, err := parseIdentificationLine(line)
			parsed.preambleLines = preambleLines
			parsed.clientLineSent = clientSent
			return parsed, err
		}

		if preambleLines >= maxPreambleLines || preambleBytes+len(line) > maxPreambleBytes {
			return parsedIdentification{
				preambleLines:  preambleLines,
				clientLineSent: clientSent,
			}, errPreambleLimit
		}
		preambleLines++
		preambleBytes += len(line)
	}
}

func writeAll(writer io.Writer, data []byte) (int, error) {
	written := 0
	for written < len(data) {
		n, err := writer.Write(data[written:])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

func readBoundedLine(reader io.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, min(limit, maxIdentificationBytes))
	var one [1]byte
	for {
		n, err := reader.Read(one[:])
		if n > 0 {
			line = append(line, one[0])
			if len(line) > limit {
				return line, errLineLimit
			}
			if one[0] == '\n' {
				return line, nil
			}
		}
		if err != nil {
			return line, err
		}
		if n == 0 {
			return line, io.ErrNoProgress
		}
	}
}

func parseIdentificationLine(line []byte) (parsedIdentification, error) {
	if len(line) == 0 || line[len(line)-1] != '\n' {
		return parsedIdentification{}, fmt.Errorf("%w: line is not LF terminated", errInvalidIdentification)
	}
	if len(line) > maxIdentificationBytes {
		return parsedIdentification{}, fmt.Errorf("%w: line exceeds %d bytes", errInvalidIdentification, maxIdentificationBytes)
	}

	content := line[:len(line)-1]
	if len(content) > 0 && content[len(content)-1] == '\r' {
		content = content[:len(content)-1]
	}
	if !bytes.HasPrefix(content, []byte("SSH-")) {
		return parsedIdentification{}, fmt.Errorf("%w: line does not begin with SSH-", errInvalidIdentification)
	}

	rest := string(content[len("SSH-"):])
	separator := strings.IndexByte(rest, '-')
	if separator <= 0 || separator == len(rest)-1 {
		return parsedIdentification{}, fmt.Errorf("%w: missing protocol or software version", errInvalidIdentification)
	}
	protocolVersion := rest[:separator]
	softwareAndComments := rest[separator+1:]
	softwareVersion := softwareAndComments
	comments := ""
	if space := strings.IndexByte(softwareAndComments, ' '); space >= 0 {
		softwareVersion = softwareAndComments[:space]
		comments = softwareAndComments[space+1:]
		if comments == "" {
			return parsedIdentification{}, fmt.Errorf("%w: empty comments after separator", errInvalidIdentification)
		}
	}

	if !validProtocolVersion(protocolVersion) {
		return parsedIdentification{}, fmt.Errorf("%w: malformed protocol version", errInvalidIdentification)
	}
	if !validVersionField(softwareVersion) {
		return parsedIdentification{}, fmt.Errorf("%w: malformed software version", errInvalidIdentification)
	}
	if comments != "" && !validComments(comments) {
		return parsedIdentification{}, fmt.Errorf("%w: malformed comments", errInvalidIdentification)
	}

	return parsedIdentification{
		raw:             string(content),
		protocolVersion: protocolVersion,
		softwareVersion: softwareVersion,
		comments:        comments,
	}, nil
}

func validProtocolVersion(value string) bool {
	if !validVersionField(value) || strings.Count(value, ".") != 1 {
		return false
	}
	major, minor, found := strings.Cut(value, ".")
	return found && allDigits(major) && allDigits(minor)
}

func validVersionField(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 33 || value[i] > 126 || value[i] == '-' {
			return false
		}
	}
	return true
}

func validComments(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}
