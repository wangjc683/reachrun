package sshobservation

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

const (
	maxIdentificationBytes = 255
	maxPreambleLines       = 16
	maxPreambleBytes       = 4 << 10
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
		line, readErr := readServerLine(conn, maxPreambleBytes-preambleBytes)
		startsSSH := bytes.HasPrefix(line, []byte("SSH-"))
		if readErr != nil {
			if errors.Is(readErr, errLineLimit) {
				if startsSSH {
					return parsedIdentification{
						preambleLines:  preambleLines,
						clientLineSent: clientSent,
					}, fmt.Errorf("%w: version line exceeded %d bytes", errInvalidIdentification, maxIdentificationBytes)
				}
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

func readServerLine(reader io.Reader, preambleRemaining int) ([]byte, error) {
	sshPrefix := []byte("SSH-")
	line := make([]byte, 0, min(max(preambleRemaining, len(sshPrefix)), maxIdentificationBytes))
	var one [1]byte
	for {
		n, err := reader.Read(one[:])
		if n > 0 {
			line = append(line, one[0])

			startsSSH := len(line) >= len(sshPrefix) && bytes.HasPrefix(line, sshPrefix)
			couldStartSSH := len(line) < len(sshPrefix) && bytes.HasPrefix(sshPrefix, line)
			if startsSSH {
				if one[0] == '\n' {
					return line, nil
				}
				if len(line) >= maxIdentificationBytes {
					return line, errLineLimit
				}
			} else if !couldStartSSH {
				if len(line) > preambleRemaining {
					return line, errLineLimit
				}
				if one[0] == '\n' {
					return line, nil
				}
				if len(line) >= preambleRemaining {
					return line, errLineLimit
				}
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
	hadCarriageReturn := len(content) > 0 && content[len(content)-1] == '\r'
	if hadCarriageReturn {
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
		return parsedIdentification{}, fmt.Errorf("%w: unsupported protocol version", errInvalidIdentification)
	}
	if protocolVersion == "2.0" && !hadCarriageReturn {
		return parsedIdentification{}, fmt.Errorf("%w: SSH 2.0 requires CRLF termination", errInvalidIdentification)
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
	return value == "2.0" || value == "1.99"
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
	for i := 0; i < len(value); i++ {
		if value[i] < 32 || value[i] > 126 {
			return false
		}
	}
	return true
}
