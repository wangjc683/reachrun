package nettarget

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// MaxWebRequestTargetBytes bounds the canonical path plus optional query.
const MaxWebRequestTargetBytes = 4 << 10

// WebRequestTarget is the canonical origin-form path and query that a bounded
// Web observation may send. Path and RawPath are kept separately so escaped
// path identity survives net/url rendering.
type WebRequestTarget struct {
	EscapedPath string
	Path        string
	RawPath     string
	RawQuery    string
}

// NormalizeWebRequestTarget applies the single request-target policy shared
// by direct Web observations and redirect orchestration.
func NormalizeWebRequestTarget(path, rawQuery string) (WebRequestTarget, error) {
	if path == "" {
		path = "/"
	}
	result := WebRequestTarget{EscapedPath: path, RawQuery: rawQuery}
	if err := validateRawQuery(rawQuery); err != nil {
		return result, err
	}
	requestTarget := path
	if rawQuery != "" {
		requestTarget += "?" + rawQuery
	}
	if len(requestTarget) > MaxWebRequestTargetBytes {
		return result, fmt.Errorf("request target exceeds %d bytes", MaxWebRequestTargetBytes)
	}
	parsed, err := url.ParseRequestURI(requestTarget)
	if err != nil {
		return result, fmt.Errorf("invalid request target: %w", err)
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.Opaque != "" || parsed.Fragment != "" ||
		!strings.HasPrefix(path, "/") || parsed.RawQuery != rawQuery {
		return result, errors.New("request target must be an origin-form path with a separate query")
	}
	escapedPath := parsed.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	canonicalBytes := len(escapedPath)
	if parsed.RawQuery != "" {
		canonicalBytes += 1 + len(parsed.RawQuery)
	}
	if canonicalBytes > MaxWebRequestTargetBytes {
		return result, fmt.Errorf("normalized request target exceeds %d bytes", MaxWebRequestTargetBytes)
	}
	result.EscapedPath = escapedPath
	result.Path = parsed.Path
	result.RawPath = parsed.RawPath
	result.RawQuery = parsed.RawQuery
	return result, nil
}

func validateRawQuery(value string) error {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '%' {
			if index+2 >= len(value) || !isHex(value[index+1]) || !isHex(value[index+2]) {
				return errors.New("raw query contains invalid percent-encoding")
			}
			index += 2
			continue
		}
		if isAlphaNumeric(character) || strings.ContainsRune("-._~!$&'()*+,;=:@/?", rune(character)) {
			continue
		}
		return fmt.Errorf("raw query contains unsafe unescaped byte 0x%02x", character)
	}
	return nil
}

func isAlphaNumeric(value byte) bool {
	return (value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z') ||
		(value >= '0' && value <= '9')
}

func isHex(value byte) bool {
	return (value >= 'a' && value <= 'f') ||
		(value >= 'A' && value <= 'F') ||
		(value >= '0' && value <= '9')
}
