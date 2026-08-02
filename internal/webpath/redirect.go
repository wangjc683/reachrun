package webpath

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

func isRedirectStatus(status int) bool {
	switch status {
	case http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusSeeOther,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect:
		return true
	default:
		return false
	}
}

func redirectTarget(
	current *url.URL,
	response webobservation.HTTPObservation,
) (*url.URL, StopReason, error) {
	if response.LocationOmitted || response.Location == "" {
		return nil, StopRedirectLocationUnavailable, errors.New("redirect response has no usable Location")
	}
	reference, err := url.Parse(response.Location)
	if err != nil {
		return nil, StopRedirectTargetInvalid, fmt.Errorf("parse redirect Location: %w", err)
	}
	next := current.ResolveReference(reference)
	next.Fragment = ""
	if next.Opaque != "" || next.User != nil {
		return nil, StopRedirectTargetUnsafe, errors.New("redirect target must not use opaque URLs or credentials")
	}

	scheme := strings.ToLower(next.Scheme)
	switch webobservation.Scheme(scheme) {
	case webobservation.SchemeHTTP, webobservation.SchemeHTTPS:
	default:
		return nil, StopRedirectTargetUnsafe, fmt.Errorf("redirect scheme %q is not HTTP(S)", next.Scheme)
	}
	hostname, err := nettarget.NormalizeWebHostname(next.Hostname())
	if err != nil {
		return nil, StopRedirectTargetInvalid, fmt.Errorf("invalid redirect hostname: %w", err)
	}
	if port := next.Port(); port != "" &&
		!((scheme == string(webobservation.SchemeHTTP) && port == "80") ||
			(scheme == string(webobservation.SchemeHTTPS) && port == "443")) {
		return nil, StopRedirectTargetUnsafe, fmt.Errorf("redirect target uses unsupported port %q", port)
	}

	next.Scheme = scheme
	next.Host = hostname
	if next.RawQuery == "" {
		next.ForceQuery = false
	}
	if next.EscapedPath() == "" {
		next.Path = "/"
		next.RawPath = ""
	}
	requestTarget, err := nettarget.NormalizeWebRequestTarget(next.EscapedPath(), next.RawQuery)
	if err != nil {
		return nil, StopRedirectTargetInvalid, fmt.Errorf("invalid redirect request target: %w", err)
	}
	next.Path = requestTarget.Path
	next.RawPath = requestTarget.RawPath
	next.RawQuery = requestTarget.RawQuery
	return next, "", nil
}
