package webpath

import (
	"net/url"
	"strings"
	"testing"

	"github.com/wangjc683/reachrun/internal/nettarget"
	"github.com/wangjc683/reachrun/internal/webobservation"
)

func TestRedirectTargetResolvesRelativeLocationsAndCanonicalizesIdentity(t *testing.T) {
	t.Parallel()

	current := &url.URL{Scheme: "https", Host: "example.com", Path: "/old/page"}
	next, reason, err := redirectTarget(current, webobservation.HTTPObservation{
		StatusCode: 302,
		Location:   "../new/%2Fpath?query=value#fragment",
	})
	if err != nil {
		t.Fatalf("redirectTarget() error = %v (%q)", err, reason)
	}
	if got, want := next.String(), "https://example.com/new/%2Fpath?query=value"; got != want {
		t.Fatalf("next URL = %q, want %q", got, want)
	}
}

func TestRedirectTargetRejectsUnusableLocations(t *testing.T) {
	t.Parallel()

	current := &url.URL{Scheme: "https", Host: "example.com", Path: "/"}
	tests := map[string]struct {
		location string
		omitted  bool
		reason   StopReason
	}{
		"missing":        {reason: StopRedirectLocationUnavailable},
		"omitted":        {omitted: true, reason: StopRedirectLocationUnavailable},
		"IP hostname":    {location: "https://127.0.0.1/", reason: StopRedirectTargetInvalid},
		"single label":   {location: "https://localhost/", reason: StopRedirectTargetInvalid},
		"credentials":    {location: "https://user:secret@next.example/", reason: StopRedirectTargetUnsafe},
		"custom port":    {location: "https://next.example:8443/", reason: StopRedirectTargetUnsafe},
		"other scheme":   {location: "file:///etc/passwd", reason: StopRedirectTargetUnsafe},
		"invalid query":  {location: "https://next.example/?query=has space", reason: StopRedirectTargetInvalid},
		"oversized path": {location: "https://next.example/" + strings.Repeat("x", nettarget.MaxWebRequestTargetBytes), reason: StopRedirectTargetInvalid},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, reason, err := redirectTarget(current, webobservation.HTTPObservation{
				StatusCode:      302,
				Location:        test.location,
				LocationOmitted: test.omitted,
			})
			if err == nil || reason != test.reason {
				t.Fatalf("redirectTarget() = reason %q, error %v; want %q", reason, err, test.reason)
			}
		})
	}
}
