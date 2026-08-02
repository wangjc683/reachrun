package nettarget

import (
	"strings"
	"testing"
)

func TestNormalizeWebRequestTargetPreservesEscapedPathAndQuery(t *testing.T) {
	t.Parallel()

	target, err := NormalizeWebRequestTarget("/redirected/%2Fpath", "source=reachrun")
	if err != nil {
		t.Fatalf("NormalizeWebRequestTarget() error = %v", err)
	}
	if target.EscapedPath != "/redirected/%2Fpath" ||
		target.Path != "/redirected//path" ||
		target.RawPath != "/redirected/%2Fpath" ||
		target.RawQuery != "source=reachrun" {
		t.Fatalf("target = %#v", target)
	}
}

func TestNormalizeWebRequestTargetRejectsNonOriginFormOrMalformedTargets(t *testing.T) {
	t.Parallel()

	for name, target := range map[string]struct {
		path     string
		rawQuery string
	}{
		"absolute URL":      {path: "https://other.example/path"},
		"embedded query":    {path: "/path?query=embedded"},
		"fragment":          {path: "/path", rawQuery: "query=value#fragment"},
		"invalid raw query": {path: "/path", rawQuery: "query=has space"},
		"oversized":         {path: "/" + strings.Repeat("x", MaxWebRequestTargetBytes)},
		"escaped expansion": {path: "/" + strings.Repeat("例", 500)},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NormalizeWebRequestTarget(target.path, target.rawQuery); err == nil {
				t.Fatalf("NormalizeWebRequestTarget(%q, %q) error = nil", target.path, target.rawQuery)
			}
		})
	}
}
