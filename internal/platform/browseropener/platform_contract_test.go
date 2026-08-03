package browseropener

import (
	"runtime"
	"testing"
)

func TestPlatformBackendMatchesBuildTarget(t *testing.T) {
	t.Parallel()

	want := map[string]string{
		"darwin":  "darwin-open",
		"linux":   "linux-xdg-open",
		"windows": "windows-shell-execute",
	}[runtime.GOOS]
	if want == "" {
		want = "unsupported-browser-platform"
	}
	if platformBackend != want {
		t.Fatalf("platform backend = %q, want %q", platformBackend, want)
	}
}
