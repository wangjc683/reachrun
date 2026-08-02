package nettarget

import "testing"

func TestNormalizeWebHostname(t *testing.T) {
	t.Parallel()

	normalized, err := NormalizeWebHostname(" WWW.Example.COM. ")
	if err != nil {
		t.Fatalf("NormalizeWebHostname() error = %v", err)
	}
	if normalized != "www.example.com" {
		t.Fatalf("hostname = %q, want www.example.com", normalized)
	}
}

func TestNormalizeWebHostnameRejectsNonWebIdentities(t *testing.T) {
	t.Parallel()

	for name, value := range map[string]string{
		"empty":        "",
		"single label": "localhost",
		"IP literal":   "8.8.8.8",
		"path":         "example.com/path",
		"empty label":  "example..com",
		"unicode":      "例子.example",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := NormalizeWebHostname(value); err == nil {
				t.Fatalf("NormalizeWebHostname(%q) error = nil", value)
			}
		})
	}
}
