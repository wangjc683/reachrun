//go:build windows && !netgo

package systemresolver

import "testing"

func TestWindowsNativeResolverContract(t *testing.T) {
	assertNativeResolverContract(t)
}
