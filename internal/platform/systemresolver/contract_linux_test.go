//go:build linux && cgo && netcgo && !netgo

package systemresolver

import "testing"

func TestLinuxNativeResolverContract(t *testing.T) {
	assertNativeResolverContract(t)
}
