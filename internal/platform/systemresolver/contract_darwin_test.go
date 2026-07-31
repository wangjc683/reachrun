//go:build darwin && !netgo

package systemresolver

import "testing"

func TestDarwinNativeResolverContract(t *testing.T) {
	assertNativeResolverContract(t)
}
