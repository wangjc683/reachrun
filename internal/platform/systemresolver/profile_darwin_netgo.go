//go:build darwin && netgo

package systemresolver

func compiledResolverProfile() resolverBuildProfile {
	return resolverBuildProfile{
		fallbackBackend: "go-dns-resolver",
		fallbackReason:  "native_backend_disabled_at_build",
	}
}
