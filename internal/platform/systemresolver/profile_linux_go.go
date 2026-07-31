//go:build linux && (!cgo || netgo)

package systemresolver

func compiledResolverProfile() resolverBuildProfile {
	return resolverBuildProfile{
		fallbackBackend: "go-dns-resolver",
		fallbackReason:  "native_backend_unavailable",
	}
}
