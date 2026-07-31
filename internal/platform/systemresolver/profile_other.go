//go:build !darwin && !windows && !linux

package systemresolver

func compiledResolverProfile() resolverBuildProfile {
	return resolverBuildProfile{
		fallbackBackend: "resolver-backend-unverified",
		fallbackReason:  "platform_backend_unverified",
	}
}
