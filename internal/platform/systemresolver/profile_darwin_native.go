//go:build darwin && !netgo

package systemresolver

func compiledResolverProfile() resolverBuildProfile {
	return resolverBuildProfile{
		nativeAvailable: true,
		nativeByDefault: true,
		nativeBackend:   "darwin-system-resolver",
		fallbackBackend: "go-dns-resolver",
	}
}
